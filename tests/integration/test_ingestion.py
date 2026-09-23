"""Logging: events from every lab host are ingested, alerted and searchable."""
from __future__ import annotations

import subprocess
import uuid

import pytest

import socgen
import soclab
from conftest import ROOT


@pytest.fixture(scope="module")
def heartbeat():
    nonce = "it" + uuid.uuid4().hex[:12]
    since = socgen.now_utc()
    subprocess.run([str(ROOT / ".venv/bin/python"), "scripts/generate-test-events/generate.py", "heartbeat",
                    "--nonce", nonce], cwd=ROOT, check=True, capture_output=True)
    subprocess.run(["docker", "compose", "exec", "-T", "lab-web-01", "curl", "-s", "-o", "/dev/null",
                    f"http://web-nginx/soc-lab-heartbeat?nonce={nonce}"], cwd=ROOT, check=True)
    return nonce, since


@pytest.mark.parametrize("host", soclab.LAB_AGENTS)
def test_events_ingested_and_alerted_per_host(indexer, heartbeat, host):
    nonce, since = heartbeat
    q = soclab.q_and(soclab.q_term("rule.id", "100090"), soclab.q_term("data.nonce", nonce),
                     soclab.q_term("agent.name", host))
    hits = indexer.wait_for(soclab.ALERTS_INDEX, q, timeout=90)
    assert hits, f"heartbeat from {host} never reached the indexer"
    a = hits[0]
    assert a["data"]["lab_host"] == host
    assert a["location"] == "/var/log/lab/heartbeat.log"
    assert a["decoder"]["name"] == "soc-lab-heartbeat"
    assert soclab.parse_ts(a["timestamp"]) >= since.replace(microsecond=0) - __import__("datetime").timedelta(seconds=5)


@pytest.mark.parametrize("host", soclab.LAB_AGENTS)
def test_raw_events_searchable_in_archives(indexer, heartbeat, host):
    nonce, _ = heartbeat
    q = soclab.q_and(soclab.q_term("agent.name", host), {"match_phrase": {"full_log": nonce}})
    assert indexer.wait_for(soclab.EVENTS_INDEX, q, timeout=90), f"raw event from {host} not searchable"


def test_real_nginx_access_log_ingested(indexer, heartbeat):
    nonce, _ = heartbeat
    q = soclab.q_and(soclab.q_term("rule.id", "100091"), {"wildcard": {"data.url": f"*{nonce}*"}})
    hits = indexer.wait_for(soclab.ALERTS_INDEX, q, timeout=90)
    assert hits, "request served by the real Nginx container was not ingested"
    a = hits[0]
    assert a["agent"]["name"] == "lab-web-01"
    assert a["decoder"]["name"] == "web-accesslog"
    assert a["data"]["id"] == "204"


def test_full_text_search_on_events(indexer, heartbeat):
    nonce, _ = heartbeat
    r = indexer.post(f"/{soclab.EVENTS_INDEX}/_search", {"query": {"query_string": {"query": f"*{nonce}*",
                                                                                     "default_field": "full_log"}}})
    assert r.json()["hits"]["total"]["value"] >= 4


def test_alert_and_event_indices_are_daily(indexer):
    names = indexer.get("/_cat/indices/wazuh-*?h=index&format=json").json()
    idx = {n["index"] for n in names}
    today = socgen.now_utc().strftime("%Y.%m.%d")
    assert f"wazuh-alerts-4.x-{today}" in idx
    assert f"wazuh-archives-4.x-{today}" in idx
