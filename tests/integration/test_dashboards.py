"""Dashboards: service up, saved objects present, panels backed by real data."""
from __future__ import annotations

import json
import re

import pytest
import requests

import socgen
import soclab
from conftest import ROOT

NDJSON = ROOT / "dashboards" / "soc-overview.ndjson"
OBJECTS = [json.loads(line) for line in NDJSON.read_text().splitlines() if line.strip()]
VIS = [o for o in OBJECTS if o["type"] == "visualization"]
PATTERNS = {o["id"]: o["attributes"]["title"] for o in OBJECTS if o["type"] == "index-pattern"}
# Panels that must show data once detections have run (incident panels are covered by test_investigation)
MUST_HAVE_DATA = {"soc-lab-m-events", "soc-lab-m-alerts", "soc-lab-m-detections", "soc-lab-m-high",
                  "soc-lab-m-authfail", "soc-lab-m-authok", "soc-lab-m-scans", "soc-lab-t-srcip", "soc-lab-t-netsrc",
                  "soc-lab-t-targets", "soc-lab-t-mitre", "soc-lab-t-detections", "soc-lab-t-process",
                  "soc-lab-t-web", "soc-lab-t-network", "soc-lab-p-severity", "soc-lab-p-tactics"}


@pytest.fixture(scope="module")
def osd(env):
    s = requests.Session()
    s.verify = False
    s.auth = (env["INDEXER_USERNAME"], env["INDEXER_PASSWORD"])
    s.headers["osd-xsrf"] = "true"
    s.base = f"https://127.0.0.1:{env['DASHBOARD_PORT']}"
    return s


@pytest.fixture(scope="module")
def fresh_data(indexer):
    """Make the data-backed checks self-contained: inject a few detections."""
    since = socgen.now_utc()
    for name in ("auth_ssh_success_after_failures", "network_scan_suricata", "web_sql_injection",
                 "process_certutil_download"):
        s = socgen.load_scenarios([name])[0]
        socgen.inject(socgen.render(s, socgen.now_utc()))
    q = soclab.q_and(soclab.q_terms("rule.id", ["100102", "100151", "100170", "100140"]), soclab.q_since(since))
    hits = indexer.wait_for(soclab.ALERTS_INDEX, q, timeout=120, min_hits=4)
    assert len(hits) >= 4


def kql_to_lucene(kql: str) -> str:
    q = re.sub(r"(\S+)\s*(>=|<=|>|<)\s*(\d+)", r"\1:\2\3", kql)
    return re.sub(r"\band\b", "AND", re.sub(r"\bor\b", "OR", re.sub(r"\bnot\b", "NOT", q)))


def test_dashboard_service_green(osd):
    assert osd.get(f"{osd.base}/api/status").json()["status"]["overall"]["state"] == "green"


@pytest.mark.parametrize("obj", OBJECTS, ids=lambda o: o["id"])
def test_saved_object_imported(osd, obj):
    r = osd.get(f"{osd.base}/api/saved_objects/{obj['type']}/{obj['id']}")
    assert r.status_code == 200, f"{obj['type']} {obj['id']} not imported - run `make dashboards`"


def test_dashboard_references_all_panels(osd):
    d = osd.get(f"{osd.base}/api/saved_objects/dashboard/soc-lab-overview").json()
    assert len(json.loads(d["attributes"]["panelsJSON"])) == len(VIS)
    assert {r["id"] for r in d["references"]} == {v["id"] for v in VIS}


@pytest.mark.parametrize("pattern_id", sorted(PATTERNS))
def test_index_pattern_fields_cover_visualizations(osd, pattern_id):
    p = osd.get(f"{osd.base}/api/saved_objects/index-pattern/{pattern_id}").json()
    fields = {f["name"]: f for f in json.loads(p["attributes"]["fields"])}
    assert fields, f"index pattern {pattern_id} has no fields"
    for v in VIS:
        if not v["references"] or v["references"][0]["id"] != pattern_id:
            continue
        for agg in json.loads(v["attributes"]["visState"])["aggs"]:
            f = agg.get("params", {}).get("field")
            if f:
                assert f in fields, f"{v['id']}: field {f} missing from {pattern_id}"
                assert fields[f]["aggregatable"], f"{v['id']}: field {f} not aggregatable"


@pytest.mark.parametrize("required_index", ["wazuh-alerts-4.x-*", "wazuh-archives-4.x-*", "soc-incidents"])
def test_required_index_exists(indexer, required_index):
    assert indexer.get(f"/{required_index}?allow_no_indices=false").status_code == 200


@pytest.mark.parametrize("vis", [v for v in VIS if v["id"] in MUST_HAVE_DATA], ids=lambda v: v["id"])
def test_panel_has_data(indexer, fresh_data, vis):
    ss = json.loads(vis["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
    index = PATTERNS[vis["references"][0]["id"]]
    kql = ss["query"]["query"]
    clauses = [{"range": {"timestamp": {"gte": "now-24h"}}}]
    if kql:
        clauses.append({"query_string": {"query": kql_to_lucene(kql)}})
    for agg in json.loads(vis["attributes"]["visState"])["aggs"]:
        if agg.get("params", {}).get("field"):
            clauses.append({"exists": {"field": agg["params"]["field"]}})
    n = indexer.count(index, {"bool": {"filter": clauses}})
    assert n > 0, f"panel '{vis['attributes']['title']}' would be empty (query: {kql or '*'})"
