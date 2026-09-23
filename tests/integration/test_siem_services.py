"""SIEM services: indexer, manager, agents, rules loaded."""
from __future__ import annotations

import re

import pytest

import soclab
from conftest import ROOT

RULES_FILE = ROOT / "wazuh" / "manager" / "etc" / "rules" / "soc_lab_rules.xml"


def test_indexer_cluster_healthy(indexer):
    h = indexer.get("/_cluster/health").json()
    assert h["status"] in ("green", "yellow")
    assert h["number_of_nodes"] == 1


def test_indexer_is_opensearch(indexer):
    # The Wazuh indexer reports an ES-compatible version on "/" (compat mode),
    # so check the node build and plugins instead.
    assert "OpenSearch" in indexer.get("/").json()["tagline"]
    node = next(iter(indexer.get("/_nodes/_local").json()["nodes"].values()))
    assert node["version"].startswith("2.")
    assert "opensearch-security" in indexer.get("/_cat/plugins?h=component").text


def test_manager_api_and_version(api):
    info = api.get("/")["data"]
    assert info["api_version"].startswith("4.14")


@pytest.mark.parametrize("daemon", ["wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-authd",
                                    "wazuh-modulesd", "wazuh-apid"])
def test_manager_daemon_running(api, daemon):
    st = api.get("/manager/status")["data"]["affected_items"][0]
    assert st[daemon] == "running"


@pytest.mark.parametrize("agent", soclab.LAB_AGENTS)
def test_agent_connected(api, agent):
    agents = {a["name"]: a for a in api.agents()}
    assert agent in agents, f"{agent} not registered"
    assert agents[agent]["status"] == "active"
    assert agents[agent]["version"].startswith("Wazuh v4.14")


def test_all_soc_rules_loaded(api):
    expected = set(re.findall(r'<rule id="(\d+)"', RULES_FILE.read_text()))
    loaded = api.get("/rules", filename="soc_lab_rules.xml", limit=500)["data"]["affected_items"]
    assert {str(r["id"]) for r in loaded} == expected
    assert all(r["status"] == "enabled" for r in loaded)


def test_soc_decoders_loaded(api):
    names = {d["name"] for d in api.get("/decoders", filename="soc_lab_decoders.xml", limit=100)["data"]["affected_items"]}
    assert {"soc-usermod", "soc-usermod-group-add", "soc-lab-heartbeat", "soc-lab-heartbeat-fields"} <= names


def test_ruleset_validates_in_manager(api):
    # The manager validates its full configuration (incl. rules) on demand.
    res = api.get("/manager/configuration/validation")["data"]["affected_items"][0]
    assert res["status"] == "OK", res


def test_deterministic_processing_options_applied():
    out = soclab_exec("cat /var/ossec/etc/local_internal_options.conf")
    for opt in ("remoted.worker_pool=1", "analysisd.event_threads=1", "analysisd.rule_matching_threads=1"):
        assert opt in out


def test_archives_shipping_enabled():
    assert "archives:\n      enabled: true" in soclab_exec("cat /etc/filebeat/filebeat.yml")


def soclab_exec(cmd: str) -> str:
    import subprocess
    return subprocess.run(["docker", "compose", "exec", "-T", "wazuh.manager", "sh", "-c", cmd], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout
