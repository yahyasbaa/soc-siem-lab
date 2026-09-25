"""Analyst investigation workflow: alert -> evidence bundle -> incident -> closure."""
from __future__ import annotations

import hashlib
import json
import subprocess

import pytest

import socgen
import soclab
from conftest import ROOT

PY = str(ROOT / ".venv" / "bin" / "python")
SRCIP = "198.51.100.24"


def run(script: str, *args: str) -> str:
    return subprocess.run([PY, f"scripts/{script}", *args], cwd=ROOT, check=True, capture_output=True, text=True,
                          env={"PYTHONPATH": str(ROOT / "scripts"), "PATH": "/usr/bin:/bin"}).stdout


@pytest.fixture(scope="module")
def incident(indexer):
    s = socgen.load_scenarios(["auth_ssh_success_after_failures"])[0]
    sent = socgen.now_utc()
    socgen.inject(socgen.render(s, sent))
    q = soclab.q_and(soclab.q_term("rule.id", "100102"), soclab.q_term("data.srcip", SRCIP), soclab.q_since(sent))
    assert indexer.wait_for(soclab.ALERTS_INDEX, q, timeout=120), "brute-force success alert not generated"
    out = run("investigate.py", "--rule-id", "100102", "--srcip", SRCIP, "--analyst", "pytest", "--json")
    return json.loads(out)


def test_incident_opened_with_detection_context(indexer, incident):
    doc = indexer.get(f"/{soclab.INCIDENTS_INDEX}/_doc/{incident['incident_id']}").json()["_source"]
    assert doc["status"] == "open"
    assert doc["severity"] == "high" and doc["level"] == 13
    assert doc["playbook"] == "IR-001"
    assert doc["rule_id"] == "100102"
    assert set(doc["mitre_ids"]) == {"T1110", "T1078"}
    assert SRCIP in doc["source_ips"]
    assert "deploy" in doc["users"]
    assert doc["hosts"] == ["lab-linux-01"]


def test_evidence_bundle_complete(incident):
    d = ROOT / incident["evidence_path"]
    for f in ("alert.json", "related_alerts.json", "raw_events.jsonl", "indicators.json", "timeline.md",
              "report.md", "sha256sums.txt", "incident.json"):
        assert (d / f).is_file() and (d / f).stat().st_size > 0, f"evidence file {f} missing"


def test_evidence_integrity_manifest(incident):
    d = ROOT / incident["evidence_path"]
    manifest = (d / "sha256sums.txt").read_text().splitlines()
    assert manifest
    for line in manifest:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((d / name).read_bytes()).hexdigest() == digest, f"{name} modified after collection"
    assert hashlib.sha256((d / "sha256sums.txt").read_bytes()).hexdigest() == incident["evidence_sha256"]


def test_evidence_contains_attack_chain(incident):
    d = ROOT / incident["evidence_path"]
    rules = {a["rule"]["id"] for a in json.loads((d / "related_alerts.json").read_text())}
    assert {"100100", "100101", "100102"} <= rules, f"attack chain incomplete: {rules}"
    raw = (d / "raw_events.jsonl").read_text()
    assert "Failed password for deploy" in raw and "Accepted password for deploy" in raw
    iocs = json.loads((d / "indicators.json").read_text())
    assert SRCIP in iocs["source_ip"] and "deploy" in iocs["user"]
    report = (d / "report.md").read_text()
    for needle in ("T1110", "IR-001", "Recommended response", SRCIP):
        assert needle in report


def test_open_incident_visible_on_dashboard_query(indexer, incident):
    q = soclab.q_and(soclab.q_term("status", "open"), soclab.q_term("incident_id", incident["incident_id"]))
    assert indexer.count(soclab.INCIDENTS_INDEX, q) == 1


def test_incident_lifecycle_close(indexer, incident):
    inc = incident["incident_id"]
    run("incident.py", "update", inc, "--status", "contained", "--note", "source blocked (lab)")
    assert indexer.get(f"/{soclab.INCIDENTS_INDEX}/_doc/{inc}").json()["_source"]["status"] == "contained"
    run("incident.py", "close", inc, "--resolution", "Lab validation incident - synthetic telemetry", "--analyst", "pytest")
    doc = indexer.get(f"/{soclab.INCIDENTS_INDEX}/_doc/{inc}").json()["_source"]
    assert doc["status"] == "closed" and doc["closed_at"] and doc["resolution"]
