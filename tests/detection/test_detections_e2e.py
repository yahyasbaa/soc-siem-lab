"""End-to-end detection tests through the full SIEM pipeline.

    synthetic event (fixture)
        -> log file on the lab host
        -> Wazuh agent (logcollector / EventChannel queue)
        -> Wazuh manager (remoted -> analysisd decoders -> rules)
        -> alerts.json / archives.json -> Filebeat
        -> Wazuh indexer (OpenSearch)   <- this test queries here

For every positive fixture the expected alert must appear in the indexer with
the correct rule id, level/severity, MITRE mapping, agent, location and
fields. For every negative (benign) fixture the raw events must be ingested
while none of the forbidden rules fire. Per-rule detection latency is
recorded in reports/detection-results.{json,md}.
"""
from __future__ import annotations

import datetime as dt
import json
import time

import pytest

import socgen
import soclab
from conftest import REPORTS

SCENARIOS = socgen.load_scenarios()
POSITIVE = [(s, e) for s in SCENARIOS if s.kind == "positive" for e in s.expect]
NEGATIVE = [s for s in SCENARIOS if s.kind == "negative"]
ALERT_TIMEOUT = 120
SKEW = dt.timedelta(seconds=5)
RESULTS: list[dict] = []


@pytest.fixture(scope="module")
def injected(api, indexer):
    agents = {a["name"]: a["status"] for a in api.agents()}
    inactive = [n for n in soclab.LAB_AGENTS if agents.get(n) != "active"]
    assert not inactive, f"lab agents not active: {inactive} - run `make health`"
    t0 = socgen.now_utc()
    times = {}
    for s in SCENARIOS:
        times[s.id] = socgen.now_utc()
        socgen.inject(socgen.render(s, times[s.id]))
    yield {"t0": t0, "times": times}
    _write_report(t0)


def _alert_query(s: socgen.Scenario, rule_id: str, since: dt.datetime) -> dict:
    return soclab.q_and(
        soclab.q_term("rule.id", rule_id),
        soclab.q_term("agent.name", s.host),
        soclab.q_since(since - SKEW),
        *soclab.q_identity(s.identity),
    )


@pytest.mark.parametrize("scenario,expect", POSITIVE, ids=[f"{s.id}->{e['rule_id']}" for s, e in POSITIVE])
def test_detection(injected, indexer, scenario, expect):
    sent = injected["times"][scenario.id]
    started = time.monotonic()
    hits = indexer.wait_for(soclab.ALERTS_INDEX, _alert_query(scenario, expect["rule_id"], sent), timeout=ALERT_TIMEOUT)
    searchable_after = time.monotonic() - started
    assert hits, (f"{scenario.id}: expected alert {expect['rule_id']} not found in {soclab.ALERTS_INDEX} "
                  f"within {ALERT_TIMEOUT}s - the detection is broken")
    a = hits[0]
    rule = a["rule"]

    # correct rule / severity
    assert rule["id"] == expect["rule_id"]
    assert rule["level"] == expect["level"], f"level {rule['level']} != {expect['level']}"
    assert soclab.severity_for_level(rule["level"]) == socgen.severity_for_level(expect["level"])
    assert "soc_lab" in rule["groups"]
    assert rule.get("description"), "alert has no description"

    # correct MITRE ATT&CK mapping (ids + enrichment from the Wazuh MITRE db)
    mitre = rule.get("mitre", {})
    assert sorted(mitre.get("id", [])) == sorted(expect["mitre"])
    assert mitre.get("technique") and mitre.get("tactic"), "MITRE technique/tactic enrichment missing"

    # correct source
    assert a["agent"]["name"] == scenario.host
    ev = socgen.render(scenario, sent)[0]
    assert a["location"] == ev.location
    assert a.get("decoder", {}).get("name"), "alert has no decoder"
    for field, value in expect["fields"].items():
        assert str(soclab.dotted(a, field)) == str(value), f"{field}: {soclab.dotted(a, field)!r} != {value!r}"

    # required metadata for analysts
    for meta in ("timestamp", "id", "manager"):
        assert a.get(meta), f"alert missing '{meta}'"

    alert_ts = soclab.parse_ts(a["timestamp"])
    RESULTS.append({
        "scenario": scenario.id, "rule_id": rule["id"], "level": rule["level"],
        "severity": soclab.severity_for_level(rule["level"]), "mitre": mitre.get("id"),
        "agent": scenario.host, "description": rule["description"],
        "detection_latency_s": round(max(0.0, (alert_ts - sent).total_seconds()), 3),
        "searchable_after_s": round(searchable_after, 1), "result": "pass",
    })


@pytest.mark.parametrize("scenario", NEGATIVE, ids=lambda s: s.id)
def test_no_false_positive(injected, indexer, scenario):
    sent = injected["times"][scenario.id]
    raw = soclab.q_and(soclab.q_term("agent.name", scenario.host), soclab.q_since(sent - SKEW),
                       *soclab.q_identity(scenario.identity))
    # 1) the benign events really went through the pipeline
    events = indexer.wait_for(soclab.EVENTS_INDEX, raw, timeout=ALERT_TIMEOUT)
    assert events, f"{scenario.id}: benign events were never ingested - cannot evaluate false positives"
    time.sleep(3)  # alerts and archives are shipped by the same Filebeat; allow for batching
    # 2) none of the forbidden detections fired for them
    alerts = indexer.search(soclab.ALERTS_INDEX, soclab.q_and(raw, soclab.q_terms("rule.id", scenario.forbid_rules)))
    assert not alerts, f"{scenario.id}: false positive - {sorted({x['rule']['id'] for x in alerts})} fired"
    RESULTS.append({"scenario": scenario.id, "rule_id": ",".join(scenario.forbid_rules), "result": "no-false-positive",
                    "agent": scenario.host})


def _write_report(t0: dt.datetime) -> None:
    if not RESULTS:
        return
    REPORTS.mkdir(exist_ok=True)
    data = {"generated": soclab.iso(soclab.utcnow()), "run_started": soclab.iso(t0), "results": RESULTS}
    (REPORTS / "detection-results.json").write_text(json.dumps(data, indent=2))
    pos = [r for r in RESULTS if r["result"] == "pass"]
    lines = ["# Detection test results", "", f"Run started {soclab.iso(t0)}.", "",
             f"Positive detections verified: **{len(pos)}**; benign scenarios with no false positive: "
             f"**{len(RESULTS) - len(pos)}**.", "",
             "| Scenario | Rule | Level | Severity | MITRE | Detection latency (s) | Searchable after (s) |",
             "|---|---|---|---|---|---|---|"]
    for r in sorted(pos, key=lambda r: (r["rule_id"], r["scenario"])):
        lines.append(f"| {r['scenario']} | {r['rule_id']} | {r['level']} | {r['severity']} | "
                     f"{', '.join(r['mitre'])} | {r['detection_latency_s']} | {r['searchable_after_s']} |")
    lines += ["", "| Benign scenario | Rules that must NOT fire | Result |", "|---|---|---|"]
    for r in RESULTS:
        if r["result"] != "pass":
            lines.append(f"| {r['scenario']} | {r['rule_id']} | no false positive |")
    (REPORTS / "detection-results.md").write_text("\n".join(lines) + "\n")
