"""Engine-level detection tests through the manager's wazuh-logtest API.

Each logtest-capable fixture is replayed into a fresh logtest session (the
real analysisd decoders + rules, isolated correlation state). This is fast
and pinpoints rule-logic regressions independently of transport/indexing.

Windows EventChannel fixtures are excluded here (logtest cannot emulate the
EventChannel queue); they are covered by test_detections_e2e.py, which uses
the real agent pipeline for every fixture.
"""
from __future__ import annotations

import pytest

import socgen
import soclab

LOGTEST_SCENARIOS = [s for s in socgen.load_scenarios() if s.logtest]


def replay(api: soclab.WazuhAPI, scenario: socgen.Scenario) -> list[dict]:
    outputs, token = [], None
    try:
        for ev in socgen.render(scenario, socgen.now_utc()):
            # The agent's audit reader joins the records of one audit event
            # with a space; do the same here.
            line = ev.line.replace("\n", " ") if ev.log_format == "audit" else ev.line
            data = api.logtest(line, ev.location, ev.log_format, token)
            token = data.get("token", token)
            outputs.append(data["output"])
    finally:
        if token:
            api.logtest_end(token)
    return outputs


@pytest.mark.parametrize("scenario", LOGTEST_SCENARIOS, ids=lambda s: s.id)
def test_logtest(api, scenario):
    outputs = replay(api, scenario)
    fired = [o.get("rule", {}) for o in outputs]
    fired_ids = [r.get("id") for r in fired]
    if scenario.kind == "positive":
        for exp in scenario.expect:
            hits = [r for r in fired if r.get("id") == exp["rule_id"]]
            assert hits, f"{scenario.id}: rule {exp['rule_id']} did not fire (fired: {fired_ids})"
            r = hits[0]
            assert r["level"] == exp["level"]
            assert sorted(r.get("mitre", {}).get("id", [])) == sorted(exp["mitre"])
            assert "soc_lab" in r.get("groups", [])
            out = next(o for o in outputs if o.get("rule", {}).get("id") == exp["rule_id"])
            for field, value in exp["fields"].items():
                # logtest output has no top-level "data." prefix
                key = field[5:] if field.startswith("data.") else field
                assert str(soclab.dotted(out.get("data", {}), key) if field.startswith("data.")
                           else soclab.dotted(out, key)) == str(value), f"{scenario.id}: {field}"
    else:
        bad = sorted(set(fired_ids) & set(scenario.forbid_rules))
        assert not bad, f"{scenario.id}: false positive - rules {bad} fired on benign activity"
