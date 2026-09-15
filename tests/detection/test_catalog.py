"""Static consistency checks: rules XML <-> detection catalog <-> fixtures.

These run without the lab being up and fail when a rule, its documentation or
its test drift apart (e.g. a rule is deleted or its MITRE mapping changes).
"""
from __future__ import annotations

import datetime as dt
import pathlib
import re
import xml.etree.ElementTree as ET

import pytest

import socgen

ROOT = pathlib.Path(__file__).resolve().parents[2]
RULES_XML = ROOT / "wazuh" / "manager" / "etc" / "rules" / "soc_lab_rules.xml"
REQUIRED_FIELDS = ("id", "rule_id", "name", "description", "level", "data_source", "detection_logic",
                   "mitre", "false_positives", "response", "playbook", "tests")
MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def parse_rules() -> dict[str, dict]:
    text = RULES_XML.read_text()
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    root = ET.fromstring(f"<root>{text}</root>")
    rules = {}
    for group in root.findall("group"):
        group_names = [g for g in group.get("name", "").split(",") if g]
        for r in group.findall("rule"):
            rid = r.get("id")
            assert rid not in rules, f"duplicate rule id {rid}"
            rules[rid] = {
                "level": int(r.get("level")),
                "mitre": [m.text for m in r.findall("mitre/id")],
                "description": (r.findtext("description") or "").strip(),
                "groups": group_names + [g for g in (r.findtext("group") or "").split(",") if g],
            }
    return rules


RULES = parse_rules()


@pytest.fixture(scope="module")
def detections(catalog):
    return {d["rule_id"]: d for d in catalog["detections"]}


def test_rules_file_parses_and_ids_in_lab_range():
    assert RULES, "no rules parsed"
    for rid in RULES:
        assert 100090 <= int(rid) <= 100299, f"rule {rid} outside the SOC lab id range"


def test_every_rule_is_catalogued(catalog, detections):
    pipeline = {p["rule_id"] for p in catalog["pipeline_rules"]}
    missing = set(RULES) - set(detections) - pipeline
    assert not missing, f"rules without catalog entry: {sorted(missing)}"
    stale = (set(detections) | pipeline) - set(RULES)
    assert not stale, f"catalog entries without a rule: {sorted(stale)}"


def test_catalog_ids_unique(catalog):
    ids = [d["id"] for d in catalog["detections"]]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule_id", sorted(r for r in RULES if int(r) >= 100100))
def test_detection_metadata_complete_and_matches_rule(rule_id, detections):
    d = detections[rule_id]
    for f in REQUIRED_FIELDS:
        assert d.get(f) not in (None, "", []), f"{d.get('id')} missing '{f}'"
    rule = RULES[rule_id]
    assert d["level"] == rule["level"], f"{d['id']}: catalog level {d['level']} != rule level {rule['level']}"
    assert [m["id"] for m in d["mitre"]] == rule["mitre"], f"{d['id']}: MITRE mismatch"
    for m in d["mitre"]:
        assert MITRE_ID.match(m["id"]) and m.get("name") and m.get("tactic"), f"{d['id']}: bad MITRE entry {m}"
    assert "soc_lab" in rule["groups"]
    assert re.match(r"^IR-00\d$", d["playbook"])
    assert list((ROOT / "playbooks").glob(f"{d['playbook']}-*.md")), f"playbook {d['playbook']} file missing"


@pytest.mark.parametrize("rule_id", sorted(r for r in RULES if int(r) >= 100100))
def test_every_detection_has_positive_fixture(rule_id, detections, scenarios):
    d = detections[rule_id]
    by_id = {s.id: s for s in scenarios}
    for fx in d["tests"]:
        assert fx in by_id, f"{d['id']}: fixture {fx} does not exist"
    expecting = [s.id for s in scenarios if s.kind == "positive" and any(e["rule_id"] == rule_id for e in s.expect)]
    assert expecting, f"{d['id']} ({rule_id}) has no positive fixture expecting it"
    assert set(d["tests"]) <= set(expecting), f"{d['id']}: catalog lists fixtures that do not expect this rule"
    for fx in d.get("negative_tests", []):
        assert fx in by_id and by_id[fx].kind == "negative", f"{d['id']}: negative fixture {fx} missing"


def test_fixture_expectations_match_rules(scenarios):
    for s in scenarios:
        for e in s.expect:
            rule = RULES.get(e["rule_id"])
            assert rule, f"{s.id}: expects unknown rule {e['rule_id']}"
            assert e["level"] == rule["level"], f"{s.id}: expected level {e['level']} != rule {rule['level']}"
            assert sorted(e["mitre"]) == sorted(rule["mitre"]), f"{s.id}: MITRE mismatch for {e['rule_id']}"
        for r in s.forbid_rules:
            assert r in RULES, f"{s.id}: forbids unknown rule {r}"


def test_fixtures_only_use_lab_and_documentation_addresses(scenarios):
    # load_scenarios() already validates; this makes the guarantee explicit.
    for s in scenarios:
        socgen.validate_scenario(s)


def test_generator_is_deterministic(scenarios):
    t = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    for s in scenarios:
        a = [e.line for e in socgen.render(s, t)]
        b = [e.line for e in socgen.render(s, t)]
        assert a == b and a, f"{s.id}: rendering is not deterministic"


def test_generator_matches_golden_snapshot(scenarios):
    """The rendered output for a fixed base time is committed in
    tests/fixtures/rendered/golden.jsonl; any change to fixtures or the
    generator must be deliberate (regenerate with `make golden`)."""
    import json
    golden = ROOT / "tests" / "fixtures" / "rendered" / "golden.jsonl"
    assert golden.exists(), "golden snapshot missing - run `make golden`"
    t = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    current = [json.dumps({"scenario": s.id, "location": e.location, "event": e.line}, sort_keys=True)
               for s in scenarios for e in socgen.render(s, t)]
    assert golden.read_text().splitlines() == current


def test_false_positive_controls_exist_per_category(scenarios):
    negatives = " ".join(s.id for s in scenarios if s.kind == "negative")
    for c in ("ssh", "sudo", "linux_user", "windows", "powershell", "process", "certutil",
              "suricata", "web", "outbound"):
        assert c in negatives, f"no negative (false-positive) control for category '{c}'"
