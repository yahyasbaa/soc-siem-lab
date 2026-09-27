"""Incident-response playbooks are complete and linked to detections."""
from __future__ import annotations

import pytest
import yaml

from conftest import ROOT

PLAYBOOKS = sorted((ROOT / "playbooks").glob("IR-*.md"))
SECTIONS = ["## 1. Detection", "## 2. Triage", "## 3. Investigation", "## 4. Evidence collection",
            "## 5. Containment", "## 6. Eradication", "## 7. Recovery", "## 8. Lessons learned",
            "## Logs to inspect", "## Indicators of compromise", "## Escalation criteria"]


def test_minimum_playbooks_present():
    ids = {p.name[:6] for p in PLAYBOOKS}
    assert {"IR-001", "IR-002", "IR-003", "IR-004", "IR-005"} <= ids


@pytest.mark.parametrize("pb", PLAYBOOKS, ids=lambda p: p.name)
def test_playbook_sections(pb):
    text = pb.read_text()
    for s in SECTIONS:
        assert s in text, f"{pb.name} is missing section '{s}'"


@pytest.mark.parametrize("pb", PLAYBOOKS, ids=lambda p: p.name)
def test_playbook_covers_its_detections(pb):
    cat = yaml.safe_load((ROOT / "detections" / "catalog.yml").read_text())
    rules = [d["rule_id"] for d in cat["detections"] if d["playbook"] == pb.name[:6]]
    assert rules, f"{pb.name} is not referenced by any detection"
    text = pb.read_text()
    for r in rules:
        assert r in text, f"{pb.name} does not mention rule {r}"
