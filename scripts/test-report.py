#!/usr/bin/env python3
"""Summarise reports/junit-*.xml and reports/detection-results.json."""
from __future__ import annotations

import json
import pathlib
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"


def main() -> int:
    files = sorted(REPORTS.glob("junit-*.xml"))
    if not files:
        print("no test results in reports/ - run `make test` or `make all`")
        return 1
    tot = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    print(f"{'suite':28} {'tests':>6} {'passed':>7} {'failed':>7} {'errors':>7} {'skipped':>8}")
    for f in files:
        root = ET.parse(f).getroot()
        suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
        c = {k: sum(int(s.get(k, 0)) for s in suites) for k in tot}
        passed = c["tests"] - c["failures"] - c["errors"] - c["skipped"]
        print(f"{f.stem:28} {c['tests']:6} {passed:7} {c['failures']:7} {c['errors']:7} {c['skipped']:8}")
        for k in tot:
            tot[k] += c[k]
    passed = tot["tests"] - tot["failures"] - tot["errors"] - tot["skipped"]
    print(f"{'TOTAL':28} {tot['tests']:6} {passed:7} {tot['failures']:7} {tot['errors']:7} {tot['skipped']:8}")
    det = REPORTS / "detection-results.json"
    if det.exists():
        res = json.loads(det.read_text())["results"]
        pos = [r for r in res if r["result"] == "pass"]
        rules = sorted({r["rule_id"] for r in pos})
        lat = [r["detection_latency_s"] for r in pos]
        print(f"\nend-to-end detections verified : {len(pos)} expectations across {len(rules)} rules")
        print(f"false-positive controls passed : {len(res) - len(pos)}")
        if lat:
            print(f"detection latency (s)          : min {min(lat)}  avg {sum(lat)/len(lat):.2f}  max {max(lat)}")
    ok = tot["failures"] == 0 and tot["errors"] == 0
    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
