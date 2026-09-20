#!/usr/bin/env python3
"""Minimal incident tracker backed by the soc-incidents index.

  incident.py list [--status open|investigating|contained|closed|all]
  incident.py show INC-ID
  incident.py update INC-ID --status investigating|contained [--note TEXT]
  incident.py close INC-ID --resolution TEXT [--analyst NAME]

Incidents are opened by scripts/investigate.py and shown on the SOC dashboard
("Open incidents"). Status flow: open -> investigating -> contained -> closed.
"""
from __future__ import annotations

import argparse
import json
import sys

import soclab

STATUSES = ("open", "investigating", "contained", "closed")


def get(ix, inc):
    r = ix.get(f"/{soclab.INCIDENTS_INDEX}/_doc/{inc}")
    if r.status_code != 200:
        print(f"{inc} not found", file=sys.stderr)
        return None
    return r.json()["_source"]


def save(ix, inc, doc):
    r = ix.put(f"/{soclab.INCIDENTS_INDEX}/_doc/{inc}?refresh=wait_for", doc)
    r.raise_for_status()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    l_ = sub.add_parser("list")
    l_.add_argument("--status", default="open", choices=STATUSES + ("all",))
    s_ = sub.add_parser("show")
    s_.add_argument("incident")
    u_ = sub.add_parser("update")
    u_.add_argument("incident")
    u_.add_argument("--status", required=True, choices=("open", "investigating", "contained"))
    u_.add_argument("--note", default="")
    c_ = sub.add_parser("close")
    c_.add_argument("incident")
    c_.add_argument("--resolution", required=True)
    c_.add_argument("--analyst", default="soc-analyst")
    args = p.parse_args(argv)
    ix = soclab.Indexer()

    if args.cmd == "list":
        q = {"match_all": {}} if args.status == "all" else soclab.q_term("status", args.status)
        for d in ix.search(soclab.INCIDENTS_INDEX, q, size=500, sort="desc", sort_field="created_at"):
            print(f"{d['incident_id']:32} {d['status']:13} {d['severity']:8} {d['playbook'] or '-':7} {d['title']}")
        return 0
    doc = get(ix, args.incident)
    if doc is None:
        return 1
    now = soclab.iso(soclab.utcnow())
    if args.cmd == "show":
        print(json.dumps(doc, indent=2))
    elif args.cmd == "update":
        doc.update(status=args.status, updated_at=now)
        if args.note:
            doc["summary"] = (doc.get("summary") or "") + f"\n[{now}] {args.note}"
        save(ix, args.incident, doc)
        print(f"{args.incident} -> {args.status}")
    elif args.cmd == "close":
        doc.update(status="closed", updated_at=now, closed_at=now, resolution=args.resolution, analyst=args.analyst)
        save(ix, args.incident, doc)
        print(f"{args.incident} closed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
