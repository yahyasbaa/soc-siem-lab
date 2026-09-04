#!/usr/bin/env python3
"""Synthetic security-telemetry generator CLI.

  generate.py list                         list scenarios
  generate.py render [SCENARIO...]         print rendered events (stdout)
         [--fixed-time 2026-01-01T00:00:00Z]   deterministic output
  generate.py inject [SCENARIO...]         append events to the lab agents' log files
  generate.py heartbeat --nonce N          write a pipeline heartbeat on every host
  generate.py golden                       rewrite tests/fixtures/rendered/golden.jsonl

With no SCENARIO arguments, all scenarios are used. Scenario names are the
fixture ids in tests/fixtures/security_events/.

This tool only writes text into local lab log files. It sends no network
traffic and runs no commands described in the events.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys

import socgen


def parse_time(value: str) -> dt.datetime:
    t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def cmd_list(args) -> int:
    for s in socgen.load_scenarios():
        rules = ",".join(e["rule_id"] for e in s.expect) if s.kind == "positive" else "!" + ",".join(s.forbid_rules)
        print(f"{s.id:42} {s.kind:8} {s.host:13} {rules}")
    return 0


def cmd_render(args) -> int:
    base = parse_time(args.fixed_time) if args.fixed_time else socgen.now_utc()
    for s in socgen.load_scenarios(args.scenarios or None):
        for e in socgen.render(s, base):
            if args.json:
                print(json.dumps({"scenario": s.id, "host": e.host, "location": e.location,
                                  "log_format": e.log_format, "event": e.line}))
            else:
                print(f"# {s.id} -> {e.host}:{e.location}\n{e.line}")
    return 0


def cmd_inject(args) -> int:
    base = socgen.now_utc()
    total = 0
    for s in socgen.load_scenarios(args.scenarios or None):
        n = socgen.inject(socgen.render(s, base))
        total += n
        if not args.quiet:
            print(f"injected {n:3d} event(s)  {s.id}  -> {s.host}")
    print(f"total events injected: {total} at {base.isoformat()}")
    return 0


def cmd_heartbeat(args) -> int:
    t = socgen.now_utc()
    ts = socgen._ts_fields(t, 0)["syslog_ts"]
    events = [
        socgen.RenderedEvent(host, "heartbeat", "heartbeat.log", "syslog",
                             f"{ts} {host} soc-lab-heartbeat: nonce={args.nonce} host={host}")
        for host in socgen.SOURCES
    ]
    socgen.inject(events)
    print(f"heartbeat {args.nonce} written to {len(events)} hosts")
    return 0


GOLDEN_TIME = "2026-01-01T00:00:00Z"


def cmd_golden(args) -> int:
    """Snapshot of every scenario rendered at a fixed time; test_catalog.py
    compares against it so fixture/generator changes are always deliberate."""
    base = parse_time(GOLDEN_TIME)
    out = socgen.ROOT / "tests" / "fixtures" / "rendered" / "golden.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = [json.dumps({"scenario": s.id, "location": e.location, "event": e.line}, sort_keys=True)
            for s in socgen.load_scenarios() for e in socgen.render(s, base)]
    out.write_text("\n".join(rows) + "\n")
    print(f"wrote {len(rows)} rendered events to {out.relative_to(socgen.ROOT)}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    r = sub.add_parser("render")
    r.add_argument("scenarios", nargs="*")
    r.add_argument("--fixed-time", help="ISO-8601 base time for byte-reproducible output")
    r.add_argument("--json", action="store_true", help="one JSON object per event")
    r.set_defaults(fn=cmd_render)
    i = sub.add_parser("inject")
    i.add_argument("scenarios", nargs="*")
    i.add_argument("-q", "--quiet", action="store_true")
    i.set_defaults(fn=cmd_inject)
    h = sub.add_parser("heartbeat")
    h.add_argument("--nonce", required=True)
    h.set_defaults(fn=cmd_heartbeat)
    sub.add_parser("golden").set_defaults(fn=cmd_golden)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (KeyError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
