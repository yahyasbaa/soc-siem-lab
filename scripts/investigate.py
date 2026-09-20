#!/usr/bin/env python3
"""Analyst investigation helper: alert -> evidence bundle -> incident.

  investigate.py --rule-id 100101                 newest alert of that rule
  investigate.py --alert-id 1791047372.3542       a specific alert (alert "id")
        [--srcip 198.51.100.23] [--window 30] [--analyst name] [--no-incident]

What it does (read-only against the SIEM, except for the incident record):
  1. fetches the alert from the indexer
  2. pivots on source IPs, user names and host within +/- --window minutes
  3. collects related alerts and the raw decoded events (archives)
  4. extracts indicators (IPs, users, URLs, command lines, processes)
  5. writes an evidence bundle to runtime/evidence/<INCIDENT>/ with a
     SHA-256 manifest (chain-of-custody)
  6. opens an incident in the soc-incidents index (shown on the dashboard)
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys

import yaml

import soclab

EVIDENCE = soclab.ROOT / "runtime" / "evidence"
IP_FIELDS = ("data.srcip", "data.src_ip", "data.win.eventdata.ipAddress")
DST_FIELDS = ("data.dstip", "data.dest_ip", "data.win.eventdata.destinationIp")
USER_FIELDS = ("data.srcuser", "data.dstuser", "data.win.eventdata.targetUserName",
               "data.win.eventdata.subjectUserName", "data.win.eventdata.user", "data.audit.auid")
IOC_FIELDS = {
    "url": ("data.url",),
    "command": ("data.command", "data.win.eventdata.commandLine", "data.win.eventdata.scriptBlockText"),
    "process": ("data.win.eventdata.image", "data.win.eventdata.parentImage", "data.audit.exe"),
    "signature": ("data.alert.signature",),
}
IGNORED_USERS = {"-", "root", "SYSTEM", "LAB-WIN-01$", "", "None"}


def load_catalog() -> dict[str, dict]:
    cat = yaml.safe_load((soclab.ROOT / "detections" / "catalog.yml").read_text())
    return {d["rule_id"]: d for d in cat["detections"]}


def values(doc: dict, fields) -> list[str]:
    out = []
    for f in fields:
        v = soclab.dotted(doc, f)
        if v not in (None, "", []):
            out.extend(v if isinstance(v, list) else [str(v)])
    return out


def find_alert(ix: soclab.Indexer, args) -> dict | None:
    if args.alert_id:
        hits = ix.search(soclab.ALERTS_INDEX, soclab.q_term("id", args.alert_id), size=1)
    else:
        clauses = [soclab.q_term("rule.id", args.rule_id)]
        if args.srcip:
            clauses.append({"bool": {"should": [soclab.q_term(f, args.srcip) for f in IP_FIELDS],
                                     "minimum_should_match": 1}})
        hits = ix.search(soclab.ALERTS_INDEX, soclab.q_and(*clauses), size=1, sort="desc")
    return hits[0] if hits else None


def pivot_query(alert: dict, start: dt.datetime, end: dt.datetime) -> tuple[dict, dict]:
    ips = sorted(set(values(alert, IP_FIELDS)))
    users = sorted(set(values(alert, USER_FIELDS)) - IGNORED_USERS)
    should = [soclab.q_term(f, ip) for ip in ips for f in IP_FIELDS]
    should += [soclab.q_term(f, u) for u in users for f in USER_FIELDS]
    if not should:  # host-based alert without network/user context: pivot on the host
        should = [soclab.q_term("agent.name", alert["agent"]["name"])]
    q = {"bool": {"filter": [{"range": {"timestamp": {"gte": soclab.iso(start), "lte": soclab.iso(end)}}},
                             soclab.q_term("agent.name", alert["agent"]["name"])],
                  "should": should, "minimum_should_match": 1}}
    return q, {"source_ips": ips, "users": users, "hosts": [alert["agent"]["name"]]}


def indicators(docs: list[dict]) -> dict[str, list[str]]:
    iocs: dict[str, set] = {"source_ip": set(), "destination_ip": set(), "user": set()}
    for k in IOC_FIELDS:
        iocs[k] = set()
    for d in docs:
        iocs["source_ip"].update(values(d, IP_FIELDS))
        iocs["destination_ip"].update(v for v in values(d, DST_FIELDS) if not v.startswith("10."))
        iocs["user"].update(set(values(d, USER_FIELDS)) - IGNORED_USERS)
        for k, fields in IOC_FIELDS.items():
            iocs[k].update(values(d, fields))
    return {k: sorted(v) for k, v in iocs.items() if v}


def next_incident_id(ix: soclab.Indexer, rule_id: str) -> str:
    stamp = soclab.utcnow().strftime("%Y%m%d-%H%M%S")
    base = f"INC-{stamp}-{rule_id}"
    inc, n = base, 1
    while (EVIDENCE / inc).exists() or ix.get(f"/{soclab.INCIDENTS_INDEX}/_doc/{inc}").status_code == 200:
        n += 1
        inc = f"{base}-{n}"
    return inc


def write_bundle(inc_id: str, alert: dict, related: list[dict], raw: list[dict], iocs: dict, meta: dict,
                 det: dict | None) -> tuple[str, str]:
    d = EVIDENCE / inc_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "alert.json").write_text(soclab.dump(alert))
    (d / "related_alerts.json").write_text(soclab.dump(related))
    (d / "raw_events.jsonl").write_text("".join(json.dumps(e, sort_keys=True, default=str) + "\n" for e in raw))
    (d / "indicators.json").write_text(soclab.dump(iocs))

    timeline = ["# Timeline", "", "| Time (UTC) | Host | Rule | Level | Description |", "|---|---|---|---|---|"]
    for a in related:
        r = a["rule"]
        desc = r["description"].replace("|", "\\|")
        timeline.append(f"| {a['timestamp']} | {a['agent']['name']} | {r['id']} | {r['level']} | {desc} |")
    (d / "timeline.md").write_text("\n".join(timeline) + "\n")

    r = alert["rule"]
    mitre = r.get("mitre", {})
    report = [
        f"# {inc_id}: {r['description']}", "",
        f"* **Severity:** {soclab.severity_for_level(r['level'])} (Wazuh level {r['level']})",
        f"* **Detection:** {det['id'] + ' - ' + det['name'] if det else r['id']} (rule {r['id']})",
        f"* **Playbook:** {det['playbook'] if det else 'n/a'} (playbooks/)",
        f"* **Host:** {alert['agent']['name']}   **Location:** {alert.get('location')}",
        f"* **First alert:** {meta['first_seen']}   **Last alert:** {meta['last_seen']}",
        f"* **MITRE ATT&CK:** " + ", ".join(f"{i} {t}" for i, t in zip(mitre.get('id', []), mitre.get('technique', []))),
        f"* **Tactics:** {', '.join(mitre.get('tactic', []))}",
        f"* **Related alerts:** {len(related)}   **Raw events:** {len(raw)}", "",
        "## Triggering event", "", "```", alert.get("full_log") or json.dumps(alert.get("data", {}), indent=2), "```", "",
        "## Indicators", "",
    ]
    for k, vs in iocs.items():
        report.append(f"* **{k}:** " + ", ".join(f"`{v}`" for v in vs[:20]))
    if det:
        report += ["", "## Recommended response", "", det["response"], "",
                   "## False-positive considerations", "", det["false_positives"]]
    report += ["", "## Evidence files", "",
               "alert.json, related_alerts.json, raw_events.jsonl, indicators.json, timeline.md - "
               "integrity hashes in sha256sums.txt"]
    (d / "report.md").write_text("\n".join(report) + "\n")

    sums = []
    for f in sorted(d.iterdir()):
        if f.name != "sha256sums.txt":
            sums.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}")
    (d / "sha256sums.txt").write_text("\n".join(sums) + "\n")
    manifest_hash = hashlib.sha256((d / "sha256sums.txt").read_bytes()).hexdigest()
    return str(d.relative_to(soclab.ROOT)), manifest_hash


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--rule-id")
    g.add_argument("--alert-id")
    p.add_argument("--srcip")
    p.add_argument("--window", type=int, default=30, help="pivot window in minutes (default 30)")
    p.add_argument("--analyst", default="soc-analyst")
    p.add_argument("--no-incident", action="store_true", help="only build the evidence bundle")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    args = p.parse_args(argv)

    ix = soclab.Indexer()
    alert = find_alert(ix, args)
    if not alert:
        print("no matching alert found", file=sys.stderr)
        return 1
    t = soclab.parse_ts(alert["timestamp"])
    start, end = t - dt.timedelta(minutes=args.window), t + dt.timedelta(minutes=args.window)
    q, pivots = pivot_query(alert, start, end)
    related = ix.search(soclab.ALERTS_INDEX, q, size=500)
    raw = ix.search(soclab.EVENTS_INDEX, q, size=1000)
    iocs = indicators(related + raw)
    first = related[0]["timestamp"] if related else alert["timestamp"]
    last = related[-1]["timestamp"] if related else alert["timestamp"]
    det = load_catalog().get(alert["rule"]["id"])

    inc_id = next_incident_id(ix, alert["rule"]["id"])
    path, manifest = write_bundle(inc_id, alert, related, raw, iocs, {"first_seen": first, "last_seen": last}, det)
    mitre = alert["rule"].get("mitre", {})
    now = soclab.iso(soclab.utcnow())
    incident = {
        "incident_id": inc_id, "title": f"{det['name'] if det else alert['rule']['description']} on {alert['agent']['name']}",
        "status": "open", "severity": soclab.severity_for_level(alert["rule"]["level"]), "level": alert["rule"]["level"],
        "playbook": det["playbook"] if det else None, "rule_id": alert["rule"]["id"],
        "rule_description": alert["rule"]["description"], "mitre_ids": mitre.get("id", []),
        "mitre_tactics": mitre.get("tactic", []), "source_alert_id": alert["id"],
        "source_ips": pivots["source_ips"], "users": pivots["users"], "hosts": pivots["hosts"],
        "related_alerts": len(related), "related_events": len(raw),
        "first_seen": soclab.iso(soclab.parse_ts(first)), "last_seen": soclab.iso(soclab.parse_ts(last)),
        "created_at": now, "updated_at": now, "analyst": args.analyst,
        "summary": f"{len(related)} related alerts and {len(raw)} raw events collected around alert {alert['id']}.",
        "evidence_path": path, "evidence_sha256": manifest,
    }
    (soclab.ROOT / path / "incident.json").write_text(soclab.dump(incident))
    if not args.no_incident:
        r = ix.put(f"/{soclab.INCIDENTS_INDEX}/_doc/{inc_id}?refresh=wait_for", incident)
        r.raise_for_status()
    if args.json:
        print(json.dumps(incident, indent=2))
    else:
        print(f"{inc_id} [{incident['severity']}] {incident['title']}")
        print(f"  playbook        : {incident['playbook']}")
        print(f"  MITRE           : {', '.join(incident['mitre_ids'])}")
        print(f"  related alerts  : {len(related)}   raw events: {len(raw)}")
        print(f"  evidence bundle : {path}/report.md")
        print(f"  incident record : {'not created (--no-incident)' if args.no_incident else 'soc-incidents/' + inc_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
