#!/usr/bin/env python3
"""Generate the SOC analyst dashboard as OpenSearch Dashboards saved objects.

Writes dashboards/soc-overview.ndjson (committed). scripts/import-dashboards.py
fills in index-pattern field lists from the live indexer and imports it.

Panels are deliberately plain (metrics, tables, one pie, two time series):
an analyst should see at a glance what fired, how bad, from where, against
what, mapped to which ATT&CK technique, and what is still open.
"""
from __future__ import annotations

import json
import pathlib

OUT = pathlib.Path(__file__).with_name("soc-overview.ndjson")
VERSION = "2.19.6"

IDX_ALERTS = "soc-lab-alerts"
IDX_EVENTS = "soc-lab-events"
IDX_INCIDENTS = "soc-lab-incidents"

SOC = "rule.groups:soc_lab and not rule.groups:soc_health"


def index_pattern(oid: str, title: str, time_field: str) -> dict:
    return {"id": oid, "type": "index-pattern",
            "attributes": {"title": title, "timeFieldName": time_field, "fields": "[]"},
            "references": [], "migrationVersion": {"index-pattern": "7.6.0"}}


def search_source(index: str | None, query: str = "") -> tuple[str, list]:
    ss = {"query": {"query": query, "language": "kuery"}, "filter": []}
    refs = []
    if index:
        ss["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
        refs = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index}]
    return json.dumps(ss), refs


def vis(oid: str, title: str, vis_type: str, params: dict, aggs: list, index: str | None,
        query: str = "", description: str = "") -> dict:
    ss, refs = search_source(index, query)
    state = {"title": title, "type": vis_type, "params": params, "aggs": aggs}
    return {"id": oid, "type": "visualization",
            "attributes": {"title": title, "description": description, "version": 1,
                           "visState": json.dumps(state), "uiStateJSON": "{}",
                           "kibanaSavedObjectMeta": {"searchSourceJSON": ss}},
            "references": refs, "migrationVersion": {"visualization": "7.10.0"}}


def count(label: str) -> dict:
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": label}}


def metric(oid, title, label, index, query="", description=""):
    params = {"addTooltip": True, "addLegend": False, "type": "metric",
              "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                         "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                         "labels": {"show": True}, "invertColors": False,
                         "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 42}}}
    return vis(oid, title, "metric", params, [count(label)], index, query, description)


def terms(agg_id: str, field: str, size: int = 10, label: str | None = None, schema: str = "bucket") -> dict:
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "size": size, "order": "desc", "orderBy": "1", "otherBucket": False,
                       "missingBucket": False, "customLabel": label or field}}


def table(oid, title, index, buckets: list[tuple[str, str]], query="", size=10, description=""):
    params = {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False,
              "totalFunc": "sum", "percentageCol": ""}
    aggs = [count("Count")] + [terms(str(i + 2), f, size, label) for i, (f, label) in enumerate(buckets)]
    return vis(oid, title, "table", params, aggs, index, query, description)


SEVERITY_FILTERS = [
    {"input": {"query": "rule.level >= 15", "language": "kuery"}, "label": "critical (15)"},
    {"input": {"query": "rule.level >= 12 and rule.level < 15", "language": "kuery"}, "label": "high (12-14)"},
    {"input": {"query": "rule.level >= 7 and rule.level < 12", "language": "kuery"}, "label": "medium (7-11)"},
    {"input": {"query": "rule.level < 7", "language": "kuery"}, "label": "low (0-6)"},
]


def filters_agg(agg_id: str, filters: list, schema: str) -> dict:
    return {"id": agg_id, "enabled": True, "type": "filters", "schema": schema, "params": {"filters": filters}}


def date_hist(agg_id: str = "2") -> dict:
    return {"id": agg_id, "enabled": True, "type": "date_histogram", "schema": "segment",
            "params": {"field": "timestamp", "useNormalizedOpenSearchInterval": True, "interval": "auto",
                       "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}, "customLabel": "time"}}


def bar_params() -> dict:
    return {"type": "histogram", "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                              "style": {}, "scale": {"type": "linear"},
                              "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                           "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
            "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
            "addTimeMarker": False, "labels": {"show": False},
            "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}}


def pie(oid, title, index, bucket_agg: dict, query=""):
    params = {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
              "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}
    return vis(oid, title, "pie", params, [count("Alerts"), bucket_agg], index, query)


ANALYST_GUIDE = """### Analyst workflow
1. **Triage** - start with *High/critical detections* and *Top detections*. Sort by severity.
2. **Scope** - pivot on the source IP / host in *Top source IPs* and *Top targeted hosts*.
3. **Context** - check the ATT&CK technique and open the playbook (`playbooks/IR-00x`).
4. **Investigate** - `make investigate RULE=<rule id>` builds an evidence bundle and opens an incident.
5. **Track** - *Open incidents* lists every incident until it is closed with `scripts/incident.py close`.

Severity: low 0-6, medium 7-11, high 12-14, critical 15 (Wazuh rule level).
All data in this lab is synthetic telemetry generated by `scripts/generate-test-events`."""


def build() -> list[dict]:
    objs = [
        index_pattern(IDX_ALERTS, "wazuh-alerts-4.x-*", "timestamp"),
        index_pattern(IDX_EVENTS, "wazuh-archives-4.x-*", "timestamp"),
        index_pattern(IDX_INCIDENTS, "soc-incidents", "created_at"),
    ]
    v = [
        metric("soc-lab-m-events", "Total events", "Total events (all telemetry)", IDX_EVENTS),
        metric("soc-lab-m-alerts", "Total alerts", "Total alerts", IDX_ALERTS),
        metric("soc-lab-m-detections", "SOC detections", "SOC lab detections", IDX_ALERTS, SOC),
        metric("soc-lab-m-high", "High/critical detections", "High + critical", IDX_ALERTS, f"{SOC} and rule.level >= 12"),
        metric("soc-lab-m-authfail", "Authentication failures", "Authentication failures", IDX_ALERTS,
               "rule.groups:authentication_failed or rule.groups:authentication_failures"),
        metric("soc-lab-m-authok", "Authentication successes", "Authentication successes", IDX_ALERTS,
               "rule.groups:authentication_success"),
        metric("soc-lab-m-scans", "Network scans", "Network scan alerts", IDX_ALERTS, "rule.id:100150 or rule.id:100151"),
        metric("soc-lab-m-incidents", "Open incidents", "Open incidents", IDX_INCIDENTS, "status:open"),
        pie("soc-lab-p-severity", "Alerts by severity", IDX_ALERTS, filters_agg("2", SEVERITY_FILTERS, "segment")),
        vis("soc-lab-h-overtime", "Alerts over time by severity", "histogram", bar_params(),
            [count("Alerts"), date_hist("2"), filters_agg("3", SEVERITY_FILTERS, "group")], IDX_ALERTS),
        table("soc-lab-t-srcip", "Top source IPs (host & web logs)", IDX_ALERTS,
              [("data.srcip", "Source IP")], "data.srcip:*"),
        table("soc-lab-t-netsrc", "Top network sources (Suricata / Windows)", IDX_ALERTS,
              [("data.src_ip", "Suricata source")], "data.src_ip:*"),
        table("soc-lab-t-targets", "Top targeted hosts and services", IDX_ALERTS,
              [("agent.name", "Host"), ("decoder.name", "Service / log source")], SOC),
        table("soc-lab-t-mitre", "MITRE ATT&CK techniques", IDX_ALERTS,
              [("rule.mitre.id", "ATT&CK technique ID")], SOC, size=40),
        pie("soc-lab-p-tactics", "MITRE ATT&CK tactics", IDX_ALERTS, terms("2", "rule.mitre.tactic", 15, "Tactic", "segment"), SOC),
        table("soc-lab-t-detections", "Top detections", IDX_ALERTS,
              [("rule.id", "Rule"), ("rule.level", "Level")], SOC, size=40),
        table("soc-lab-t-process", "Suspicious processes and PowerShell", IDX_ALERTS,
              [("rule.id", "Rule"), ("agent.name", "Host")],
              "rule.groups:soc_process or rule.groups:soc_powershell"),
        table("soc-lab-t-web", "Web security events", IDX_ALERTS,
              [("rule.id", "Rule"), ("data.srcip", "Source")], "rule.groups:soc_web"),
        table("soc-lab-t-network", "Network security events", IDX_ALERTS,
              [("rule.id", "Rule"), ("data.dest_ip", "Destination")],
              "rule.groups:soc_network or rule.groups:suricata"),
        vis("soc-lab-h-auth", "Authentication activity over time", "histogram", bar_params(),
            [count("Events"), date_hist("2"), filters_agg("3", [
                {"input": {"query": "rule.groups:authentication_failed or rule.groups:authentication_failures",
                           "language": "kuery"}, "label": "failures"},
                {"input": {"query": "rule.groups:authentication_success", "language": "kuery"}, "label": "successes"},
            ], "group")], IDX_ALERTS),
        table("soc-lab-t-incidents", "Open incidents", IDX_INCIDENTS,
              [("incident_id", "Incident"), ("severity", "Severity"), ("title", "Title")], "status:open", size=50),
        vis("soc-lab-md-guide", "Analyst workflow", "markdown",
            {"fontSize": 12, "openLinksInNewTab": False, "markdown": ANALYST_GUIDE}, [], None),
    ]
    objs += v

    layout = [  # (vis id, x, y, w, h)
        ("soc-lab-m-events", 0, 0, 6, 7), ("soc-lab-m-alerts", 6, 0, 6, 7), ("soc-lab-m-detections", 12, 0, 6, 7),
        ("soc-lab-m-high", 18, 0, 6, 7), ("soc-lab-m-authfail", 24, 0, 6, 7), ("soc-lab-m-authok", 30, 0, 6, 7),
        ("soc-lab-m-scans", 36, 0, 6, 7), ("soc-lab-m-incidents", 42, 0, 6, 7),
        ("soc-lab-p-severity", 0, 7, 16, 13), ("soc-lab-h-overtime", 16, 7, 32, 13),
        ("soc-lab-t-detections", 0, 20, 24, 15), ("soc-lab-t-incidents", 24, 20, 24, 15),
        ("soc-lab-t-srcip", 0, 35, 16, 14), ("soc-lab-t-netsrc", 16, 35, 16, 14), ("soc-lab-t-targets", 32, 35, 16, 14),
        ("soc-lab-t-mitre", 0, 49, 28, 15), ("soc-lab-p-tactics", 28, 49, 20, 15),
        ("soc-lab-t-process", 0, 64, 16, 14), ("soc-lab-t-web", 16, 64, 16, 14), ("soc-lab-t-network", 32, 64, 16, 14),
        ("soc-lab-h-auth", 0, 78, 32, 13), ("soc-lab-md-guide", 32, 78, 16, 13),
    ]
    panels, refs = [], []
    for i, (vid, x, y, w, h) in enumerate(layout):
        pid = str(i + 1)
        panels.append({"version": VERSION, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                       "panelIndex": pid, "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": "visualization", "id": vid})
    assert {r["id"] for r in refs} == {o["id"] for o in v}, "every visualization must be on the dashboard"

    objs.append({"id": "soc-lab-overview", "type": "dashboard",
                 "attributes": {"title": "SOC Lab - Security Overview",
                                "description": "SOC analyst overview: volume, severity, sources, targets, ATT&CK, open incidents.",
                                "hits": 0, "panelsJSON": json.dumps(panels),
                                "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
                                "version": 1, "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
                                "refreshInterval": {"pause": False, "value": 30000},
                                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                                    {"query": {"query": "", "language": "kuery"}, "filter": []})}},
                 "references": refs, "migrationVersion": {"dashboard": "7.9.3"}})

    objs.append({"id": "soc-lab-search-detections", "type": "search",
                 "attributes": {"title": "SOC Lab - Detections (alert queue)", "description": "", "hits": 0,
                                "columns": ["rule.level", "rule.id", "rule.description", "agent.name", "data.srcip",
                                            "rule.mitre.id"],
                                "sort": [["timestamp", "desc"]], "version": 1,
                                "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(IDX_ALERTS, SOC)[0]}},
                 "references": search_source(IDX_ALERTS, SOC)[1], "migrationVersion": {"search": "7.9.3"}})
    return objs


def main() -> None:
    objs = build()
    OUT.write_text("".join(json.dumps(o, sort_keys=True) + "\n" for o in objs))
    print(f"wrote {len(objs)} saved objects to {OUT.name}")


if __name__ == "__main__":
    main()
