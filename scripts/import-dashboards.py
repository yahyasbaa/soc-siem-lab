#!/usr/bin/env python3
"""Create the soc-incidents index and import the SOC dashboards.

  1. waits for the Wazuh dashboard (OpenSearch Dashboards) API
  2. creates the soc-incidents index from opensearch/soc-incidents-mapping.json
  3. fills each index pattern's field list from the live indexer
  4. imports dashboards/soc-overview.ndjson (overwrite) and sets the default index
"""
from __future__ import annotations

import json
import sys
import time

import requests

import soclab

DASH = soclab.ROOT / "dashboards" / "soc-overview.ndjson"
MAPPING = soclab.ROOT / "opensearch" / "soc-incidents-mapping.json"
TEMPLATE = soclab.ROOT / "opensearch" / "soc-lab-alerts-template.json"


def main() -> int:
    env = soclab.load_env()
    base = f"https://127.0.0.1:{env.get('DASHBOARD_PORT', '5601')}"
    s = requests.Session()
    s.verify = False
    s.auth = (env["INDEXER_USERNAME"], env["INDEXER_PASSWORD"])
    s.headers["osd-xsrf"] = "true"

    for _ in range(60):
        try:
            if s.get(f"{base}/api/status", timeout=10).json()["status"]["overall"]["state"] == "green":
                break
        except (requests.RequestException, KeyError, ValueError):
            pass
        time.sleep(5)
    else:
        print("dashboard API not ready", file=sys.stderr)
        return 1

    ix = soclab.Indexer(env)
    if ix.get(f"/{soclab.INCIDENTS_INDEX}").status_code == 404:
        r = ix.put(f"/{soclab.INCIDENTS_INDEX}", json.loads(MAPPING.read_text()))
        r.raise_for_status()
        print(f"created index {soclab.INCIDENTS_INDEX}")

    # On a fresh install the daily indices appear with the first events (agent
    # enrollment). Wait for them so the index patterns get real field lists.
    for _ in range(60):
        if all(ix.count(p) > 0 for p in (soclab.ALERTS_INDEX, soclab.EVENTS_INDEX)):
            break
        time.sleep(5)
    else:
        print("warning: alert/event indices still empty; field lists will be incomplete", file=sys.stderr)

    # Declare the dynamic fields the dashboards use: template for future daily
    # indices, put-mapping for the indices that already exist.
    tpl = json.loads(TEMPLATE.read_text())
    tpl.pop("_comment", None)
    ix.put("/_template/soc-lab-fields", tpl).raise_for_status()
    for pattern in tpl["index_patterns"]:
        r = ix.put(f"/{pattern}/_mapping?allow_no_indices=true", tpl["mappings"])
        r.raise_for_status()
    print("index template soc-lab-fields installed and applied")

    objs = [json.loads(line) for line in DASH.read_text().splitlines() if line.strip()]
    for o in objs:
        if o["type"] != "index-pattern":
            continue
        title = o["attributes"]["title"]
        r = s.get(f"{base}/api/index_patterns/_fields_for_wildcard",
                  params=[("pattern", title)] + [("meta_fields", m) for m in ("_source", "_id", "_type", "_index", "_score")],
                  timeout=30)
        if r.status_code == 200:
            o["attributes"]["fields"] = json.dumps(r.json()["fields"])
            print(f"index pattern {title}: {len(r.json()['fields'])} fields")
        else:
            print(f"index pattern {title}: no data yet ({r.status_code}); fields will load on first use")

    payload = "".join(json.dumps(o) + "\n" for o in objs)
    r = s.post(f"{base}/api/saved_objects/_import", params={"overwrite": "true"},
               files={"file": ("soc-overview.ndjson", payload, "application/ndjson")}, timeout=60)
    r.raise_for_status()
    res = r.json()
    if not res.get("success"):
        print(json.dumps(res.get("errors"), indent=2), file=sys.stderr)
        return 1
    print(f"imported {res['successCount']} saved objects")
    s.post(f"{base}/api/opensearch-dashboards/settings", json={"changes": {"defaultIndex": "soc-lab-alerts"}}, timeout=30)
    print(f"dashboard: {base}/app/dashboards#/view/soc-lab-overview")
    return 0


if __name__ == "__main__":
    sys.exit(main())
