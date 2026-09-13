"""Shared helpers for the SOC lab tooling and test-suite.

Talks only to the local lab services (127.0.0.1): the Wazuh manager API,
the Wazuh indexer (OpenSearch) and the Wazuh dashboard (OpenSearch Dashboards).
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import time
from typing import Any, Iterable

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = pathlib.Path(__file__).resolve().parents[2]
ALERTS_INDEX = "wazuh-alerts-4.x-*"
EVENTS_INDEX = "wazuh-archives-4.x-*"
INCIDENTS_INDEX = "soc-incidents"
LAB_AGENTS = ("lab-linux-01", "lab-win-01", "lab-web-01", "lab-nids-01")


def load_env(path: pathlib.Path | None = None) -> dict[str, str]:
    path = path or ROOT / ".env"
    if not path.exists():
        raise FileNotFoundError(f"{path} not found - run `make setup`")
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"')
    return env


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_ts(value: str) -> dt.datetime:
    # Wazuh: 2026-10-03T17:34:22.712+0000
    value = value.replace("Z", "+00:00")
    if len(value) > 5 and value[-5] in "+-" and value[-3] != ":":
        value = value[:-2] + ":" + value[-2:]
    return dt.datetime.fromisoformat(value)


def dotted(doc: dict, path: str) -> Any:
    cur: Any = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def severity_for_level(level: int) -> str:
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
class WazuhAPI:
    """Wazuh manager REST API (https://127.0.0.1:55000)."""

    def __init__(self, env: dict | None = None):
        env = env or load_env()
        self.base = f"https://127.0.0.1:{env.get('API_PORT', '55000')}"
        self.auth = (env["API_USERNAME"], env["API_PASSWORD"])
        self._token: str | None = None
        self.s = requests.Session()
        self.s.verify = False

    def token(self) -> str:
        if not self._token:
            r = self.s.post(f"{self.base}/security/user/authenticate?raw=true", auth=self.auth, timeout=15)
            r.raise_for_status()
            self._token = r.text.strip()
        return self._token

    def request(self, method: str, path: str, **kw) -> dict:
        for attempt in range(2):
            r = self.s.request(method, f"{self.base}{path}", headers={"Authorization": f"Bearer {self.token()}"},
                               timeout=30, **kw)
            if r.status_code == 401 and attempt == 0:
                self._token = None
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError("unreachable")

    def get(self, path: str, **params) -> dict:
        return self.request("GET", path, params=params)

    def agents(self) -> list[dict]:
        return self.get("/agents", select="id,name,status,ip,version", limit=500)["data"]["affected_items"]

    def logtest(self, event: str, location: str, log_format: str, token: str | None = None) -> dict:
        body = {"event": event, "location": location, "log_format": log_format}
        if token:
            body["token"] = token
        return self.request("PUT", "/logtest", json=body)["data"]

    def logtest_end(self, token: str) -> None:
        try:
            self.request("DELETE", f"/logtest/sessions/{token}")
        except requests.HTTPError:
            pass


# ---------------------------------------------------------------------------
class Indexer:
    """Wazuh indexer / OpenSearch (https://127.0.0.1:9200)."""

    def __init__(self, env: dict | None = None):
        env = env or load_env()
        self.base = f"https://127.0.0.1:{env.get('INDEXER_PORT', '9200')}"
        self.s = requests.Session()
        self.s.verify = False
        self.s.auth = (env["INDEXER_USERNAME"], env["INDEXER_PASSWORD"])

    def get(self, path: str, **kw) -> requests.Response:
        return self.s.get(f"{self.base}{path}", timeout=30, **kw)

    def put(self, path: str, body: dict | None = None, **kw) -> requests.Response:
        return self.s.put(f"{self.base}{path}", json=body, timeout=30, **kw)

    def post(self, path: str, body: dict | None = None, **kw) -> requests.Response:
        return self.s.post(f"{self.base}{path}", json=body, timeout=30, **kw)

    def search(self, index: str, query: dict, size: int = 100, sort: str = "asc", sort_field: str = "timestamp") -> list[dict]:
        body = {"size": size, "query": query, "sort": [{sort_field: {"order": sort, "unmapped_type": "date"}}]}
        r = self.post(f"/{index}/_search?ignore_unavailable=true&allow_no_indices=true", body)
        r.raise_for_status()
        return [h["_source"] | {"_id": h["_id"], "_index": h["_index"]} for h in r.json()["hits"]["hits"]]

    def count(self, index: str, query: dict | None = None) -> int:
        body = {"query": query} if query else None
        r = self.post(f"/{index}/_count?ignore_unavailable=true&allow_no_indices=true", body)
        r.raise_for_status()
        return r.json()["count"]

    def refresh(self, index: str) -> None:
        self.post(f"/{index}/_refresh?ignore_unavailable=true&allow_no_indices=true")

    def wait_for(self, index: str, query: dict, timeout: float = 90, min_hits: int = 1,
                 interval: float = 2) -> list[dict]:
        deadline = time.monotonic() + timeout
        hits: list[dict] = []
        while time.monotonic() < deadline:
            hits = self.search(index, query, size=200)
            if len(hits) >= min_hits:
                return hits
            time.sleep(interval)
        return hits


def q_and(*clauses: dict) -> dict:
    return {"bool": {"filter": list(clauses)}}


def q_since(t: dt.datetime, field: str = "timestamp") -> dict:
    return {"range": {field: {"gte": iso(t)}}}


def q_term(field: str, value: Any) -> dict:
    return {"match_phrase": {field: value}}


def q_identity(identity: dict) -> list[dict]:
    return [q_term(k, v) for k, v in identity.items()]


def q_terms(field: str, values: Iterable) -> dict:
    return {"terms": {field: list(values)}}


def dump(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, default=str)
