"""Deterministic synthetic security-telemetry generator for the SOC lab.

The scenario definitions live in tests/fixtures/security_events/*.json. They
are pure DATA: log lines and event records that *describe* security-relevant
activity. Nothing here executes, scans, connects to or attacks anything - the
generator only renders text and appends it to the log files that the lab
Wazuh agents tail (runtime/hosts/<host>/...).

Determinism: given the same fixture and the same base time, render() always
produces byte-identical output. When events are injected into the live lab the
base time is "now" so the SIEM sees fresh timestamps; tests can pass a fixed
base time to verify reproducibility.

All IP addresses used by fixtures come from the documentation ranges
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or the private lab
range 10.10.0.0/16, so no rendered event refers to a real third party.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import pathlib
from dataclasses import dataclass, field
from typing import Iterable
import zlib
from xml.sax.saxutils import escape

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "security_events"
RUNTIME_HOSTS = ROOT / "runtime" / "hosts"

# host -> source -> (relative file path inside runtime/hosts/<host>, format)
SOURCES: dict[str, dict[str, tuple[str, str]]] = {
    "lab-linux-01": {
        "auth": ("auth.log", "syslog"),
        "audit": ("audit.log", "audit"),
        "heartbeat": ("heartbeat.log", "syslog"),
    },
    "lab-win-01": {
        "eventchannel": ("eventchannel.jsonl", "eventchannel"),
        "heartbeat": ("heartbeat.log", "syslog"),
    },
    "lab-web-01": {
        "nginx_access": ("nginx/access.log", "syslog"),
        "nginx_error": ("nginx/error.log", "syslog"),
        "heartbeat": ("heartbeat.log", "syslog"),
    },
    "lab-nids-01": {
        "eve": ("suricata/eve.json", "json"),
        "heartbeat": ("heartbeat.log", "syslog"),
    },
}

# Location string the agent reports for each source (used by logtest and by
# assertions on the alert "location" field).
AGENT_PATH_PREFIX = "/var/log/lab/"

ALLOWED_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "10.10.0.0/16", "127.0.0.0/8")
]

# Wazuh rule level -> SOC severity label (documented in docs/detection-catalog.md)
def severity_for_level(level: int) -> str:
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


@dataclass
class RenderedEvent:
    host: str
    source: str
    path: str          # path relative to runtime/hosts/<host>
    log_format: str
    line: str          # exactly what is appended to the file (no newline)

    @property
    def location(self) -> str:
        if self.log_format == "eventchannel":
            return "EventChannel"
        return AGENT_PATH_PREFIX + self.path


@dataclass
class Scenario:
    data: dict
    path: pathlib.Path
    events: list = field(default_factory=list)

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def host(self) -> str:
        return self.data["host"]

    @property
    def kind(self) -> str:
        return self.data.get("kind", "positive")

    @property
    def expect(self) -> list[dict]:
        exp = self.data.get("expect", [])
        return exp if isinstance(exp, list) else [exp]

    @property
    def forbid_rules(self) -> list[str]:
        return [str(r) for r in self.data.get("forbid_rules", [])]

    @property
    def identity(self) -> dict:
        return self.data.get("identity", {})

    @property
    def logtest(self) -> bool:
        return bool(self.data.get("logtest", True))


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_scenarios(names: Iterable[str] | None = None) -> list[Scenario]:
    files = sorted(FIXTURE_DIR.glob("*.json"))
    scenarios = [Scenario(json.loads(p.read_text()), p) for p in files]
    if names:
        wanted = set(names)
        scenarios = [s for s in scenarios if s.id in wanted or s.path.stem in wanted]
        missing = wanted - {s.id for s in scenarios} - {s.path.stem for s in scenarios}
        if missing:
            raise KeyError(f"unknown scenario(s): {', '.join(sorted(missing))}")
    for s in scenarios:
        validate_scenario(s)
    return scenarios


def validate_scenario(s: Scenario) -> None:
    d = s.data
    for key in ("id", "title", "description", "host", "kind", "events", "identity"):
        if key not in d:
            raise ValueError(f"{s.path.name}: missing key '{key}'")
    if s.host not in SOURCES:
        raise ValueError(f"{s.path.name}: unknown host {s.host}")
    if s.kind not in ("positive", "negative"):
        raise ValueError(f"{s.path.name}: kind must be positive|negative")
    if s.kind == "positive" and not s.expect:
        raise ValueError(f"{s.path.name}: positive scenario needs 'expect'")
    if s.kind == "negative" and not s.forbid_rules:
        raise ValueError(f"{s.path.name}: negative scenario needs 'forbid_rules'")
    for ev in d["events"]:
        if ev.get("source") not in SOURCES[s.host]:
            raise ValueError(f"{s.path.name}: source {ev.get('source')} not valid for {s.host}")
    # Safety: every IP literal in the fixture must be a lab/documentation address
    for ip in _iter_ips(json.dumps(d)):
        if not any(ip in net for net in ALLOWED_NETS):
            raise ValueError(f"{s.path.name}: IP {ip} is outside the lab/documentation ranges")


def _iter_ips(text: str):
    import re
    for m in re.finditer(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", text):
        try:
            yield ipaddress.ip_address(m.group(1))
        except ValueError:
            continue


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def fill(text: str, f: dict) -> str:
    """Substitute @@name@@ placeholders. A custom token is used instead of
    str.format because fixtures legitimately contain braces (JSON, ${jndi:})."""
    for key, value in f.items():
        text = text.replace(f"@@{key}@@", str(value))
    return text


def _ts_fields(t: dt.datetime, seq: int, salt: int = 0) -> dict:
    t = t.astimezone(dt.timezone.utc)
    return {
        "syslog_ts": f"{t:%b} {t.day:>2} {t:%H:%M:%S}",
        "iso_ts": t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}+0000",
        "win_ts": t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond:06d}0Z",
        "nginx_ts": t.strftime("%d/%b/%Y:%H:%M:%S +0000"),
        "nginx_err_ts": t.strftime("%Y/%m/%d %H:%M:%S"),
        "audit_ts": f"{int(t.timestamp())}.{t.microsecond // 1000:03d}",
        "seq": seq,
        # unique per scenario so auditd records of different scenarios are
        # never merged by the agent's audit log reader
        "audit_serial": 100000 + salt * 100 + seq,
        "record_id": 880000 + seq,
        "pid": 2000 + seq,
    }


def _attr(value: str) -> str:
    # Windows renders event XML with single-quoted attributes; the Wazuh
    # EventChannel parser expects that exact form.
    return "'" + escape(value, {"'": "&apos;"}) + "'"


def render_windows_event(win: dict, f: dict) -> str:
    """Render an EventChannel record exactly as the Wazuh Windows agent ships it:
    a JSON object holding the rendered message and the raw event XML."""
    provider = win["provider"]
    guid = win.get("provider_guid")
    prov = f"<Provider Name={_attr(provider)}" + (f" Guid={_attr(guid)}" if guid else "") + "/>"
    data_items = "".join(
        f"<Data Name={_attr(k)}>{escape(fill(str(v), f))}</Data>"
        for k, v in win.get("data", {}).items()
    )
    xml = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System>{prov}<EventID>{win['event_id']}</EventID><Version>{win.get('version', 0)}</Version>"
        f"<Level>{win.get('level', 0)}</Level><Task>{win.get('task', 0)}</Task><Opcode>0</Opcode>"
        f"<Keywords>{win.get('keywords', '0x8020000000000000')}</Keywords>"
        f"<TimeCreated SystemTime='{f['win_ts']}'/><EventRecordID>{f['record_id']}</EventRecordID>"
        f"<Correlation/><Execution ProcessID='{win.get('process_id', 4)}' ThreadID='{win.get('thread_id', 1000)}'/>"
        f"<Channel>{escape(win['channel'])}</Channel><Computer>{escape(win.get('computer', 'lab-win-01.lab.local'))}</Computer>"
        "<Security/></System>"
        f"<EventData>{data_items}</EventData></Event>"
    )
    return json.dumps({"Message": fill(win.get("message", ""), f), "Event": xml}, separators=(",", ":"))


def render_event(ev: dict, f: dict) -> str:
    if "template" in ev:
        return fill(ev["template"], f)
    if "win" in ev:
        return render_windows_event(ev["win"], f)
    if "eve" in ev:
        rec = {"timestamp": f["iso_ts"]}
        rec.update(json.loads(fill(json.dumps(ev["eve"]), f)))
        return json.dumps(rec, separators=(",", ":"))
    raise ValueError(f"event has no template/win/eve: {ev}")


def render(s: Scenario, base_time: dt.datetime) -> list[RenderedEvent]:
    """Render a scenario. Each emitted line is 100 ms after the previous one."""
    out: list[RenderedEvent] = []
    seq = 0
    salt = zlib.crc32(s.id.encode()) % 90000
    for ev in s.data["events"]:
        rel_path, fmt = SOURCES[s.host][ev["source"]]
        for _ in range(int(ev.get("repeat", 1))):
            f = _ts_fields(base_time + dt.timedelta(milliseconds=100 * seq), seq, salt)
            out.append(RenderedEvent(s.host, ev["source"], rel_path, fmt, render_event(ev, f)))
            seq += 1
    return out


# ---------------------------------------------------------------------------
# Injection (append rendered lines to the files tailed by the lab agents)
# ---------------------------------------------------------------------------

def inject(events: list[RenderedEvent], hosts_dir: pathlib.Path = RUNTIME_HOSTS) -> int:
    """Append events to their log files. Lines for the same file are written
    in a single append so multi-event scenarios keep their ordering."""
    by_file: dict[pathlib.Path, list[str]] = {}
    for e in events:
        by_file.setdefault(hosts_dir / e.host / e.path, []).append(e.line)
    for path, lines in by_file.items():
        if not path.parent.exists():
            raise FileNotFoundError(f"{path.parent} missing - run `make setup` first")
        with path.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    return len(events)


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)
