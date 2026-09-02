#!/usr/bin/env python3
"""EventChannel forwarder for the simulated Windows host (lab-win-01).

A real Windows Wazuh agent reads the Security / PowerShell / Sysmon / Defender
event channels and pushes each record to its local agent queue as

    f:EventChannel:{"Message": "<rendered message>", "Event": "<Event xml>"}

The manager then decodes it with the built-in `windows_eventchannel` decoder
and evaluates the stock Windows ruleset plus the SOC lab rules.

No Windows VM is available in this Docker lab, so this forwarder reproduces
exactly that hand-off: it tails /var/log/lab/eventchannel.jsonl (written by
scripts/generate-test-events) and sends every line to the local agent queue
socket with the EventChannel queue id. Everything downstream - transport,
decoding, rules, indexing - is the genuine Wazuh pipeline.
"""
import json
import os
import socket
import sys
import time

SRC = os.environ.get("EVENTCHANNEL_FILE", "/var/log/lab/eventchannel.jsonl")
QUEUE = "/var/ossec/queue/sockets/queue"
STATE = "/var/ossec/var/run/eventchannel-forwarder.offset"


def log(msg: str) -> None:
    print(f"[eventchannel-forwarder] {msg}", flush=True)


def connect() -> socket.socket:
    while True:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(QUEUE)
            return s
        except OSError as exc:
            log(f"agent queue not ready ({exc}); retrying")
            time.sleep(2)


def load_offset(size: int) -> int:
    # First start: begin at end of file, like Wazuh logcollector does.
    try:
        off = int(open(STATE).read().strip())
        return off if off <= size else 0
    except (OSError, ValueError):
        return size


def save_offset(off: int) -> None:
    with open(STATE, "w") as fh:
        fh.write(str(off))


def main() -> int:
    while not os.path.exists(SRC):
        log(f"waiting for {SRC}")
        time.sleep(2)
    sock = connect()
    offset = load_offset(os.path.getsize(SRC))
    log(f"forwarding {SRC} from offset {offset}")
    buf = b""
    while True:
        size = os.path.getsize(SRC)
        if size < offset:  # truncated / rotated
            log("source truncated; restarting at 0")
            offset, buf = 0, b""
        if size > offset:
            with open(SRC, "rb") as fh:
                fh.seek(offset)
                chunk = fh.read(size - offset)
            offset = size
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for raw in lines:
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    assert "Event" in rec
                except (ValueError, AssertionError):
                    log("skipping malformed line (expected {\"Message\",\"Event\"} JSON)")
                    continue
                msg = b"f:EventChannel:" + json.dumps(rec, separators=(",", ":")).encode()
                for _ in range(3):
                    try:
                        sock.send(msg)
                        break
                    except OSError:
                        sock = connect()
            save_offset(offset - len(buf))
        time.sleep(0.5)


if __name__ == "__main__":
    sys.exit(main())
