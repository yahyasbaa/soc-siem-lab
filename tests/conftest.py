"""Shared pytest fixtures for the SOC lab test-suite.

Test layers
  tests/detection/test_catalog.py        static: catalog <-> rules <-> fixtures consistency
  tests/detection/test_logtest.py        engine: every logtest-capable fixture through wazuh-logtest
  tests/detection/test_detections_e2e.py pipeline: fixture -> agent -> manager -> indexer -> alert
  tests/infrastructure/                  containers, ports, networks
  tests/integration/                     SIEM services, ingestion, dashboards, investigation workflow
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "generate-test-events"))

import socgen  # noqa: E402
import soclab  # noqa: E402

REPORTS = ROOT / "reports"


def pytest_configure(config):
    REPORTS.mkdir(exist_ok=True)


@pytest.fixture(scope="session")
def env() -> dict:
    return soclab.load_env()


@pytest.fixture(scope="session")
def api(env) -> soclab.WazuhAPI:
    return soclab.WazuhAPI(env)


@pytest.fixture(scope="session")
def indexer(env) -> soclab.Indexer:
    return soclab.Indexer(env)


@pytest.fixture(scope="session")
def scenarios() -> list[socgen.Scenario]:
    return socgen.load_scenarios()


@pytest.fixture(scope="session")
def catalog() -> dict:
    import yaml
    return yaml.safe_load((ROOT / "detections" / "catalog.yml").read_text())


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, capture_output=True, text=True, check=check)


@pytest.fixture(scope="session")
def compose_ps() -> list[dict]:
    out = compose("ps", "--all", "--format", "json").stdout.strip()
    if not out:
        return []
    # compose v2 prints either a JSON array or one JSON object per line
    if out.startswith("["):
        return json.loads(out)
    return [json.loads(line) for line in out.splitlines() if line.strip()]
