"""Infrastructure: required containers, ports and networks."""
from __future__ import annotations

import json
import socket
import subprocess

import pytest

SERVICES = ["wazuh.indexer", "wazuh.manager", "wazuh.dashboard",
            "lab-linux-01", "lab-win-01", "lab-web-01", "lab-nids-01", "web-nginx"]
# host port -> what must answer there (all bound to 127.0.0.1 only)
PORTS = {"INDEXER_PORT": "Wazuh indexer (OpenSearch)", "API_PORT": "Wazuh manager API",
         "DASHBOARD_PORT": "Wazuh dashboard"}


def by_service(compose_ps):
    return {c["Service"]: c for c in compose_ps}


@pytest.mark.parametrize("service", SERVICES)
def test_container_running_and_healthy(compose_ps, service):
    c = by_service(compose_ps).get(service)
    assert c, f"{service} container does not exist"
    assert c["State"] == "running", f"{service} is {c['State']}"
    assert c.get("Health") in ("healthy", ""), f"{service} health is {c.get('Health')}"


@pytest.mark.parametrize("port_var", sorted(PORTS))
def test_required_port_reachable_on_localhost(env, port_var):
    with socket.create_connection(("127.0.0.1", int(env[port_var])), timeout=5):
        pass


def test_published_ports_bound_to_loopback_only(compose_ps):
    for c in compose_ps:
        for p in c.get("Publishers") or []:
            if p.get("PublishedPort"):
                assert p["URL"] in ("127.0.0.1", "::1"), \
                    f"{c['Service']} publishes {p['PublishedPort']} on {p['URL']} (must be loopback only)"


def test_agent_and_syslog_ports_not_published(compose_ps):
    published = {p.get("PublishedPort") for c in compose_ps for p in (c.get("Publishers") or [])}
    assert not published & {1514, 1515, 514}, "agent/syslog ports must stay inside the Docker network"


def _network(name_suffix: str) -> dict:
    nets = subprocess.run(["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True,
                          check=True).stdout.split()
    match = [n for n in nets if n.endswith(name_suffix)]
    assert match, f"network *{name_suffix} not found"
    return json.loads(subprocess.run(["docker", "network", "inspect", match[0]], capture_output=True, text=True,
                                     check=True).stdout)[0]


def test_required_networks_exist():
    core = _network("_soc-core")
    hosts = _network("_soc-hosts")
    assert core["Driver"] == "bridge" and hosts["Driver"] == "bridge"


def test_lab_host_network_has_no_external_egress():
    assert _network("_soc-hosts")["Internal"] is True, "soc-hosts must be an internal (no egress) network"


def test_lab_hosts_only_on_internal_network(compose_ps):
    for svc in ("lab-linux-01", "lab-win-01", "lab-web-01", "lab-nids-01", "web-nginx"):
        cid = by_service(compose_ps)[svc]["ID"]
        nets = json.loads(subprocess.run(["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", cid],
                                         capture_output=True, text=True, check=True).stdout)
        assert all(n.endswith("_soc-hosts") for n in nets), f"{svc} attached to {list(nets)}"


def test_required_volumes_exist():
    vols = subprocess.run(["docker", "volume", "ls", "--format", "{{.Name}}"], capture_output=True, text=True,
                          check=True).stdout.split()
    for v in ("wazuh-indexer-data", "wazuh_etc", "wazuh_logs", "wazuh_queue"):
        assert any(x.endswith("_" + v) for x in vols), f"volume {v} missing"
