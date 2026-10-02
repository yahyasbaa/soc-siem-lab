# Security policy and safety scope

This repository is a **defensive training laboratory**. It exists to practise log collection, detection
engineering, alert triage and incident response.

## Safety scope

* **No offensive activity.** The lab doesn't scan, exploit, brute-force or connect to anything. Security
  scenarios are represented by *synthetic telemetry*: deterministic log lines and event records in
  `tests/fixtures/security_events/`. The generator (`scripts/generate-test-events/`) only appends text to
  local log files that the lab's Wazuh agents read. The command lines and payload strings inside fixtures
  are inert text and are never executed. The encoded PowerShell fixture decodes to a harmless
  `Write-Output`.
* **No real third parties.** Every IP address in a fixture is an RFC 5737 documentation address
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or the private lab range `10.10.0.0/16`. This is
  enforced in code: `socgen.validate_scenario()` rejects any other address, and
  `tests/detection/test_catalog.py` runs the check.
* **Network isolation.** The monitored lab hosts run on `soc-hosts`, an `internal` Docker network with no
  egress. The SIEM's indexer, API and dashboard ports are published on `127.0.0.1` only. The agent ports
  (1514/1515) aren't published. `tests/infrastructure/test_containers.py` verifies all of this.
* **No real credentials.** `make setup` generates random, lab-only passwords into `.env` (mode 600, git-ignored).
  User names and accounts in the fixtures are fictitious.

## Lab-only shortcuts (do not copy to production)

| Shortcut | Why it is acceptable here | Production practice |
|---|---|---|
| Self-signed CA generated per install, private keys readable by the containers (`wazuh/certs`, 0644) | single-host lab, git-ignored | dedicated PKI, keys readable only by the service user |
| Agent enrollment without a password (`use_password no`), forced re-enrollment | agents are only reachable on the internal Docker network | enrollment password or certificate-based enrollment |
| `admin` indexer user used by Filebeat, the dashboard importer and the tests | fewer moving parts | least-privilege users per integration |
| Single-threaded remoted/analysisd | deterministic correlation for tests | default worker pools sized to EPS |
| No retention / ISM policy on indices | lab data is disposable (`make clean`) | ISM rollover and retention |
| Vulnerability-detection feeds disabled | offline lab, no Internet dependency | enabled |

## Reporting

If you find a way this lab could affect anything outside the local machine (for example a fixture that
causes real network traffic, or a port exposed beyond loopback), treat it as a bug. Open an issue with the
details, or fix it and add a regression test next to the existing safety tests.
