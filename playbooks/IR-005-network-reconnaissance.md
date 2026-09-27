# IR-005 — Network Reconnaissance Indicator

| | |
|---|---|
| **Severity range** | medium (single scan signature) → high (correlated port scan) |
| **MITRE ATT&CK** | T1046 Network Service Discovery |
| **Owner** | SOC L1 → network team |
| **Target time to triage** | high: 30 min · medium: 4 h |

## 1. Detection

| Rule | Detection | Level |
|---|---|---|
| 100150 | SOC-NET-001 Suricata "ET SCAN" signature | 8 |
| 100151 | SOC-NET-002 Port scan: ≥4 scan alerts from one source in 120 s | 12 |

Dashboard: *Network scans*, *Top network sources (Suricata)*, *Network security events*.

## 2. Triage

1. Source (`data.src_ip`), destination(s) (`data.dest_ip`), ports, signatures (`data.alert.signature`).
2. **Internal or external source?** An internal source scanning is far more serious (possible compromised host, lateral movement).
3. Approved scanner (vulnerability management, asset discovery) in a scheduled window? → document and suppress.
4. Open the incident: `make investigate RULE=100151`.

## 3. Investigation

* Which services were probed, and which are actually exposed/listening?
* Any follow-up from the same source after the scan: authentication attempts (IR-001), web attacks (IR-003),
  exploit signatures?
* Internal source: what process generated the traffic (Sysmon 3 on Windows, auditd/`ss -p` on Linux)? Treat the
  host as potentially compromised (IR-006).

## 4. Evidence collection

* Evidence bundle `runtime/evidence/<INC>/`.
* Suricata `eve.json` (alerts + flow records) for the window; PCAP if full capture is available.
* Firewall logs for the source; the list of exposed services at the time (`nmap` of your *own* assets by the network team, `ss -lntp`).

## 5. Containment

* External: block the source at the perimeter; confirm no exposed service was exploited.
* Internal: isolate the scanning host; disable the account running the scanning process.

## 6. Eradication

* Close unnecessary exposed ports; remove the scanning tool / malware from an internal host.

## 7. Recovery

* Restore network access for an internal host once clean; keep enhanced monitoring for 7 days.
* Re-run `make detection-test`.

## 8. Lessons learned

* Keep an inventory of authorised scanners and their windows to suppress known-good scans.
* Review the correlation threshold (4 alerts / 120 s) against the noise level of the environment.

## Logs to inspect

| Source | Location | Rules |
|---|---|---|
| Suricata EVE JSON | `/var/log/lab/suricata/eve.json` (lab-nids-01) | 86600/86601, 100150, 100151, 100201 |
| Firewall | perimeter / host | connection denies by source |
| Sysmon 3 / auditd | endpoints | process responsible for internal scanning |

## Indicators of compromise

* Many destination ports or hosts from one source in a short time; "ET SCAN" signatures.
* Scans followed by authentication or exploit attempts from the same source.
* An internal workstation scanning server subnets.

## Escalation criteria

* Internal source → **escalate to L2** and treat as a possible compromise.
* Scan followed by any successful authentication or exploit signature → declare an incident.
