# IR-007 — Security Control Tampering (defense evasion, configuration changes)

| | |
|---|---|
| **Severity range** | medium → high |
| **MITRE ATT&CK** | T1562.001 Disable or Modify Tools, T1562.002 Disable Windows Event Logging, T1562.004 Disable or Modify System Firewall, T1070.001 Clear Windows Event Logs |
| **Owner** | SOC L2 |
| **Target time to triage** | 15 min |

## 1. Detection

| Rule | Detection | Level |
|---|---|---|
| 100132 | SOC-PS-003 PowerShell Defender/AMSI tampering | 14 |
| 100190 | SOC-CONF-001 Windows event log cleared (1102 / 104) | 12 |
| 100191 | SOC-CONF-002 Windows audit policy weakened (4719 "removed") | 10 |
| 100192 | SOC-CONF-003 Defender protection disabled (5001 / 5010 / 5012) | 12 |
| 100193 | SOC-CONF-004 Linux security control disabled via sudo (ufw, auditd, SELinux, …) | 12 |

## 2. Triage

1. Which control, on which host, by which account (`subjectUserName`, `srcuser`), at what time?
2. Is there an approved change / maintenance window? Security-control changes without one are **high**.
3. Tampering is usually a *middle* step: look for what happened just before (access) and just after (payload).
4. Open the incident: `make investigate RULE=<rule id>`.

## 3. Investigation

* Timeline ±2 h on the host from the SIEM (forwarded logs survive a local log clear — that is the point of a SIEM).
* Windows: who ran `wevtutil cl` / `Clear-EventLog` / `auditpol` / `Set-MpPreference` (Sysmon 1, 4104)?
* Linux: commands run by the same sudo user afterwards; was auditd stopped before other activity?
* Compare the gap: events expected from the host but missing after the change.

## 4. Evidence collection

* Evidence bundle `runtime/evidence/<INC>/`.
* Current configuration snapshots: `auditpol /get /category:*`, `Get-MpPreference`, `ufw status verbose`,
  `auditctl -s`, `getenforce` — copied and hashed.
* SIEM copies of the logs that were cleared locally.

## 5. Containment

* Re-enable the control immediately (Defender real-time protection, audit policy, firewall, auditd).
* If unauthorised: isolate the host and disable the account that made the change.

## 6. Eradication

* Remove Defender exclusions and AMSI bypass artefacts; restore GPO-managed audit policy.
* Investigate and remove whatever the attacker ran while the control was off (see IR-004 / IR-006).

## 7. Recovery

* Verify telemetry is flowing again (`make health` — heartbeat from every host) and controls stay enabled.
* Re-run `make detection-test`.

## 8. Lessons learned

* Use tamper protection (Defender), immutable audit configuration (`auditctl -e 2`), centrally managed firewall policy.
* Alert on *missing* telemetry (agent disconnected / log silence) as a complementary detection.

## Logs to inspect

| Source | Events | Rules |
|---|---|---|
| Windows Security / System | 1102, 104, 4719 | 63103, 60112, 100190, 100191 |
| Windows Defender/Operational | 5001, 5010, 5012, 5007 | 62152, 100192 |
| PowerShell/Operational | 4104 | 100132 |
| Linux auth.log (sudo) | COMMAND= | 100193 |

## Indicators of compromise

* Log clears outside maintenance; audit subcategories set to "No Auditing".
* `Set-MpPreference -DisableRealtimeMonitoring $true`, new Defender exclusions, `AmsiUtils` strings.
* `ufw disable`, `systemctl stop auditd`, `setenforce 0`, `iptables -F`.

## Escalation criteria

* Any tampering without a change record → **escalate to L2 immediately**.
* Tampering combined with any other high alert on the same host within 24 h → declare an incident.
