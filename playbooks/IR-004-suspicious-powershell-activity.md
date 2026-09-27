# IR-004 — Suspicious PowerShell Activity

| | |
|---|---|
| **Severity range** | high |
| **MITRE ATT&CK** | T1059.001 PowerShell, T1027 Obfuscated Files or Information, T1105 Ingress Tool Transfer |
| **Owner** | SOC L2 (endpoint) |
| **Target time to triage** | 15 min |

## 1. Detection

| Rule | Detection | Level | Source |
|---|---|---|---|
| 100130 | SOC-PS-001 PowerShell download cradle (IEX + download primitive) | 12 | PowerShell/Operational 4104 |
| 100131 | SOC-PS-002 Hidden / encoded PowerShell | 12 | Sysmon 1 (process creation) |

Related: 100132 (Defender/AMSI tampering from PowerShell) is handled in **IR-007**; outbound connections from
PowerShell (100200) in **IR-006**.

## 2. Triage

1. Host, user (`win.eventdata.user`), parent process (`win.eventdata.parentImage`), full command line or script block.
2. Decode encoded commands: `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<b64>'))`
   (UTF-16LE). In the lab the payload decodes to a harmless `Write-Output`.
3. Known management tooling (SCCM, RMM, installer)? Check parent image and signer; if yes, document and tune.
4. Download cradle: extract the URL/IP; is it internal software distribution or unknown?
5. Open the incident: `make investigate RULE=100130` / `100131`.

## 3. Investigation

* Process tree: Sysmon 1 for the `ProcessGuid` and its children; Sysmon 3 network connections from it (100200).
* Script block logging (4104) for the full deobfuscated script; module logging 4103.
* Files written (Sysmon 11), registry run keys (Sysmon 13), scheduled tasks (4698) after the event.
* Same user/host earlier: phishing document (100141), logon anomalies (IR-001).

## 4. Evidence collection

* Evidence bundle `runtime/evidence/<INC>/`.
* Export `Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-Sysmon/Operational` and `Security` logs (`wevtutil epl`).
* PowerShell console history: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.
* Memory image of the host if the payload executed (before reboot).
* Downloaded payload (hash + copy in a quarantined store).

## 5. Containment

* Isolate the host (EDR network containment / switch port), keep it running.
* Block the download URL/IP/domain at proxy and DNS.
* Disable the user account if credentials may be stolen.

## 6. Eradication

* Remove dropped files and persistence (run keys, scheduled tasks, WMI subscriptions, services).
* Reset credentials used on the host; reimage if integrity cannot be established.

## 7. Recovery

* Return the host to the network after a clean scan/reimage; monitor for recurrence.
* Re-run `make detection-test`.

## 8. Lessons learned

* Enforce Constrained Language Mode / AppLocker or WDAC for non-admins; keep script block logging enabled.
* Add allow-list entries (by parent image + signer) for legitimate encoded PowerShell to reduce false positives.

## Logs to inspect

| Source | Event IDs | Rules |
|---|---|---|
| Microsoft-Windows-PowerShell/Operational | 4103, **4104** | 91802 tree, 100130, 100132 |
| Microsoft-Windows-Sysmon/Operational | **1**, 3, 11, 13 | 61603/61605, 100131, 100200 |
| Security | 4688, 4624 | process creation, logon session |

## Indicators of compromise

* `-enc`/`-EncodedCommand` with long base64; `-w hidden`; `-nop`; `IEX`, `DownloadString`, `Net.WebClient`, `Invoke-WebRequest | iex`.
* PowerShell spawned by Office, browsers, `wscript`, `mshta`.
* PowerShell network connections to public IPs on non-standard ports.

## Escalation criteria

* Payload executed and reached the network, or parent is an Office application → **declare an incident**.
* Same command seen on more than one host → escalate (possible spreading / GPO abuse).
