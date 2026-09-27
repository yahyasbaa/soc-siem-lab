# IR-003 — Suspicious Web Activity (reconnaissance, injection, exploitation attempts)

| | |
|---|---|
| **Severity range** | low (unusual method) → high (Log4Shell, SQLi, command injection) |
| **MITRE ATT&CK** | T1595.002 Vulnerability Scanning, T1595.003 Wordlist Scanning, T1190 Exploit Public-Facing Application, T1083, T1059.004, T1059.007 |
| **Owner** | SOC L1 → L2 / application owner |
| **Target time to triage** | high: 15 min · medium: 1 h · low: daily review |

## 1. Detection

| Rule | Detection | Level |
|---|---|---|
| 100160 | SOC-WEB-001 Sensitive path request (.env, .git, admin panels, backups) | 6 |
| 100161 | SOC-WEB-001b Web content discovery (≥6 sensitive paths / 60 s) | 10 |
| 100162 | SOC-WEB-002 Scanner user agent (sqlmap, nikto, nuclei, …) | 8 |
| 100163 | SOC-WEB-003 Path traversal / LFI | 10 |
| 100164 | SOC-WEB-008 Unusual HTTP method (TRACE, WebDAV, …) | 5 |
| 100170 | SOC-WEB-004 SQL injection | 12 |
| 100171 | SOC-WEB-005 Cross-site scripting | 10 |
| 100172 | SOC-WEB-006 OS command injection | 12 |
| 100173 | SOC-WEB-007 Log4Shell JNDI injection | 14 |
| 100175 | SOC-WEB-009 Nginx blocked hidden-file access (error log) | 6 |

Dashboard: *Web security events*, *Top source IPs*.

## 2. Triage

1. Source IP, URL (`data.url`), method (`data.protocol`), **status code (`data.id`)** and user agent.
2. **Did it succeed?** 4xx/5xx → attempt; **2xx on an attack pattern or a secret file → possible compromise**.
3. Breadth: how many requests/patterns from this IP (`data.srcip:"<ip>"`)? A single pattern vs a scanner sweep.
4. Is the source an authorised scanner (DAST, pentest window)?
5. Open the incident: `make investigate RULE=<rule id>`.

## 3. Investigation

* All requests from the source ±24 h in the archives index (`wazuh-archives-*`, `agent.name:lab-web-01`).
* Response sizes for the attack requests — unusually large 200 responses suggest data disclosure.
* Application/database logs for errors at the same timestamps (SQL errors, stack traces).
* Post-exploitation on the web host: auditd EXECVE by the web user (uid 33/`www-data`), new files in the
  web root, outbound connections (IR-006: 100142, 100200, 100201).
* Log4Shell: any outbound LDAP/RMI (389/1389/1099) from servers after the request.

## 4. Evidence collection

* Evidence bundle `runtime/evidence/<INC>/` (alerts, raw access/error log lines, indicators, timeline, hashes).
* Copies of Nginx `access.log` / `error.log` for the window (lab: `runtime/hosts/lab-web-01/nginx/`).
* Web root file listing with hashes and mtimes; WAF logs if present.

## 5. Containment

* Block the source IP (WAF / Nginx `deny`, firewall); rate-limit the targeted endpoint.
* If exploitation succeeded: take the application out of rotation, preserve the host, rotate application secrets
  (DB passwords, API keys, `.env` contents) that may have been exposed.

## 6. Eradication

* Patch / fix the vulnerable parameter (prepared statements, output encoding, input validation).
* Remove exposed files (`.git/`, `.env`, backups) from the web root; deny hidden files (`location ~ /\.` as in the lab).
* Remove any web shells or attacker files.

## 7. Recovery

* Redeploy from a known-good build; restore data if modified.
* Monitor the endpoint and source for recurrence; re-run `make detection-test`.

## 8. Lessons learned

* Add a WAF rule for the observed pattern; add a regression test fixture for any new pattern
  (`tests/fixtures/security_events/`).
* Review why sensitive files were deployable to the web root.

## Logs to inspect

| Source | Location | Decoder / rules |
|---|---|---|
| Nginx access log | `/var/log/lab/nginx/access.log` | `web-accesslog` → 31100 tree, 100160-100173 |
| Nginx error log | `/var/log/lab/nginx/error.log` | `nginx-errorlog` → 31301, 100175 |
| auditd on web host | audit.log | 100142 (shells by the web user) |
| Suricata | eve.json | HTTP alerts, 100150/100201 |

## Indicators of compromise

* Requests with `UNION SELECT`, `' OR 1=1`, `../`, `/etc/passwd`, `${jndi:`, `;cat`, `<script>` and **2xx** responses.
* Scanner user agents; bursts of 404 on admin/backup paths from one IP.
* Unexpected processes spawned by the web server user; new files in the web root.

## Escalation criteria

* Any attack pattern answered with 2xx, or 100173 (Log4Shell) against a Java-backed service → **escalate to L2 + application owner**.
* Evidence of code execution on the web host → declare an incident, follow IR-006.
