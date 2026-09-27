# IR-001 — Authentication Abuse (brute force, password guessing, credential compromise)

| | |
|---|---|
| **Severity range** | low (single failure) → high (success after brute force) |
| **MITRE ATT&CK** | T1110 Brute Force, T1110.001 Password Guessing, T1078 Valid Accounts |
| **Owner** | SOC L1 triage → L2 investigation |
| **Target time to triage** | high: 15 min · medium: 1 h |

## 1. Detection

| Rule | Detection | Level | Meaning |
|---|---|---|---|
| 100100 | SOC-AUTH-001 SSH authentication failure | 5 | single failed SSH login (context only) |
| 100101 | SOC-AUTH-002 SSH brute force | 10 | ≥5 failures from one IP in 120 s |
| 100102 | SOC-AUTH-003 SSH login after brute force | **13** | a brute-forcing IP logged in successfully |
| 100110 | SOC-AUTH-004 Windows logon failure | 5 | single 4625 (context only) |
| 100111 | SOC-AUTH-005 Multiple Windows logon failures | 10 | ≥4 × 4625 from one IP in 120 s |
| 100112 | SOC-AUTH-006 Windows logon after repeated failures | **13** | 4624 from an IP that just triggered 100111 |

Dashboard: *SOC Lab – Security Overview* → *Authentication failures / successes*, *Top source IPs*, *Authentication activity over time*.

## 2. Triage

1. Open the alert; note `data.srcip` / `data.win.eventdata.ipAddress`, target account(s), host, time.
2. Is the source internal (10.x / 192.168.x) or external? Is it an approved scanner or jump host?
3. **Did any login succeed?** Search for 100102 / 100112, or any `authentication_success` from the same IP:
   `rule.groups:authentication_success and data.srcip:"<ip>"`
4. Classify:
   * failures only, external, no success → **medium**, contain at perimeter;
   * any success from the source → **high**, assume credential compromise, escalate to L2.
5. Record the decision: `make investigate RULE=100101` (or 100102 / 100111 / 100112) opens an incident.

## 3. Investigation

* Scope the source: all alerts from the IP in ±24 h (other hosts? web attacks? scans → IR-005 / IR-003).
* Scope the account: other sources that used the same account; time of last legitimate login.
* For a successful login: what happened in the session — sudo usage (IR-002), process execution
  (auditd / Sysmon), new accounts, outbound connections (IR-006).
* Windows: correlate 4624 `TargetLogonId` with 4688/Sysmon 1 for that logon session; check logon type
  (3 = network, 10 = RDP).
* Pull the evidence bundle written by `scripts/investigate.py` (`runtime/evidence/<INC>/report.md`).

## 4. Evidence collection

* `runtime/evidence/<INC>/` — alert, related alerts, raw events, indicators, timeline, SHA-256 manifest.
* Raw sources: `/var/log/auth.log` (`/var/log/lab/auth.log` in the lab), `wtmp`/`btmp` (`last`, `lastb`),
  Windows Security log 4625/4624/4776/4740.
* For a compromised Linux account: `~/.bash_history`, `~/.ssh/authorized_keys`, `crontab -l`.
* Preserve copies before containment changes anything; record hashes in the incident.

## 5. Containment

* Block the source IP at the perimeter / host firewall (`ufw deny from <ip>` / NSG / security group).
* Successful login: disable the account (`usermod -L`, `Disable-ADAccount`), kill active sessions
  (`pkill -KILL -u <user>`, `logoff`), revoke SSH keys and tokens.
* If the account is privileged, isolate the host from the network (keep it powered on for forensics).

## 6. Eradication

* Remove any persistence created during the session (authorized_keys, cron, services, new accounts).
* Reset the password / rotate keys for every account the source touched.
* Disable SSH password authentication (`PasswordAuthentication no`), enforce MFA for remote access.

## 7. Recovery

* Re-enable the account with new credentials after the user is verified out-of-band.
* Monitor the account and source for 7 days (saved search on `data.srcip` / user).
* Confirm detections still fire: `make detection-test`.

## 8. Lessons learned

* Was the threshold (5 in 120 s SSH, 4 in 120 s Windows) right? Adjust frequency/timeframe in
  `soc_lab_rules.xml` and the catalog; the tests will flag any drift.
* Should the exposed service be reachable at all (VPN/bastion only)?
* Add the source to a deny list (CDB list) if it is persistent.

## Logs to inspect

| Source | Location | Wazuh decoder / rules |
|---|---|---|
| sshd | auth.log | `sshd` → 5710/5760/5715, 100100-100102 |
| Windows Security | EventChannel | `windows_eventchannel` → 60122/60106, 100110-100112 |
| Windows NTLM | 4776 | credential validation by DC |
| PAM / sudo | auth.log | 5402-5405 (post-login activity) |

## Indicators of compromise

* Source IP with ≥5 failures followed by `Accepted password` / 4624.
* Failures for many distinct user names from one IP (spraying) or for non-existent users (`invalid user`).
* Successful logins at unusual hours / from new geographies for the account.

## Escalation criteria

* **Escalate to L2 immediately**: any 100102 or 100112; brute force against a privileged account
  (root, administrator, service accounts); the same source hitting more than one host.
* **Escalate to incident manager**: confirmed post-login activity (privilege escalation, persistence,
  data access) → declare a security incident.
