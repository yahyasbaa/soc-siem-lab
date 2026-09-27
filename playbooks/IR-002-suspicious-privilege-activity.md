# IR-002 — Suspicious Privilege Activity (privilege escalation, privileged account creation)

| | |
|---|---|
| **Severity range** | medium → high |
| **MITRE ATT&CK** | T1548.001 Setuid and Setgid, T1548.003 Sudo and Sudo Caching, T1098 Account Manipulation, T1136.001 Create Account: Local Account |
| **Owner** | SOC L2 |
| **Target time to triage** | high: 15 min · medium: 1 h |

## 1. Detection

| Rule | Detection | Level |
|---|---|---|
| 100120 | SOC-PRIV-001 Root shell via sudo | 10 |
| 100121 | SOC-PRIV-002 Repeated unauthorized sudo (user not in sudoers) | 10 |
| 100122 | SOC-PRIV-003 SUID/SGID bit set (auditd) | 12 |
| 100180 | SOC-PERS-001 Linux account added to privileged group (sudo, wheel, docker, …) | 12 |
| 100182 | SOC-PERS-002 Windows account added to Administrators / Domain Admins | 12 |
| 100183 | SOC-PERS-003 New Windows local account (4720) | 8 |

## 2. Triage

1. Who performed the action (`data.srcuser`, `data.audit.auid`, `win.eventdata.subjectUserName`) and on which host?
2. Is the actor an authorised administrator, and is there a change ticket for this action at this time?
3. For account changes: who is the *target* account (`data.dstuser`, `win.eventdata.memberSid` / `targetUserName`)? Is it new?
4. Look for an access-related alert just before (IR-001 brute force, web exploitation IR-003): a privilege
   change shortly after an intrusion indicator is **high**.
5. Open the incident: `make investigate RULE=<rule id>`.

## 3. Investigation

* Build the command timeline for the actor: all `sudo` events, auditd EXECVE for `auid`, Sysmon 1 for the user.
* For 100122 (SUID): which file? Is it an interpreter or a GTFOBins binary (`find`, `vim`, `python`, `bash`)?
  `find / -perm -4000 -newer /etc/hostname 2>/dev/null` lists recently changed SUID files.
* For 100180/100182: when was the account created (5902 / 4720), from which session, and has it logged in since?
* For 100121: were the attempted commands sensitive (`/etc/shadow`, shells)? Is the account itself compromised (IR-001)?

## 4. Evidence collection

* Evidence bundle `runtime/evidence/<INC>/` (alerts, raw sudo/audit/Security events, timeline, hashes).
* `/etc/sudoers`, `/etc/sudoers.d/*`, `/etc/group`, `/etc/passwd`, `/etc/shadow` metadata (not contents) — copy + hash.
* `ausearch -k perm_mod -i`, `ausearch -ua <auid> -i` output.
* Windows: Security 4720/4722/4724/4728/4732/4756, `net localgroup administrators` output.

## 5. Containment

* Remove the unauthorised group membership (`gpasswd -d <user> sudo`, `Remove-LocalGroupMember`).
* Lock the created/abused account; revert SUID bits (`chmod u-s <file>`).
* If the actor account is compromised, follow IR-001 containment (disable, kill sessions).

## 6. Eradication

* Remove backdoor accounts, SSH keys, sudoers drop-ins and SUID binaries introduced by the attacker.
* Verify package integrity (`dpkg -V`, `rpm -Va`) for modified binaries.

## 7. Recovery

* Restore the approved privileged-group membership baseline; document it.
* Re-run `make detection-test` to confirm privilege rules still fire.

## 8. Lessons learned

* Enforce change tickets for privileged-group changes; consider just-in-time admin access.
* Tune the root-shell rule with an allow-list of named administrators if it is noisy.
* Add file-integrity monitoring (syscheck) on `/etc/sudoers*` and SUID inventory.

## Logs to inspect

| Source | Location | Rules |
|---|---|---|
| sudo | auth.log | 5402-5405, 100120, 100121, 100193 |
| shadow-utils (useradd/usermod) | auth.log | 5902, 100180 (decoder `soc-usermod`) |
| auditd EXECVE | audit.log | 80700 tree, 100122, 100142 |
| Windows Security | EventChannel | 60109, 60154, 100182, 100183 |

## Indicators of compromise

* New accounts with UID ≥ 1000 added to sudo/wheel/docker/lxd outside onboarding.
* SUID set on interpreters/editors; `chmod 4755` in shell history.
* `sudo` by accounts that never used sudo before (stock rule 5403 "first time user executed sudo").

## Escalation criteria

* Privileged group change or SUID change without a change ticket → **escalate to L2 / incident manager**.
* Any privilege activity by an account involved in IR-001 or IR-003 in the last 24 h → declare an incident.
* Domain-level group changes (Domain/Enterprise/Schema Admins) → escalate immediately.
