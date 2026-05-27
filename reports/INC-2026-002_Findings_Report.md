---
title: "INC-2026-002 : Incident Investigation Report"
subtitle: "Root-level compromise of bru-app-01 (NexaCorp Brussels DC)"
author: "Johan-Emmanuel Hatchi"
team: "BLUE"
team_color: "BLUE"
classification: "CRITICAL"
incident_id: "INC-2026-002"
related_incident: "INC-2026-001"
target_host: "bru-app-01"
target_os: "Debian 12"
incident_date: "2026-05-16"
investigation_date: "2026-05-27"
report_version: "v2"
report_status: "final"
investigator: "Johan-Emmanuel Hatchi, BeCode Corp SOC Team"
mitre_techniques:
  - T1078.003
  - T1133
  - T1110.001
  - T1595.002
  - T1552.004
  - T1572
  - T1548.001
  - T1057
  - T1083
  - T1003.008
  - T1136.001
  - T1053.003
---


**Classification :** CRITICAL, Root-level compromise, data exfiltration risk
**Target host :** bru-app-01 (NexaCorp Brussels internal application server)
**Incident date :** 2026-05-16
**Investigation date :** 2026-05-27
**Investigator :** Johan-Emmanuel Hatchi, BeCode Corp SOC Team
**Report version :** v1 (draft)
**Related incident :** INC-2026-001 (Liège services server, same threat actor)

---

## 1. Executive Summary

On the night of May 16, 2026, a threat actor compromised `bru-app-01`, NexaCorp's Brussels internal application server. The attacker authenticated as the service account `svc_api` using a stolen SSH private key, escalated to root via a misconfigured SUID bit on `/usr/bin/find`, dumped credential material, harvested SSH keys, created a backdoor account, and installed a cron-based persistence mechanism.

The intrusion is the direct continuation of INC-2026-001 (Liège). The SSH private key used to access bru-app-01 was almost certainly harvested during the prior compromise. Both incidents must be treated as a single coordinated campaign.

The attacker maintains potential access to NexaCorp infrastructure through three vectors :
1. The original SSH key (still valid if not yet rotated)
2. The backdoor user `it_support` (with attacker-defined password)
3. The cron persistence file `/etc/cron.d/svc-updater`

All three must be neutralized before any other action is taken. Beyond bru-app-01, every NexaCorp host whose `authorized_keys` could trust a key compromised on this server must be considered potentially at risk.

---

## 2. Incident Overview

### 2.1 Target system

| Field | Value |
|---|---|
| Hostname | bru-app-01 |
| Operating system | Debian 12 (Linux) |
| Internal IP | 10.10.10.42 |
| Management IP | 192.168.100.199 |
| Service account | svc_api (uid=1000), runs the internal REST API |
| Wazuh agent | tgt-blue11 (id 041) |

### 2.2 Investigation scope

The SOC team received an evidence bundle containing the following log files :

| File | Purpose |
|---|---|
| auth.log | SSH authentication events, PAM, useradd |
| audit.log | Linux audit daemon syscall trail |
| syslog | General system events |
| cron.log | Scheduled task execution |
| INCIDENT_METADATA.txt | Initial NexaCorp summary |

The four investigation questions framed by NexaCorp management :

1. How did the attacker get in?
2. What did they do?
3. How far did they get?
4. What must be done right now?

### 2.3 Methodology

The investigation followed a structured DFIR approach :
1. Timeline reconstruction from authentication logs (auth.log)
2. Privilege escalation analysis through audit syscalls (audit.log)
3. Post-exploitation action mapping via process-title decoding
4. Cross-correlation with INCIDENT_METADATA.txt to validate findings
5. Live confirmation via Wazuh SIEM (Phase 2, planned)

All timestamps in this report are in local Brussels time (CEST, UTC+02:00) unless otherwise indicated.

---

## 3. Attack Chain Summary

The attack unfolded in six distinct phases, summarized below. Each phase is detailed in Section 5.

```
[Phase 1] Reconnaissance     17:45:14 - 19:41:06  (T1110.001, diversion)
[Phase 2] Initial access      17:43:43             (T1078.003, T1133)
[Phase 3] Beacon persistence  17:43:43 - 19:42:37  (40 logins, T1572)
[Phase 4] Privilege esc       19:43:01             (T1548.001, SUID find)
[Phase 5] Credential dump     19:43+               (T1003.008, T1552.004)
[Phase 6] Persistence install 19:47:07             (T1136.001, T1053.003)
```

---

## 4. Timeline

| Timestamp (CEST) | Event | Source | ATT&CK |
|---|---|---|---|
| 2026-05-16 17:43:43 | Initial access : SSH publickey auth as svc_api from 185.220.101.68 (Tor) | auth.log | T1078.003 |
| 2026-05-16 17:45:14 | Brute force diversion starts (first failed SSH attempt) | auth.log | T1110.001 |
| 2026-05-16 17:43:43 to 19:42:37 | 40 successful SSH publickey logins as svc_api, intervals of approximately 3 minutes, rotating Tor IPs | auth.log | T1071.004, T1572 |
| 2026-05-16 19:41:06 | Brute force diversion ends (last failed SSH attempt) | auth.log | T1110.001 |
| 2026-05-16 19:42:37 | Last beacon login before privilege escalation | auth.log | T1071.004 |
| 2026-05-16 19:43:01 | Privilege escalation moment (attack reference timestamp) | INCIDENT_METADATA | T1548.001 |
| 2026-05-16 19:47:07.478 | Backdoor user creation : useradd it_support | auth.log | T1136.001 |
| 2026-05-16 19:47:07.527 | Password set on it_support via chpasswd | auth.log | T1136.001 |
| 2026-05-16 22:47:02 to 23:41:54 | 55 SUID find exploit events (uid=1000 svc_api, euid=0 root) | audit.log | T1548.001 |
| 2026-05-16 22:47:02 to 23:41:54 | 27 reads of /etc/shadow | audit.log | T1003.008 |
| 2026-05-16 22:47:02 to 23:41:54 | 54 systematic searches for SSH private keys (`find /home -name id_rsa`) | audit.log | T1552.004 |

---

## 5. Findings

### 5.1 Reconnaissance phase

**Question :** Was the attacker probing the server before making their move?

**Findings :**
- Window : 2026-05-16 17:45:14 to 19:41:06, duration approximately 1h56
- Volume : 39 SSH authentication failures, 100% on non-existent accounts
- Sources : 36 distinct IPs across 5 /24 blocks identified as Tor exit nodes
- Targets : 8 usernames, all aligned with NexaCorp naming conventions
- Distribution : maximum 2 attempts per IP, low frequency (approximately one every 3 minutes)

**Tor exit node blocks identified :**

| Block | Suspected operator | Distinct IPs |
|---|---|---|
| 185.220.101.0/24 | Foundation for Applied Privacy | 6 |
| 162.247.74.0/24 | Quintex Alliance | 4 |
| 45.142.212.0/24 | (Tor exit) | 11 |
| 89.248.167.0/24 | (Tor exit) | 7 |
| 193.32.162.0/24 | (Tor exit) | 8 |

**Usernames targeted :** svc_api, api, nexacorp, deploy, backup, admin, root, ubuntu.

**Assessment :**

This is account enumeration over Tor, not credential brute force. The total volume is deliberately kept below typical fail2ban thresholds. The username list shows the attacker had prior knowledge of NexaCorp internal naming conventions, consistent with information gathered during INC-2026-001 (Liège server compromise).

The probing activity runs in parallel with successful publickey logins (Section 5.2). This is the strongest single indicator that the probing is a diversion : the attacker was already inside through a different channel when these failed attempts were generated.

**ATT&CK :**
- T1595.002 (Active Scanning : Vulnerability Scanning)
- T1110.001 (Brute Force : Password Guessing), failed attempts only

**Evidence commands :**

```bash
grep "Failed password" auth.log | wc -l                                  # 39
grep "Failed password" auth.log | head -1                                # first attempt 17:45:14
grep "Failed password" auth.log | tail -1                                # last attempt 19:41:06
grep "Failed password" auth.log | grep -oE "from [0-9.]+" | sort -u      # 36 distinct IPs
grep "Failed password" auth.log | grep -oE "invalid user [^ ]+" | sort -u  # 8 distinct users
```

---

### 5.2 Initial access vector

**Question :** The attacker got in as svc_api. How? When? Using what?

**Findings :**
- Initial access timestamp : 2026-05-16 17:43:43
- Method : SSH public key authentication
- Account : svc_api (uid=1000)
- Key fingerprint : `RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA`
- Source IP : 185.220.101.68 (Tor exit node)
- Subsequent activity : 40 successful publickey logins between 17:43:43 and 19:42:37

**Assessment :**

The attacker did not brute force their way in. They authenticated using a valid SSH key that they should not have possessed. The most plausible source is the prior compromise of the Liège services server (INC-2026-001), where the threat actor had shell access and could harvest SSH key material from `/home/svc_api/.ssh/` if the svc_api service account was provisioned on both hosts (which is consistent with NexaCorp's standard service account deployment).

All 40 successful logins use the same key fingerprint, all from IPs within `185.220.101.0/24` (Tor exit nodes operated by Foundation for Applied Privacy). The 3-minute interval between connections is too regular for human interactive activity. This pattern is consistent with an automated beacon : a deployed backdoor or RAT performing scheduled callbacks through Tor.

The attacker maintained this low-privilege foothold for approximately 2 hours before pivoting to privilege escalation. The intermediate period was likely used for internal reconnaissance, identifying the SUID find misconfiguration described in Section 5.3.

**ATT&CK :**
- T1078.003 (Valid Accounts : Local Accounts)
- T1133 (External Remote Services)
- T1552.004 (Unsecured Credentials : Private Keys), context : key likely harvested from INC-2026-001
- T1071.004 / T1572 (Tor-based command and control channel)

**Evidence commands :**

```bash
grep "Accepted publickey" auth.log | wc -l                                            # 40
grep "Accepted publickey" auth.log | head -1                                          # initial access
grep "Accepted publickey" auth.log | grep -oE "SHA256:[A-Za-z0-9+/=]+" | sort -u      # single fingerprint
```

---

### 5.3 Privilege escalation

**Question :** The attacker had only svc_api. The audit log shows them with root. How did they escalate?

**Findings :**
- Mechanism : SUID bit misconfiguration on `/usr/bin/find`
- Filesystem mode : `0104755` (SUID bit set, owner root, executable by all)
- Evidence count : 55 distinct events tagged `key="suid_escalation"` in audit.log
- Identity signature : every event shows `uid=1000` (svc_api) and `euid=0` (root)
- Time window in audit.log : 22:47:02 to 23:41:54 (audit.log coverage starts later than the 19:43:01 attack timestamp due to a logging gap)

**Assessment :**

The attacker exploited a classic GTFObins technique on `/usr/bin/find`. The SUID bit, combined with root ownership, gives any caller root privileges through this binary. The attacker did not use find for an interactive shell escape but for automated read access to root-owned files. Six distinct commands were chained through this mechanism :

| Command | Occurrences | Purpose |
|---|---|---|
| `ps aux --no-headers` | 112 | Process enumeration |
| `find /home/svc_api -name *.log -newer /etc/hostname` | 56 | Recent log search (defender activity detection) |
| `bash -c "cat /proc/loadavg; ps aux | grep nexacorp-api"` | 28 | Health-check, stealth |
| `bash -c "cat /etc/shadow | head -3; ls -la /root/.ssh"` | 27 | Sensitive data probe |
| `cat /etc/shadow` | 27 | Direct shadow dump |
| `find /home -name id_rsa` | 54 | SSH private key sweep |

The pattern is highly automated. The same six commands repeat at approximately 60-second intervals, consistent with a deployed beacon performing periodic information gathering. There is no evidence of interactive operator activity in the captured window.

**Root cause :**

Standard Debian 12 installations do NOT ship `find` with the SUID bit. This was either set manually by a system administrator (likely for an automation script) or by the attacker themselves. Either way, this is the primary vulnerability that enabled root compromise.

**ATT&CK :**
- T1548.001 (Abuse Elevation Control Mechanism : Setuid and Setgid)
- T1057 (Process Discovery)
- T1083 (File and Directory Discovery)

**Evidence commands :**

```bash
grep "/usr/bin/find" audit.log | grep 'key="suid_escalation"' | wc -l                       # 55
grep "type=PROCTITLE" audit.log | awk -F'proctitle=' '{print $2}' | sort | uniq -c | sort -rn  # 6 unique commands
```

---

### 5.4 Post-exploitation actions

#### 5.4.1 Sensitive data access (Task 4A)

**Confirmed.** The attacker read `/etc/shadow` 27 times via direct `cat`, plus 27 additional invocations wrapped in `bash -c` with `head -3` piping and redirection. The wrapping pattern is consistent with **password hash exfiltration** : the attacker likely captured the first three credential lines and offloaded them for offline cracking via the active SSH session.

**Implication :** every password hash on bru-app-01 is now in the attacker's hands. Assume crackable.

**ATT&CK :** T1003.008 (OS Credential Dumping : /etc/passwd and /etc/shadow)

---

#### 5.4.2 Backdoor user creation (Task 4B)

**Confirmed.** At 2026-05-16 19:47:07 local, the attacker created a new local user :

| Field | Value |
|---|---|
| Username | it_support |
| UID | 1002 |
| GID | 1002 |
| Home | /home/it_support |
| Shell | /bin/bash |
| Password | Set at 19:47:07.527 (50ms after useradd, via chpasswd) |

The naming choice (`it_support`) is deliberate social engineering : it sounds like a legitimate internal IT account, blending in during a quick administrative review. The metadata mentions "sudo rights" but no related entries are visible in the available logs. To validate during system inspection.

**ATT&CK :** T1136.001 (Create Account : Local Account)

**Evidence :**

```bash
grep -i "useradd\|new user\|chpasswd" auth.log
```

---

#### 5.4.3 SSH key harvesting (Task 4C)

**Confirmed.** The attacker systematically searched for SSH private keys across the entire system :
- `find /home -name id_rsa` : 54 events, sweeps every user home directory
- `ls -la /root/.ssh` : enumerated via bash wrapper (within the 27 bash-c invocations)

This is a classic lateral movement preparation step. Any private key found would give the attacker access to other NexaCorp systems trusting that key, with no further credential discovery needed.

**Operational implication :** any host whose `authorized_keys` file includes a key whose private counterpart was on bru-app-01 must be considered potentially compromised. A network-wide audit of trust relationships is required.

**ATT&CK :** T1552.004 (Unsecured Credentials : Private Keys)

---

#### 5.4.4 Persistence mechanism (Task 4D)

**Partial confirmation.** The metadata states the attacker installed `/etc/cron.d/svc-updater`, executing every 10 minutes (the metadata also says 30 minutes elsewhere, suggesting an internal inconsistency or a misreport).

Direct proof from Phase 1 evidence is incomplete :
- audit.log only covers 22:47:02 to 23:41:54 local
- The cron install most likely occurred during the 17:43 to 22:47 window when the attacker had root via the SUID find but audit.log had not started capturing yet
- auth.log and syslog do not record file writes
- cron.log shows only legitimate svc_api API health checks in the available window

This finding will be validated in Phase 2 by inspecting the running system and observing the persistence mechanism on the live target.

**ATT&CK :** T1053.003 (Scheduled Task/Job : Cron)

---

## 6. ATT&CK Mapping (Full)

| Stage | Technique | ID | Evidence summary |
|---|---|---|---|
| Reconnaissance | Active Scanning : Vulnerability Scanning | T1595.002 | 39 SSH failures from Tor |
| Initial Access | Valid Accounts : Local Accounts | T1078.003 | 40 successful publickey logins as svc_api |
| Initial Access | External Remote Services | T1133 | SSH exposed to Tor-based external access |
| Credential Access | Brute Force : Password Guessing | T1110.001 | Failed attempts in auth.log (diversion) |
| Credential Access | Unsecured Credentials : Private Keys | T1552.004 | Key likely harvested from INC-2026-001, plus 54 systematic id_rsa searches on bru-app-01 |
| Command and Control | Protocol Tunneling | T1572 | Tor-rotated beaconing on 3-min intervals |
| Privilege Escalation | Abuse Elevation Control Mechanism : Setuid | T1548.001 | 55 SUID find exploits, mode 0104755 on /usr/bin/find |
| Discovery | Process Discovery | T1057 | 112 ps aux events |
| Discovery | File and Directory Discovery | T1083 | find /home/svc_api with log search |
| Credential Access | OS Credential Dumping : /etc/shadow | T1003.008 | 27 cat /etc/shadow events |
| Persistence | Create Account : Local Account | T1136.001 | useradd it_support at 19:47:07 |
| Persistence | Scheduled Task/Job : Cron | T1053.003 | /etc/cron.d/svc-updater (per metadata) |

---

## 7. Indicators of Compromise (IOCs)

### 7.1 Source IPs (Tor exit nodes)

```
# Reconnaissance phase (39 failed SSH attempts):
162.247.74.1, 162.247.74.17, 162.247.74.19, 162.247.74.7
45.142.212.2, 45.142.212.50, 45.142.212.100, 45.142.212.123,
45.142.212.155, 45.142.212.195, 45.142.212.196, 45.142.212.216,
45.142.212.229, 45.142.212.249, 45.142.212.254, 45.142.212.65
89.248.167.14, 89.248.167.79, 89.248.167.97, 89.248.167.113,
89.248.167.152, 89.248.167.172, 89.248.167.200
185.220.101.32, 185.220.101.34, 185.220.101.42, 185.220.101.135, 185.220.101.138
193.32.162.37, 193.32.162.91, 193.32.162.137, 193.32.162.147,
193.32.162.189, 193.32.162.198, 193.32.162.210, 193.32.162.221

# Initial access and beacon (40 successful SSH publickey, all in 185.220.101.0/24):
185.220.101.34, 185.220.101.35, 185.220.101.37, 185.220.101.38,
185.220.101.39, 185.220.101.40, 185.220.101.41, 185.220.101.43,
185.220.101.46, 185.220.101.48, 185.220.101.49, 185.220.101.53,
185.220.101.55, 185.220.101.58, 185.220.101.59, 185.220.101.64,
185.220.101.65, 185.220.101.67, 185.220.101.68, 185.220.101.70,
185.220.101.73, 185.220.101.77, 185.220.101.79, 185.220.101.81,
185.220.101.82, 185.220.101.83
```

### 7.2 Compromised credentials

- SSH key fingerprint : `RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA`
- Compromised service account : `svc_api` (uid=1000)
- Hash dump : entire `/etc/shadow` of bru-app-01

### 7.3 Created accounts (backdoor)

- Username : `it_support`
- UID/GID : 1002/1002
- Home : `/home/it_support`
- Shell : `/bin/bash`
- Password : attacker-defined (unknown content)

### 7.4 File paths

| Path | Role |
|---|---|
| `/usr/bin/find` | SUID misconfigured binary, mode 0104755 |
| `/etc/shadow` | Dumped credential file |
| `/home/*/.ssh/id_rsa` | Target of systematic search |
| `/root/.ssh/` | Target of enumeration |
| `/etc/cron.d/svc-updater` | Persistence file (per metadata, Phase 2 validation needed) |
| `/home/it_support/` | Backdoor user home directory |

---

## 8. Remediation

### 8.1 Critical (do immediately)

| # | Action | Command (illustrative) |
|---|---|---|
| 1 | Rotate the compromised SSH key on every NexaCorp host where svc_api is provisioned | Audit `~/.ssh/authorized_keys` on all servers, re-issue keypair |
| 2 | Remove the backdoor user `it_support` | `userdel -r it_support` |
| 3 | Audit and remove other suspicious recent accounts | Check UIDs >= 1000 with recent /home creation dates |
| 4 | Remove the cron persistence | `rm /etc/cron.d/svc-updater`, then full audit of `/etc/cron.*` and per-user crontabs |
| 5 | Force password reset for every account on bru-app-01 | `chage -d 0 <user>` for all accounts (shadow was dumped) |
| 6 | Remove SUID bit on `/usr/bin/find` | `chmod u-s /usr/bin/find` |
| 7 | Audit all SUID binaries against a Debian 12 baseline | `find / -perm -4000 -type f 2>/dev/null` |

### 8.2 Short term (within 48 hours)

| # | Action |
|---|---|
| 8 | Block Tor exit nodes at the network perimeter for inbound SSH (refresh hourly from official Tor lists) |
| 9 | Inventory lateral exposure : every host whose authorized_keys could trust a private key from bru-app-01 must be considered potentially compromised |
| 10 | Re-deploy bru-app-01 from a known-clean baseline, restoring data from pre-incident verified backups |

### 8.3 Medium term (within 2 weeks)

| # | Action |
|---|---|
| 11 | Restrict svc_api SSH access to internal source IPs via `Match User` + `AllowUsers` directives |
| 12 | Ensure auditd runs from boot with reliable, tamper-resistant shipping to Wazuh |
| 13 | Implement a SUID baseline alert in Wazuh : any SUID bit change on system binaries fires a critical alert |
| 14 | Tune Wazuh detection rules to reduce false positives on root-owned daemon activity (see Phase 2 findings) |

---

## 9. Phase 2 : Live Detection in Wazuh

### 9.1 Phase 2 setup and execution

The Caldera adversary profile `lab2-linux-privesc` was triggered via `lab attack` against the target VM `tgt-blue11` on 2026-05-27 at approximately 17:02:30 local time. The operation ran for approximately 5.5 minutes (17:02:30 to 17:08:04) and generated 13 Wazuh alerts directly attributable to the attacker simulation. A total of 18 events were observed across the 30-minute monitoring window, including 5 false positives unrelated to the attack.

**Important characteristic of the Caldera execution :**

Caldera operates as a system service (deployed agent running as root via systemd) rather than as an SSH-authenticated intruder. All events captured during the live run share `auid=4294967295` (unset) and start with `uid=0, euid=0`. The simulation skips the initial access phase (SSH publickey from Tor) and the privilege escalation phase (SUID find exploitation) documented in Phase 1, focusing exclusively on post-root activity (credential dump, account creation, key harvest).

This is a known limitation of MITRE Caldera adversary emulation : it validates detection of post-exploitation TTPs but does not exercise the upstream kill chain. For complete attack chain detection validation, complementary tooling (e.g., Atomic Red Team, manual SSH replay) would be required.

### 9.2 Detection coverage per task

| Task | Wazuh detection | Evidence count | Verdict |
|---|---|---|---|
| 1 : Brute force recon | Not exercised by Caldera | 0 in run window | (out of scope for Phase 2) |
| 2 : SSH publickey access | Not exercised by Caldera | 0 | (out of scope for Phase 2) |
| 3 : SUID find escalation | Not exercised by Caldera | 0 | (out of scope for Phase 2) |
| 4A : /etc/shadow dump | Detected | 2 alerts (rule 100201) | Effective |
| 4B : useradd backdoor | Detected | 2 alerts (rule 100202) | Effective |
| 4C : SSH key harvest | Detected as side effect | 9 alerts (rule 100204) | Imprecise |
| 4D : Cron persistence | Not detected | 0 alerts | **Critical gap** |

**Task 4A and 4B detection :** rules 100201 and 100202 fire on real attack activity. The Caldera-generated alert for /etc/shadow access shows `command="head"`, `exe="/usr/bin/head"`, with proctitle `head -5 /etc/shadow`. The useradd alert shows `execve.a4="bk_nexacorp"` with `-m -s /bin/bash` arguments, clearly creating a real account (not a `-D` read-only invocation).

**Task 4C detection :** rule 100204 fires 9 times, but all events show `exe="/usr/bin/find"` with proctitle `find / -perm -4000 -type f`. This is SUID binary enumeration by the attacker, which happens to traverse `.ssh` directories during its filesystem walk. The rule fires as a side effect, not because the attacker is performing a targeted SSH key harvest (which would look like `find /home -name id_rsa` as observed in Phase 1). The detection is imprecise : it catches the activity but mischaracterizes it.

**Task 4D not detected :** the cron persistence file `/etc/cron.d/svc-updater` (mentioned in the metadata and confirmed by the running system after Caldera execution) does not trigger any dedicated Wazuh rule. The available rules monitor /etc/shadow access, useradd execution, and SSH key directory access, but no rule watches `/etc/cron.d/` file creation. This is the most significant detection gap exposed by the live Phase 2 run.

### 9.3 False positive analysis

Inspection of the events outside the Caldera run window confirmed five false positives generated by legitimate system daemons :

**Category 1 : Wazuh self-monitoring (rule 100201)**
- `command="wazuh-modulesd"`, `exe="/var/ossec/bin/wazuh-modulesd"`
- syscall 89 (readlink) on /etc/shadow, returns -22 (EINVAL, file is not a symlink)
- Fires during File Integrity Monitoring at agent startup
- 15 occurrences observed at agent start

**Category 2 : Wazuh inventory (rule 100202)**
- `command="useradd"`, `execve.a1="-D"` (read-only mode, displays default values)
- `ppid` traces to wazuh-modulesd
- The rule fires on the comm name regardless of arguments
- 1 occurrence observed at agent start

**Category 3 : Cron daemon user cache (rule 100201)**
- `command="cron"`, `exe="/usr/sbin/cron"`, proctitle `/usr/sbin/CRON -f`
- `ppid="447"` (systemd)
- Triggered every 10 minutes after cron daemon start, likely periodic user cache rebuild
- 3 occurrences during the monitoring window (16:50:04, 17:00:04, 17:10:04)

**Category 4 : systemd cleanup (rule 100204)**
- `command="systemd-tmpfile"`, `exe="/usr/bin/systemd-tmpfiles --clean"`
- Routine cleanup that traverses paths including some `.ssh` directories
- 1 occurrence observed

**Common characteristic :** all four categories share `auid=4294967295` (unset). However, this is also the characteristic of the legitimate Caldera-detected attack events (Tasks 4A and 4B). Filtering on `auid != unset` would suppress both daemon noise AND real detection signals from this simulation. This rules out auid as a discriminator for this lab's specific architecture.

### 9.4 Detection improvement proposals

Three orthogonal improvements address the gaps identified in Sections 9.2 and 9.3.

**Improvement 1 : Tune rule 100202 (useradd) on execve arguments**

The current rule fires on any `useradd` invocation, including the read-only `useradd -D` used by Wazuh's syscollector. The fix is to require that an actual username argument is present :

```xml
<rule id="100202" level="10" overwrite="yes">
    <if_sid>80700</if_sid>
    <field name="audit.command">^useradd$</field>
    <field name="audit.execve.a1" negate="yes">^-D$</field>
    <description>Lab2: useradd executed - backdoor account creation (T1136.001)</description>
    <mitre>
        <id>T1136.001</id>
    </mitre>
    <group>lab2,linux,privesc,</group>
</rule>
```

This preserves detection of `useradd -m -s /bin/bash bk_nexacorp` (Caldera and real attacker pattern) while suppressing the Wazuh inventory false positive.

**Improvement 2 : Tune rule 100201 (/etc/shadow access) on executable path**

The current rule fires on any process touching /etc/shadow, including Wazuh's FIM probe and the cron daemon's user cache rebuild. The fix is to exclude known legitimate system daemons by exe path :

```xml
<rule id="100201" level="12" overwrite="yes">
    <if_sid>80700</if_sid>
    <field name="audit.key">^shadow_access$</field>
    <field name="audit.exe" negate="yes">^/var/ossec/bin/</field>
    <field name="audit.exe" negate="yes">^/usr/sbin/cron$</field>
    <description>Lab2: /etc/shadow accessed - credential dump attempt (T1003.008)</description>
    <mitre>
        <id>T1003.008</id>
    </mitre>
    <group>lab2,linux,privesc,</group>
</rule>
```

This preserves detection of `cat`, `head`, `find`, or shell-based shadow access (Caldera and real attacker pattern) while suppressing the daemon noise.

**Improvement 3 : Add a new rule to detect cron persistence (Task 4D gap)**

No current rule detects file creation in `/etc/cron.d/`, leaving Task 4D as a complete blind spot. Adding an auditd rule to watch the directory, paired with a Wazuh rule to fire on it :

Auditd configuration (on the agent) :

```
-w /etc/cron.d/ -p wa -k cron_persistence
-w /etc/crontab -p wa -k cron_persistence
-w /var/spool/cron/ -p wa -k cron_persistence
```

Wazuh rule (on the manager) :

```xml
<rule id="100205" level="12">
    <if_sid>80700</if_sid>
    <field name="audit.key">^cron_persistence$</field>
    <field name="audit.exe" negate="yes">^/usr/bin/crontab$</field>
    <description>Lab2: Cron persistence file modified - scheduled task backdoor (T1053.003)</description>
    <mitre>
        <id>T1053.003</id>
    </mitre>
    <group>lab2,linux,persistence,</group>
</rule>
```

The negative match on `/usr/bin/crontab` allows legitimate users to edit their crontab via the standard tool without firing alerts, while any direct file write to `/etc/cron.d/` (the technique used by INC-2026-002) triggers a level 12 alert.

**Improvement 4 (recommended, not implemented in this lab) : Add SUID escalation detection**

The Phase 1 audit.log captured 55 events with `key="suid_escalation"` showing the classic `uid=1000 / euid=0` divergence, but no Wazuh rule fires on this pattern. Adding one would close the Task 3 detection gap :

```xml
<rule id="100203" level="12">
    <if_sid>80700</if_sid>
    <field name="audit.key">^suid_escalation$</field>
    <field name="audit.uid" negate="yes">^0$</field>
    <field name="audit.euid">^0$</field>
    <description>Lab2: SUID privilege escalation detected (uid=$(audit.uid), euid=0) (T1548.001)</description>
    <mitre>
        <id>T1548.001</id>
    </mitre>
    <group>lab2,linux,privesc,</group>
</rule>
```

The condition `uid != 0 AND euid == 0` is the exact signature of a non-root user obtaining root privileges through a SUID binary. This fires on any SUID escalation, regardless of the specific binary abused.

### 9.5 Phase 2 conclusion

The live Caldera run validated Wazuh detection for two of the four post-exploitation tasks (4A shadow dump, 4B useradd backdoor). One task (4C SSH key harvest) is detected only as a side effect of unrelated activity, and one task (4D cron persistence) is not detected at all.

The Phase 2 run also exposed that the original tuning proposal `auid != unset` (drafted from initial false positive observations) is unsuitable for this lab's architecture : Caldera runs with the same audit identity signature as the false positive daemons. The correct discriminator is the executable path and the specific arguments, not the audit UID.

Four improvement proposals (Sections 9.4) address these findings : two tuning improvements to suppress noise on existing rules, and two new rules to cover the cron persistence and SUID escalation detection gaps.

---

## 10. Conclusion

The investigation conclusively reconstructs the attack chain against bru-app-01 from initial access (17:43:43 via stolen SSH key) through privilege escalation (19:43:01 via SUID find) and post-exploitation actions (credential dump, backdoor user, SSH key harvest, cron persistence).

The incident is the direct continuation of INC-2026-001, with the SSH key being the most likely pivot artifact between the two compromises. NexaCorp must treat both incidents as a single campaign and audit every host where svc_api was provisioned.

Three persistence mechanisms remain potentially active until the remediation steps in Section 8 are completed :
1. The original SSH key (if not yet rotated)
2. The backdoor user `it_support` (with attacker-defined password)
3. The cron file `/etc/cron.d/svc-updater`

Until these are addressed, the attacker should be considered to have potential re-entry capability into NexaCorp infrastructure.

---

## Appendix A : Investigation Tooling

All findings in this report were derived from log analysis using standard Unix tools (`grep`, `awk`, `sort`, `uniq`, `xxd`). The Wazuh SIEM dashboard was used in parallel to validate findings against ingested alerts. No specialized commercial DFIR tooling was required.

The full set of investigation commands is reproducible from the evidence bundle and is documented inline within each finding subsection (Section 5).

---

## Appendix B : Coverage gaps and limitations

1. **audit.log coverage window :** the available `audit.log` only spans 22:47:02 to 23:41:54 local time on 2026-05-16. The attack reference timestamp (19:43:01) and the useradd it_support creation (19:47:07) fall outside this window. Both events were confirmed through alternate sources (auth.log for useradd) or the metadata file (privilege escalation moment).

2. **No file write tracing :** the available logs do not capture file write operations to `/etc/cron.d/svc-updater`. The persistence file is mentioned in the metadata but not directly visible in evidence. To validate in Phase 2.

3. **No sudo grant evidence :** the metadata mentions it_support having sudo rights, but no related entries appear in the available logs. To validate during system inspection.

4. **Timezone ambiguity in metadata :** the INCIDENT_METADATA.txt states "All timestamps are UTC", but cross-correlation with auth.log events (useradd at 19:47 visible in auth.log BEFORE the 22:47:02 audit.log start) confirms the attack reference timestamp 19:43:01 is in fact in local Brussels time (CEST, UTC+02:00), not UTC. All timestamps in this report are normalized to local time.

---

*End of report.*
