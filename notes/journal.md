# Investigation Journal: INC-2026-002
## Phase 1 + Phase 2 Complete

---

**Analyst :** Johan-Emmanuel Hatchi (BeCode SOC trainee, lab workstation tgt-blue11 / agent id 041)
**Organization :** BeCode Corp
**Client :** NexaCorp (fictional)
**Engagement :** INC-2026-002
**Related incident :** INC-2026-001 (Liège services server, same threat actor, prior week)
**Investigation date :** 2026-05-27
**Phase 1 + Phase 2 completion :** 2026-05-27
**Report version :** v2 (audit-corrected from v1 of 2026-05-27 18:00)
**Classification :** Internal - Not for distribution

---

## 1. Lab Context

### 1.1 Target system under investigation

| Field | Value |
|---|---|
| Hostname | `bru-app-01` (NexaCorp Brussels internal application server) |
| Operating system | Debian 12 (Linux) |
| Internal IP | `10.10.10.42` |
| Management IP | `192.168.100.199` |
| Wazuh agent | `tgt-blue11`, agent id `041` |
| Service account | `svc_api` (uid 1000), runs the internal REST API |

### 1.2 Incident anchor timestamp

- Privilege escalation moment (per `INCIDENT_METADATA.txt`): 2026-05-16 19:43:01 local Brussels time (CEST, UTC+02:00)
- Timezone caveat: the metadata file asserts UTC, but cross-correlation with `auth.log` proves the metadata timestamps are in fact local Brussels time. All timestamps in this journal and the final report are normalized to local time.

### 1.3 Lab infrastructure (Phase 2)

| Component | Value |
|---|---|
| Wazuh manager + dashboard | accessible during the engagement, version 4.x |
| Caldera control plane | version 5.x, adversary profile `lab2-linux-privesc` |
| Lab harness | `lab attack` command initiates the Caldera operation against the learner's assigned target |

---

## 2. Incident Framing

### 2.1 Client narrative

A NexaCorp SOC alert escalation followed the resolution of INC-2026-001 (Liège services server compromise of the prior week). New Wazuh alerts appeared on a different host, `bru-app-01`, suggesting the threat actor was never fully evicted and pivoted to a separate machine during the night of 16-17 May 2026. The engagement coordinator handed off the evidence bundle and framed four executive questions :

1. How did the attacker get in?
2. What did they do?
3. How far did they get?
4. What must NexaCorp do right now?

### 2.2 Reported window

- Attack reference timestamp (escalation): 2026-05-16 19:43:01 local
- Reconnaissance phase observed in `auth.log`: 2026-05-16 17:45:14 to 19:41:06 local
- Initial access observed in `auth.log`: 2026-05-16 17:43:43 local (predates the failed-attempt window, which is the key signal that the failures are a diversion)
- Last visible attacker activity in `audit.log`: 2026-05-16 23:41:54 local (end of audit.log coverage)

---

## 3. Evidence Inventory

### 3.1 Files received

| File | Purpose |
|---|---|
| `auth.log` | SSH authentication events, PAM, useradd. Full incident window. |
| `audit.log` | Linux audit daemon syscall trail. Partial coverage: 22:47:02 to 23:41:54 local on 2026-05-16. |
| `syslog` | General system events. Full incident window. |
| `cron.log` | Scheduled task execution. Only legitimate `svc_api` API health checks visible. |
| `INCIDENT_METADATA.txt` | Initial NexaCorp summary, anchor timestamp. |

### 3.2 Evidence package limitations

1. `audit.log` only covers 22:47:02 to 23:41:54 local time on 2026-05-16. The attack reference timestamp (19:43:01) and the `useradd it_support` event (19:47:07) fall outside the audit window. Both events were validated through alternate sources: `auth.log` for the useradd, metadata file for the escalation moment.
2. No log captures file write operations. The persistence file `/etc/cron.d/svc-updater` (per metadata) is not directly visible in Phase 1 evidence. Validated indirectly in Phase 2 by live system inspection after the Caldera run.
3. The metadata file mentions `it_support` having sudo rights, but no related entries appear in the available logs. Documented as a Phase 2 system-inspection item.

---

## 4. Investigation Plan - Status

| Step | Description | Status |
|---|---|---|
| A | Read `INCIDENT_METADATA.txt`, anchor on attack timestamp | Done |
| B | `auth.log` triage: enumerate failed and successful auth events | Done |
| C | Identify initial access vector (SSH publickey vs password vs brute force) | Done |
| D | Audit log analysis: privilege escalation mechanism | Done |
| E | Post-exploitation action mapping (4A through 4D) | Done |
| F | IOC consolidation (IPs, accounts, file paths, key fingerprints) | Done |
| G | Cross-correlation with INC-2026-001 (key origin, threat actor link) | Done |
| H | Phase 1 report writing | Done |
| I | Phase 2 setup: Wazuh dashboard + Caldera operation | Done |
| J | Live attack run: `lab attack` + 30-min dashboard observation | Done |
| K | False positive analysis | Done |
| L | Detection improvement design (4 rules) | Done |
| M | Phase 2 report integration | Done |
| N | Audit-pass corrections (v2) | Done |

---

## 5. Working Hypotheses - Status

| # | Hypothesis | Status |
|---|---|---|
| H1 | The attacker brute-forced their way in | Refuted - the 39 failed attempts are below fail2ban thresholds and run *in parallel* with successful publickey logins, which is the signature of a diversion |
| H2 | The attacker used a valid SSH key they should not have possessed | Confirmed - 40 successful publickey logins as `svc_api` with a single key fingerprint `RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA` |
| H3 | The SSH key was harvested during INC-2026-001 | Strongly supported - the prior compromise gave shell access on the Liège server where `svc_api` was provisioned. Direct proof of the harvest event itself is in INC-2026-001 evidence, not in INC-2026-002 |
| H4 | Privilege escalation used a SUID-misconfigured binary | Confirmed - `/usr/bin/find` mode `0104755`, 55 events tagged `key="suid_escalation"` with `uid=1000 / euid=0` signature |
| H5 | Root activity was automated (beacon), not interactive | Supported - six commands repeat at ~60-second intervals, no operator-typed activity visible in the audit window |
| H6 | A persistence mechanism survives the audit window | Confirmed - `/etc/cron.d/svc-updater` per metadata + confirmed by Phase 2 system inspection |
| H7 | The backdoor user `it_support` has working sudo | N/A - hypothesis not log-corroborated. Metadata asserts sudo rights but no `sudoers` or `sudo` audit entries are present in the available logs. Recommended for Phase 2 host inspection. |

---

## 6. Findings Log

### I1 - Reconnaissance over Tor as diversion (severity LOW)

- **Window :** 2026-05-16 17:45:14 to 19:41:06 local, duration approximately 1h56
- **Volume :** 39 SSH authentication failures, 100% on non-existent accounts
- **Sources :** 36 distinct IPs across 5 known Tor exit-node /24 blocks (`162.247.74.0/24`, `45.142.212.0/24`, `89.248.167.0/24`, `185.220.101.0/24`, `193.32.162.0/24`)
- **Targets :** 8 usernames aligned with NexaCorp internal naming conventions (`svc_api`, `api`, `nexacorp`, `deploy`, `backup`, `admin`, `root`, `ubuntu`)
- **Distribution :** maximum 2 attempts per IP, approximately one attempt every 3 minutes
- **Key signal :** runs in parallel with successful publickey logins (I2), which proves the failures are not the access vector but a diversion
- **MITRE :** T1595.002 (Active Scanning), T1110.001 (Password Guessing, failed attempts only)
- **Confidence :** High

### I2 - Initial access via stolen SSH private key (severity HIGH)

- **Initial access timestamp :** 2026-05-16 17:43:43 local
- **Method :** SSH public key authentication as `svc_api` (uid 1000)
- **Key fingerprint :** `RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA` (single fingerprint across all 40 successful logins)
- **Source IP (first login) :** `185.220.101.68` (Tor exit, Foundation for Applied Privacy)
- **Beacon pattern :** 40 successful publickey logins between 17:43:43 and 19:42:37, interval approximately 3 minutes, all sources in `185.220.101.0/24`
- **Key origin :** strongly attributable to INC-2026-001 (Liège services server compromise of the prior week) where the same threat actor had shell access on a host where `svc_api` was provisioned
- **MITRE :** T1078.003 (Valid Accounts: Local Accounts), T1133 (External Remote Services), T1552.004 (Unsecured Credentials: Private Keys), T1572 (Protocol Tunneling, Tor C2)
- **Confidence :** High

### I3 - Privilege escalation via SUID misconfiguration on `/usr/bin/find` (severity CRITICAL)

- **Mechanism :** SUID bit set on `/usr/bin/find` (mode `0104755`, not standard on Debian 12)
- **Evidence count :** 55 audit events tagged `key="suid_escalation"`
- **Identity signature :** every event shows `uid=1000` (svc_api) and `euid=0` (root)
- **Time window :** 22:47:02 to 23:41:54 local in `audit.log` (note: audit coverage starts later than the 19:43:01 escalation moment due to a logging gap, but the 55 captured events confirm the technique conclusively)
- **Six chained commands observed :** `ps aux --no-headers` (112 occurrences), `find /home/svc_api -name *.log -newer /etc/hostname` (56), `bash -c "cat /proc/loadavg; ps aux | grep nexacorp-api"` (28), `bash -c "cat /etc/shadow | head -3; ls -la /root/.ssh"` (27), `cat /etc/shadow` (27), `find /home -name id_rsa` (54)
- **Pattern :** highly automated, ~60-second cadence, consistent with a deployed beacon
- **Root cause :** standard Debian 12 installations do NOT ship `find` with the SUID bit. Either an administrator set it manually for an automation script, or the attacker set it themselves after gaining initial access (subsequently used for self-escalation across reconnects)
- **MITRE :** T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid), T1057 (Process Discovery), T1083 (File and Directory Discovery)
- **Confidence :** High

### I4 - Credential dump: /etc/shadow read (severity CRITICAL)

- **Evidence :** 27 direct `cat /etc/shadow` invocations + 27 additional `bash -c` wrappers with `head -3` piping and redirection
- **Implication :** every password hash on bru-app-01 is in the attacker's hands. The `head -3` pattern is consistent with offline password cracking offload via the active SSH session.
- **MITRE :** T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow)
- **Confidence :** High

### I5 - Backdoor user `it_support` created (severity HIGH)

- **Timestamp :** 2026-05-16 19:47:07.478 local (useradd), 19:47:07.527 local (chpasswd)
- **Account :** `it_support`, uid 1002, gid 1002, home `/home/it_support`, shell `/bin/bash`
- **Password :** attacker-defined (content unknown, 50 ms gap between useradd and chpasswd is consistent with scripted creation)
- **Social engineering note :** the username `it_support` is deliberately chosen to blend in during a quick administrative review of the account list
- **Sudo rights :** asserted by metadata but not log-corroborated (Phase 2 system inspection item)
- **MITRE :** T1136.001 (Create Account: Local Account)
- **Confidence :** High

### I6 - Systematic SSH key harvest (severity MEDIUM)

- **Evidence :** 54 invocations of `find /home -name id_rsa`, plus enumeration of `/root/.ssh` via the bash wrapper
- **Operational implication :** any host whose `authorized_keys` includes a key whose private counterpart resided on `bru-app-01` must be considered potentially compromised. A network-wide trust-relationship audit is required.
- **MITRE :** T1552.004 (Unsecured Credentials: Private Keys)
- **Confidence :** High

### I7 - Cron persistence at `/etc/cron.d/svc-updater` (severity HIGH)

- **Evidence in Phase 1 :** partial. The file is asserted by `INCIDENT_METADATA.txt`. `audit.log` does not capture the install event (coverage gap). `auth.log` and `syslog` do not record file writes. `cron.log` shows only legitimate `svc_api` API health checks in the available window.
- **Evidence in Phase 2 :** validated by live system inspection of `tgt-blue11` after the Caldera run.
- **Execution interval :** metadata states "every 10 minutes" in one place and "every 30 minutes" elsewhere, suggesting an internal metadata inconsistency or misreport. Operationally, any interval is concerning.
- **MITRE :** T1053.003 (Scheduled Task/Job: Cron)
- **Confidence :** Medium for Phase 1 (metadata + indirect support), High for Phase 2 (direct system observation)

---

## 7. IOCs

### 7.1 Source IPs (Tor exit nodes, all lab-bound storytelling)

Reconnaissance phase (39 failed SSH attempts, sample of 36 distinct IPs) :
`162.247.74.1/.7/.17/.19`, `45.142.212.*` (16 IPs), `89.248.167.*` (7 IPs), `185.220.101.32/.34/.42/.135/.138`, `193.32.162.*` (8 IPs).

Initial access and beacon (40 successful SSH publickey logins, all in `185.220.101.0/24`) :
26 distinct IPs in the range `185.220.101.34` through `185.220.101.83`.

Full IP list in the [findings report](../reports/INC-2026-002_Findings_Report.md) section 7.1.

### 7.2 Compromised credentials

| Type | Value |
|---|---|
| SSH key fingerprint | `RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA` |
| Compromised service account | `svc_api` (uid 1000) |
| Hash dump | entire `/etc/shadow` of bru-app-01 |

### 7.3 Created accounts (backdoor)

| Field | Value |
|---|---|
| Username | `it_support` |
| UID/GID | 1002/1002 |
| Home | `/home/it_support` |
| Shell | `/bin/bash` |
| Password | attacker-defined (unknown content) |

### 7.4 File paths

| Path | Role |
|---|---|
| `/usr/bin/find` | SUID misconfigured binary, mode `0104755` |
| `/etc/shadow` | Dumped credential file |
| `/home/*/.ssh/id_rsa` | Target of systematic search |
| `/root/.ssh/` | Target of enumeration |
| `/etc/cron.d/svc-updater` | Persistence file (metadata + Phase 2 validation) |
| `/home/it_support/` | Backdoor user home directory |

---

## 8. Timeline (consolidated, local Brussels time CEST)

| # | Timestamp | Source | Event |
|---|---|---|---|
| 01 | 2026-05-16 17:43:43 | auth.log | Initial access: SSH publickey auth as `svc_api` from `185.220.101.68` (Tor exit) |
| 02 | 2026-05-16 17:45:14 | auth.log | Brute-force diversion starts (first failed SSH attempt) |
| 03 | 2026-05-16 17:43:43 to 19:42:37 | auth.log | 40 successful SSH publickey logins as `svc_api`, ~3-minute intervals, rotating Tor IPs |
| 04 | 2026-05-16 19:41:06 | auth.log | Brute-force diversion ends (last failed SSH attempt) |
| 05 | 2026-05-16 19:42:37 | auth.log | Last beacon login before privilege escalation |
| 06 | **2026-05-16 19:43:01** | INCIDENT_METADATA | **Privilege escalation moment (attack reference timestamp)** |
| 07 | 2026-05-16 19:47:07.478 | auth.log | Backdoor user creation: `useradd it_support` |
| 08 | 2026-05-16 19:47:07.527 | auth.log | Password set on `it_support` via `chpasswd` (50 ms after useradd) |
| 09 | (likely 19:43 to 22:47 window) | inferred | Cron persistence file `/etc/cron.d/svc-updater` written (audit coverage gap) |
| 10 | 2026-05-16 22:47:02 to 23:41:54 | audit.log | 55 SUID find exploit events (`uid=1000`, `euid=0`) |
| 11 | 2026-05-16 22:47:02 to 23:41:54 | audit.log | 27 reads of `/etc/shadow` |
| 12 | 2026-05-16 22:47:02 to 23:41:54 | audit.log | 54 systematic searches for SSH private keys (`find /home -name id_rsa`) |
| 13 | 2026-05-16 23:41:54 | audit.log | End of audit.log coverage |
| 14 | 2026-05-27 17:02:30 | Phase 2 | Caldera `lab2-linux-privesc` triggered against `tgt-blue11` |
| 15 | 2026-05-27 17:08:04 | Phase 2 | Caldera operation ends (5.5 min run, 13 attack-attributable alerts) |
| 16 | 2026-05-27 | Phase 2 | Live system inspection of `tgt-blue11` confirms `/etc/cron.d/svc-updater` exists |

---

## 9. Detection Gap Analysis (Phase 2 findings)

### 9.1 What Wazuh detected during the Caldera run

| Task | Detection | Evidence count | Verdict |
|---|---|---|---|
| 1: Brute force recon | Not exercised by Caldera | 0 | Out of scope for Phase 2 |
| 2: SSH publickey access | Not exercised by Caldera | 0 | Out of scope for Phase 2 |
| 3: SUID find escalation | Not exercised by Caldera | 0 | Out of scope for Phase 2 |
| 4A: /etc/shadow dump | Detected | 2 alerts (rule 100201) | Effective |
| 4B: useradd backdoor | Detected | 2 alerts (rule 100202) | Effective |
| 4C: SSH key harvest | Detected as side effect | 9 alerts (rule 100204) | Imprecise |
| 4D: Cron persistence | Not detected | 0 alerts | **Critical gap** |

### 9.2 What Wazuh missed or detected imprecisely

- Task 4D (cron persistence): complete blind spot. No pre-existing rule monitored `/etc/cron.d/`. Closed by deployed rule `100205` plus `auditd-config.conf`.
- Task 4C (SSH key harvest): rule 100204 fires 9 times but all events show `exe="/usr/bin/find"` with proctitle `find / -perm -4000 -type f`. This is SUID enumeration that happens to traverse `.ssh` directories during its filesystem walk, not targeted SSH key harvest. Imprecise detection (catches the activity but mischaracterizes it). Follow-up: tune 100204 and add a focused rule on `find /home -name id_rsa` or `find . -name authorized_keys`.
- Task 3 (SUID escalation): not exercised by Caldera but well-attested in Phase 1 evidence. Rule `100203` designed to close the gap, shipped as **proposed** (not validated against live attack telemetry) because Caldera does not exercise the SUID escalation phase.

### 9.3 False positive analysis

The 30-minute Phase 2 monitoring window exposed five benign events :

1. Wazuh self-monitoring on `/etc/shadow` via FIM probe (15 events, addressed by tuned 100201)
2. Wazuh inventory `useradd -D` (1 event, addressed by tuned 100202)
3. Cron daemon user-cache rebuild on `/etc/shadow` access (3 events at 16:50, 17:00, 17:10, addressed by tuned 100201)
4. systemd-tmpfile cleanup traversing `.ssh` (1 event, fires rule 100204 as a side effect, not addressed by the four delivered rules but documented for follow-up)

All four categories share `auid=4294967295` (unset). Caldera attack events also share this signature. `auid` is therefore not a viable tuning discriminator for this lab's architecture. Tuning is per-executable path and argument pattern.

### 9.4 Detection improvement proposals (Phase 2 deliverable)

Four rules in `detection/` :

1. `100201-shadow-access-tuned.xml` (deployed): closes I4
2. `100202-useradd-tuned.xml` (deployed): closes I5
3. `100205-cron-persistence-new.xml` (deployed): closes I7
4. `100203-suid-escalation-proposed.xml` (proposed): closes I3 once promoted

See `detection/README.md` for per-rule rationale, deployment commands, and validation guidance.

---

## 10. Open Questions / Followups

- Recover the full file write history for the `19:43 to 22:47` window where the cron persistence was installed but no audit coverage exists. Filesystem-level forensics (timeline analysis via `mac-robber` or `fls`) on a snapshot of `bru-app-01` would close this gap.
- Verify whether `it_support` actually has sudo rights. The metadata asserts this but no `sudoers` or `sudo` audit entries appear in the available logs. Live `id it_support` plus inspection of `/etc/sudoers` and `/etc/sudoers.d/` would resolve.
- Trust-relationship audit: enumerate every NexaCorp host where the SSH key fingerprint `RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA` is present in `authorized_keys`. Treat any such host as potentially compromised until proven otherwise.
- Promote rule `100203` from proposed to deployed by running Atomic Red Team `T1548.001` or a manual SSH replay exercising the SUID escalation step, then validate the rule fires.
- Tune rule `100204` to suppress the SUID enumeration side-effect and add a focused SSH-key-harvest rule.

---

## 11. Operational Notes (BeCode internal)

- Coach **Thomas B.** (BeCode lab coach) confirmed portfolio publication authorization for INC-2026-002 on 2026-05-17, same authorization as for INC-2026-001.
- The PDF report v1 was generated on 2026-05-27 at 18:00 local. An audit pass at 19:07 the same day identified four micro-bugs (two section references, one carryover term from INC-2026-001, one timezone typo). PDF v2 corrects all four without regression and is the canonical deliverable in `reports/`.
- The markdown source `INC-2026-002_Findings_Report.md` in this repository corresponds to the same content as PDF v2.
- Lab harness command: `lab attack` initiates the Caldera operation against the learner's assigned target. Operation duration ~5.5 minutes. Wazuh alerts start appearing within 60 seconds of trigger.

---

## 12. References

- BeCode Brussels Blue & Red Team bootcamp Mission 02 briefings (BeCode IP, not redistributed in this repository)
- [NIST SP 800-61r2: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Handler's Handbook (PICERL)](https://www.sans.org/blog/incident-handlers-handbook/)
- [MITRE ATT&CK Enterprise v15](https://attack.mitre.org/)
- [MITRE Caldera documentation](https://caldera.readthedocs.io/)
- [Wazuh custom rules documentation](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
- INC-2026-001 (prior week's compromise, same threat actor): https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001

---

*End of Phase 1 + Phase 2 journal.*
