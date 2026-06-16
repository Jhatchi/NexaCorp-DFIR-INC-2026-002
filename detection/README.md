# Detection Engineering Workflow (INC-2026-002)

This directory contains the four Wazuh detection rules produced by Phase 2 of the engagement, the auditd watch configuration required by one of those rules, and this document explaining the rationale, deployment status, and mapping to Phase 1 findings.

## Scope

Phase 2 of INC-2026-002 ran the MITRE Caldera `lab2-linux-privesc` adversary profile against the target VM `tgt-blue11` (agent id 041) for 5.5 minutes on 2026-05-27. The run generated 13 attack-attributable Wazuh alerts and a separate set of 5 benign events across the 30-minute monitoring window. The objective was to characterize what the existing Wazuh ruleset catches against a live post-exploitation campaign, and to deliver tuning and new rules closing the gaps.

The result is **four rules**, listed below in deployment order. See the inline XML comments inside each rule file for the per-rule rationale that is also restated here for the reader who arrives at this directory first.

## Files in this directory

| File | Status | Closes finding | MITRE technique |
|---|---|---|---|
| `100201-shadow-access-tuned.xml` | Deployed (validated against Caldera) | I4 (5.4.1, Task 4A) | T1003.008 |
| `100202-useradd-tuned.xml` | Deployed (validated against Caldera) | I5 (5.4.2, Task 4B) | T1136.001 |
| `100205-cron-persistence-new.xml` | Deployed (validated against system inspection) | I7 (5.4.4, Task 4D) | T1053.003 |
| `100203-suid-escalation-proposed.xml` | **Proposed (not deployed in this lab run)** | I3 (5.3, Task 3) | T1548.001 |
| `auditd-config.conf` | Prerequisite for rule 100205 | n/a | n/a |

## Per-rule documentation

### Rule 100201 (shadow access, tuned)

**What it does.** Fires a level 12 alert when an audit event tagged `key="shadow_access"` is observed, provided the calling executable is not Wazuh modulesd or the cron daemon.

**Why it exists.** The pre-tuning version of `100201` fired on any process touching `/etc/shadow`, which produced two recurring benign signals: Wazuh's File Integrity Monitoring probe at agent startup (`exe="/var/ossec/bin/wazuh-modulesd"`, syscall 89 readlink, returns -22 EINVAL because `/etc/shadow` is not a symlink) and the cron daemon's periodic user-cache rebuild (`exe="/usr/sbin/cron"`, fires every 10 minutes). These two patterns alone generated dozens of noise alerts during the 30-minute Phase 2 monitoring window, which would drown a real `/etc/shadow` access in routine inventory chatter in a production SOC.

**Impact.** The tuned rule suppresses both noise classes by negating the executable paths, while preserving detection of the real attack pattern observed during Caldera: `command="head"`, `exe="/usr/bin/head"`, proctitle `head -5 /etc/shadow`, with `auid=4294967295` and `uid=0, euid=0`. Phase 1 finding I4 (5.4.1) documented 27 direct `cat /etc/shadow` invocations during the real attack, plus 27 additional invocations wrapped in `bash -c` with `head -3` piping; all of these continue to match the tuned rule because their `exe` is outside the negated set.

**Mapping to Phase 1 finding I4 :** the real attacker performed a credential dump that this rule would have caught had the tuning been in place at the time. The lack of pre-tuning is exactly the SOC posture deficiency that this engagement is meant to address.

### Rule 100202 (useradd, tuned)

**What it does.** Fires a level 10 alert when `useradd` is executed with a real username argument (any first execve argument other than `-D`).

**Why it exists.** Wazuh's syscollector module periodically runs `useradd -D` to inventory the system's default user-creation parameters. This is a read-only operation that displays the configured defaults without creating any account, but the pre-tuning rule fired on the bare comm name `useradd` regardless of arguments, generating a noise alert at every agent startup.

**Impact.** The tuned rule requires that the first execve argument (`a1`) is not the literal string `-D`. The Caldera-generated useradd alert observed during Phase 2 (`execve.a4="bk_nexacorp"`, full command line `useradd -m -s /bin/bash bk_nexacorp`) carries a real username and continues to match. The actual Phase 1 attack (`useradd` followed 50 milliseconds later by `chpasswd` on the new account `it_support`) follows the same pattern and also continues to match.

**Mapping to Phase 1 finding I5 :** the it_support backdoor creation visible in auth.log at 19:47:07 on 2026-05-16 is exactly the event class this rule is designed to detect. The negative match on `-D` is a precision improvement, not a coverage reduction.

### Rule 100205 (cron persistence, new)

**What it does.** Fires a level 12 alert when an audit event tagged `key="cron_persistence"` is observed, provided the calling executable is not the standard `/usr/bin/crontab` utility.

**Why it exists.** Phase 1 finding I7 (5.4.4, Task 4D) identified `/etc/cron.d/svc-updater` as the persistence mechanism installed by the attacker after gaining root. The pre-existing Wazuh ruleset had no rule monitoring `/etc/cron.d/` or any of the other standard cron directories, which made this entire Task 4D class a complete blind spot. The Phase 2 Caldera run confirmed the gap: the simulation also installs a cron file and no Wazuh alert fired on it.

**Impact.** This new rule, paired with the auditd watches in `auditd-config.conf`, raises a level 12 alert on any file write to `/etc/cron.d/`, `/etc/crontab`, or `/var/spool/cron/` performed by anything other than the standard `crontab` utility. Legitimate user crontab edits via `crontab -e` bypass the alert. Any direct file write to `/etc/cron.d/` (the technique used by both the real attacker and the Caldera emulation) triggers the alert.

**Prerequisite.** Rule 100205 only fires if the agent's auditd is loading the watches from `auditd-config.conf`. The deployment workflow below covers this step.

**Mapping to Phase 1 finding I7 :** this rule closes the most significant single detection gap exposed by the engagement.

### Rule 100203 (SUID escalation, proposed)

**Status.** Proposed, not deployed in the BCC-2026 lab run.

**What it would do.** Fire a level 12 alert when an audit event tagged `key="suid_escalation"` is observed with `uid != 0` and `euid == 0`, the exact signature of a non-root user obtaining root privileges through a SUID binary regardless of the specific binary abused.

**Why it is proposed and not deployed.** MITRE Caldera operates as a systemd service starting at root (`uid=0`, `euid=0`, `auid=4294967295` unset). The `lab2-linux-privesc` adversary profile therefore skips the upstream SSH publickey access phase and the SUID `find` escalation phase, jumping directly into post-root activity. No `key="suid_escalation"` events occur during the Phase 2 run, and the proposed rule cannot be validated against live attack telemetry within this lab's architecture. Phase 1 audit.log (offline) did capture 55 such events from the real attack, all matching the `uid=1000 / euid=0` signature, which provides the design evidence base for the rule but not live deployment validation.

**Promotion path.** Atomic Red Team techniques `T1548.001` and `T1548.001a` perform actual SUID exploitation under a non-root user, which would generate audit events matching the proposed rule. A manual SSH replay (log in as a low-privilege user, then invoke a SUID-misconfigured binary) achieves the same. Either method would let the rule move from proposed to deployed-and-validated.

**Why ship it as proposed rather than omit.** The Phase 1 detection gap is real: 55 audit events tagged for SUID escalation existed in the evidence and no Wazuh rule fired. Shipping the rule as a proposed artifact lets a recruiter or SOC engineer evaluate the design even though the lab architecture prevented live validation. Treating the design honestly (proposed, not deployed) is more useful than either omitting the rule or claiming validation that did not happen.

**Mapping to Phase 1 finding I3 :** this rule closes the Task 3 detection gap once promoted to deployed.

## False positive analysis (Phase 2)

The 30-minute Phase 2 monitoring window exposed five benign events generated by legitimate system daemons. All five are documented per category :

1. **Wazuh self-monitoring on `/etc/shadow`** (rule 100201, pre-tuning). `wazuh-modulesd` performs a syscall 89 (readlink) on `/etc/shadow`, returns -22 (EINVAL, file is not a symlink). Observed 15 times at agent startup. Addressed by the tuned `100201`.
2. **Wazuh inventory `useradd -D`** (rule 100202, pre-tuning). The syscollector module reads default user-creation parameters via `useradd -D`. Observed 1 time at agent startup. Addressed by the tuned `100202`.
3. **Cron daemon user-cache rebuild** (rule 100201, pre-tuning). The cron service rebuilds its internal user cache every 10 minutes. Observed 3 times during the monitoring window (16:50:04, 17:00:04, 17:10:04). Addressed by the tuned `100201`.
4. **systemd-tmpfile traversal** (rule 100204). `/usr/bin/systemd-tmpfiles --clean` performs a routine filesystem cleanup that walks through paths including some `.ssh` directories, which fires rule 100204 (the pre-existing SSH-keys monitoring rule). Observed 1 time. Not addressed by the four delivered rules in this engagement because rule 100204 also fires on the actual SSH key harvest as a side effect (see "Imprecise detection" below). Tuning 100204 is a follow-up item.

**Common characteristic of all four false-positive categories :** they share `auid=4294967295` (unset, no SSH login behind them). However, the same audit-login signature applies to the legitimate Caldera-detected attack events (Tasks 4A and 4B), because Caldera itself runs as a systemd service with no audit login. Filtering on `auid != unset` would suppress both daemon noise and real detection signals from this lab's architecture, which rules out `auid` as a tuning discriminator. The correct discriminator is the executable path and the specific arguments, which is what `100201` and `100202` use.

## Imprecise detection note (rule 100204)

The pre-existing rule `100204` (SSH key directory monitoring) fired 9 times during Phase 2, all on the attacker's SUID enumeration sweep `find / -perm -4000 -type f`. The rule fires because this `find` invocation traverses `.ssh` directories during its filesystem walk, not because the attacker is targeting SSH keys. The detection is imprecise: it catches the activity but mischaracterizes it. A focused rule on `find /home -name id_rsa` or `find . -name authorized_keys` would be more precise. Tuning `100204` and adding a precise SSH-key-harvest rule are documented as follow-up items in the report's Phase 2 conclusion (section 9.5).

## Deployment workflow

These are the exact commands to deploy the three deployed rules and the auditd prerequisite onto a Wazuh manager and its agents. The proposed rule `100203` is intentionally excluded from this workflow.

### On every agent

```bash
# Drop the auditd watches required by rule 100205
sudo cp auditd-config.conf /etc/audit/rules.d/cron-persistence.rules
sudo augenrules --load
sudo auditctl -l | grep cron_persistence    # verify the watches are active
```

### On the Wazuh manager

```bash
# Drop the deployed rules into the manager's custom rule directory
sudo cp 100201-shadow-access-tuned.xml   /var/ossec/etc/rules/
sudo cp 100202-useradd-tuned.xml         /var/ossec/etc/rules/
sudo cp 100205-cron-persistence-new.xml  /var/ossec/etc/rules/

# Validate the rule XML before restart (the CI workflow runs the same check)
xmllint --noout /var/ossec/etc/rules/100201-shadow-access-tuned.xml
xmllint --noout /var/ossec/etc/rules/100202-useradd-tuned.xml
xmllint --noout /var/ossec/etc/rules/100205-cron-persistence-new.xml

# Apply
sudo systemctl restart wazuh-manager

# Smoke-test the parse and detection logic
sudo /var/ossec/bin/wazuh-logtest
```

### Post-deployment validation

Two manual validations are appropriate after deployment :

1. **Trigger `useradd testuser`** on a non-production host. Confirm rule 100202 fires a level 10 alert. Then trigger `useradd -D` and confirm no alert fires.
2. **Drop a test file in `/etc/cron.d/`** (e.g. `echo "* * * * * root /bin/true" | sudo tee /etc/cron.d/test`). Confirm rule 100205 fires a level 12 alert. Remove the file.

For end-to-end attack-chain validation, the `lab attack` harness (Caldera-driven) can be re-run against a target after deployment and the alerts compared against the Phase 2 baseline documented in report section 9.2.

## Mapping summary (findings to rules)

| Phase 1 finding | Section | Severity | Detection delivered |
|---|---|---|---|
| I1 Reconnaissance over Tor | 5.1 | LOW | Out of scope for Phase 2 (Caldera does not exercise upstream recon) |
| I2 Initial access via SSH publickey | 5.2 | HIGH | Out of scope for Phase 2 (Caldera does not exercise SSH access) |
| I3 SUID find privilege escalation | 5.3 | CRITICAL | Rule 100203 proposed (not deployed in this lab, see rationale above) |
| I4 /etc/shadow credential dump | 5.4.1 | CRITICAL | Rule 100201 deployed (tuned) |
| I5 it_support backdoor user | 5.4.2 | HIGH | Rule 100202 deployed (tuned) |
| I6 SSH key harvest | 5.4.3 | MEDIUM | Detected imprecisely by 100204 (follow-up: tune 100204 + add precise key-harvest rule) |
| I7 Cron persistence | 5.4.4 | HIGH | Rule 100205 deployed (new), auditd-config.conf prerequisite |

## References

- Wazuh custom rules documentation: https://documentation.wazuh.com/current/user-manual/ruleset/custom.html
- Wazuh rule syntax reference: https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-syntax.html
- Linux audit daemon (`auditd`) rule syntax: `auditctl(8)` manual page
- MITRE ATT&CK Enterprise techniques referenced :
  - [T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008/)
  - [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)
  - [T1053.003 Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
  - [T1548.001 Abuse Elevation Control Mechanism: Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/)
