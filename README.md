# NexaCorp DFIR Engagement (INC-2026-002) - Privilege Escalation and Persistence

Forensic investigation of a coordinated Linux post-exploitation campaign against `bru-app-01` (NexaCorp's Brussels internal application server), with Wazuh detection coverage analysis and rule tuning proposals validated by live MITRE Caldera adversary emulation. Conducted as a solo engagement during the BeCode Brussels Blue & Red Team bootcamp (Mission 02), as a direct continuation of [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001).

[![ci](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002/actions/workflows/ci.yml/badge.svg)](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002/actions/workflows/ci.yml)
[![Methodology](https://img.shields.io/badge/methodology-NIST%20SP%20800--61r2-blue.svg)](#methodology)
[![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Detection](https://img.shields.io/badge/Wazuh-4%20rules%20delivered-green.svg)](detection/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Johan--Emmanuel%20Hatchi-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/johan-emmanuel-hatchi/)

## ⚠ Operational notice

**This is a lab engagement against fictitious infrastructure.** NexaCorp is a fictional client used as the scenario for BeCode Brussels Mission 02. The compromised host `bru-app-01` is an isolated Debian 12 VM provisioned for the exercise, and the MITRE Caldera adversary emulation operated against it is part of the lab methodology, not a real intrusion. No real organization, network, or human was attacked.

All IP addresses, hostnames, account names, and indicators of compromise published in this report (`10.10.10.42`, `192.168.100.199`, `bru-app-01`, `tgt-blue11`, `svc_api`, `it_support`, Tor exit-node ranges quoted as IOCs, etc.) are **lab-local artifacts**, not real-world threat intelligence. Do not feed them to a production SIEM as IOCs. The Tor exit nodes referenced are public infrastructure used in the storytelling and not associated with any real campaign.

**Publication authorized** by BeCode lab coach (Thomas B.) on 2026-05-17. The full Confidentiality Statement appears in the findings report.

## At a glance

| Engagement metadata | Value |
|---|---|
| Reference | `BCC-2026 / INC-2026-002` |
| Phases | Phase 1 (offline forensics) + Phase 2 (live Caldera emulation in Wazuh) |
| Delivered | 2026-05-27 |
| Status | Complete (Phase 1 + Phase 2) |

| Investigation output | Value |
|---|---|
| Findings | **7** (2 CRITICAL, 3 HIGH, 1 MEDIUM, 1 LOW) |
| MITRE ATT&CK techniques mapped | 12 |
| Log sources analyzed | auth.log, audit.log, syslog, cron.log + INCIDENT_METADATA |
| Wazuh detection coverage | 2 of 4 post-exploitation tasks reliably detected, 1 imprecise, 1 blind |
| Detection engineering deliverables | **4 rules** (2 tunings deployed, 1 new rule deployed, 1 proposed) |
| Adversary emulation | MITRE Caldera 5.x, `lab2-linux-privesc` profile, 5.5 min run, 13 attack alerts captured |

## Engagement context

**Scenario (fictional).** During the week following [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001) (compromise of NexaCorp's Liège services server), the Wazuh SIEM generated new alerts on a different machine: `bru-app-01`, the Brussels internal application server. The evidence suggested the threat actor from the prior incident pivoted to bru-app-01 during the night of 16-17 May 2026 and escalated to root.

**Mandate.** Reconstruct the full attack chain from the evidence bundle, characterize what was accessed and what persists, and answer four executive-level questions: how did the attacker get in, what did they do, how far did they get, and what must NexaCorp do right now. A second phase added live detection engineering: run MITRE Caldera against the actual target, observe what the existing Wazuh ruleset catches in real time, then propose tuning and new rules to close the gaps.

**Evidence package received from the client.**

| Artefact | Coverage | Note |
|---|---|---|
| `auth.log` | Full incident window | SSH authentication, PAM, useradd |
| `audit.log` | 22:47:02 to 23:41:54 (partial) | Captures post-escalation activity. Onset of escalation (19:43:01) and useradd (19:47:07) fall outside this window |
| `syslog` | Full incident window | General system events |
| `cron.log` | Full incident window | Only legitimate svc_api API health checks visible |
| `INCIDENT_METADATA.txt` | n/a | Initial NexaCorp summary, anchor timestamp for analysis |

**Educational context.** Delivered during the **BeCode Brussels Blue & Red Team bootcamp (November 2025 to September 2026)** as Mission 02: a solo, time-boxed DFIR + detection engineering engagement. The methodology, tools, and report format follow real-world standards (NIST SP 800-61r2, SANS PICERL, MITRE ATT&CK, MITRE Caldera).

## Executive summary

> 📄 **The full 39-page findings report is the canonical deliverable.**
> [Download the PDF](reports/INC-2026-002_Findings_Report.pdf) (159 KB) or [browse the Markdown source](reports/INC-2026-002_Findings_Report.md) for grep/citation.

On **2026-05-16 at 17:43:43 local Brussels time**, a threat actor authenticated to bru-app-01 as the service account `svc_api` using a valid SSH private key the actor should not have possessed. The key was almost certainly harvested during the prior week's compromise of the Liège services server ([INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001)) where the same actor had shell access. The initial login originated from `185.220.101.68`, a Tor exit node, and was followed by 40 successive publickey logins over approximately two hours, all from IPs in the `185.220.101.0/24` range, with a consistent 3-minute interval consistent with an automated beacon rather than interactive activity.

In parallel with the beacon channel, the actor generated 39 deliberately low-volume SSH authentication failures from 36 distinct Tor exit IPs targeting 8 NexaCorp-aligned usernames (`svc_api`, `api`, `nexacorp`, `deploy`, `backup`, `admin`, `root`, `ubuntu`). The pattern is below typical fail2ban thresholds and runs concurrently with the successful publickey logins: this is reconnaissance noise as diversion, not the actual access vector.

At **19:43:01 local**, the actor escalated to root by abusing a SUID misconfiguration on `/usr/bin/find` (mode `0104755`, not standard on Debian 12). The audit log captured 55 events with `key="suid_escalation"` showing the classic `uid=1000 / euid=0` divergence. The escalation was used to chain six distinct commands in a roughly 60-second cadence: process enumeration, log search, sensitive-data probe, direct `/etc/shadow` read (27 occurrences), and systematic SSH key sweep across `/home` and `/root/.ssh` (54 invocations of `find /home -name id_rsa`).

At **19:47:07 local**, the actor created a backdoor user `it_support` (UID 1002) with an attacker-defined password set 50 ms after the useradd. The metadata also reports a cron persistence file at `/etc/cron.d/svc-updater`, validated indirectly during Phase 2 by the running system.

The full three-incident kill chain (INC-2026-001 + INC-2026-002 + INC-2026-003) is consolidated in the Month 1 Assessment Report delivered on 2026-05-29: see [INC-2026-003](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003).

**Phase 2 (live Caldera run).** The `lab2-linux-privesc` adversary profile was triggered against `tgt-blue11` for 5.5 minutes on 2026-05-27. Of the four post-exploitation tasks the actor performed in Phase 1, the existing Wazuh ruleset detected only two reliably (`/etc/shadow` access via rule 100201, useradd via rule 100202), detected one imprecisely as a side effect (SSH key harvest, caught by SUID enumeration rule 100204 firing on collateral filesystem traversal), and missed the cron persistence entirely. A four-improvement detection package addresses all gaps: see [Detection engineering](#detection-engineering) below.

**Headline IOCs (lab-bound, do not feed to a real SIEM):**

| Type | Value | Context |
|---|---|---|
| Source IP (initial access) | `185.220.101.68` | Tor exit, first successful publickey login |
| Source range (beacon) | `185.220.101.0/24` | All 40 successful logins |
| Source ranges (recon diversion) | `162.247.74.0/24`, `45.142.212.0/24`, `89.248.167.0/24`, `193.32.162.0/24` | 39 failed SSH attempts |
| Compromised account | `svc_api` (uid 1000) | Service account, key-authenticated |
| Backdoor account | `it_support` (uid/gid 1002), `/bin/bash` | Created via useradd at 19:47:07 |
| Persistence | `/etc/cron.d/svc-updater` | Cron file, per metadata + system inspection |
| Privesc vector | `/usr/bin/find` mode `0104755` | SUID misconfiguration |
| SSH key fingerprint | `RSA SHA256:3Qx7kY9pLmNvWz2Hj8bFcA` | Single fingerprint across all 40 logins |

## Kill chain summary

The attacker chained valid-credential access into root and durable persistence on `bru-app-01`:

1. **Reconnaissance diversion**: 39 low-volume SSH failures from 36 Tor exit IPs against 8 usernames, below fail2ban thresholds, run as noise (Finding I1).
2. **Initial access**: authentication as the service account `svc_api` using a stolen SSH private key over Tor, almost certainly harvested during INC-2026-001 (Finding I2).
3. **Privilege escalation**: root obtained via a SUID misconfiguration on `/usr/bin/find` (Finding I3).
4. **Credential dump**: 27 reads of `/etc/shadow` (Finding I4).
5. **SSH key harvest**: systematic sweep across `/home` and `/root/.ssh` (Finding I6).
6. **Backdoor account**: creation of `it_support` (uid 1002) with an attacker-defined password (Finding I5).
7. **Persistence**: a cron file at `/etc/cron.d/svc-updater` (Finding I7).

## How to read this report

The repository is organized so that you can dive in at the right depth for your role:

| If you are a... | Start here | Time |
|---|---|---|
| **Recruiter or hiring manager** | This README + skim the [PDF](reports/INC-2026-002_Findings_Report.pdf) executive summary | 5 min |
| **SOC analyst evaluating fit** | [PDF sections 5 (Findings) and 9 (Phase 2 live detection)](reports/INC-2026-002_Findings_Report.pdf) + [`detection/`](detection/) | 25 min |
| **DFIR practitioner** | Full [PDF](reports/INC-2026-002_Findings_Report.pdf) + [`notes/journal.md`](notes/journal.md) for the investigation trail | 60 min |
| **Detection engineer** | [`detection/workflow.md`](detection/workflow.md) for rationale + the four XML rules + [`detection/auditd-config.conf`](detection/auditd-config.conf) | 30 min |
| **Anyone who wants to grep, cite, or diff** | [Markdown source of the report](reports/INC-2026-002_Findings_Report.md) | as needed |

**Canonical deliverable:** the PDF in `reports/`. The Markdown source is the same content, kept in the repo for searchability and version control.

**Investigation trail:** `notes/journal.md` is the analyst's working notebook covering scope, methodology, hypotheses, findings log, IOC inventory, and timeline reconstruction. It complements the formal report by showing **how** the conclusions were reached.

**Detection ruleset:** `detection/` contains four Wazuh XML rule files (two tunings, one new deployed, one proposed) plus the auditd watch configuration needed for the cron persistence rule. `detection/workflow.md` documents the rationale for each rule, the mapping to Phase 1 findings, and the deployed-vs-proposed status.

## Findings summary

The 7 findings (`I1` to `I7`) are documented in detail in the [findings report](reports/INC-2026-002_Findings_Report.md). Each entry includes evidence, reproducibility commands, MITRE ATT&CK mapping, and remediation guidance.

| ID | Severity | Title | Primary MITRE technique | Report section |
|---|---|---|---|---|
| **I1** | 🟢 LOW | Reconnaissance over Tor (39 failed logins, 8 enumerated usernames) as diversion | T1595.002, T1110.001 | 5.1 |
| **I2** | 🟠 HIGH | Initial access as `svc_api` via stolen SSH private key over Tor | T1078.003, T1133, T1552.004 | 5.2 |
| **I3** | 🔴 CRITICAL | Privilege escalation to root via SUID misconfiguration on `/usr/bin/find` | T1548.001 | 5.3 |
| **I4** | 🔴 CRITICAL | Credential dump: 27 reads of `/etc/shadow` | T1003.008 | 5.4.1 |
| **I5** | 🟠 HIGH | Backdoor user creation: `it_support` (uid 1002) with attacker-defined password | T1136.001 | 5.4.2 |
| **I6** | 🟡 MEDIUM | Systematic SSH key harvest across `/home` and `/root/.ssh` (54 invocations) | T1552.004 | 5.4.3 |
| **I7** | 🟠 HIGH | Cron persistence at `/etc/cron.d/svc-updater` (partial Phase 1 proof, Phase 2 validated) | T1053.003 | 5.4.4 |

**Severity distribution:** 2 CRITICAL / 3 HIGH / 1 MEDIUM / 1 LOW

**Section mapping note.** The findings report uses the numbering `5.1`, `5.2`, `5.3`, `5.4.1` to `5.4.4` internally. The `I1` to `I7` labels in this README map one-to-one to those sections (column "Report section" above) for cross-reference with [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001).

**Reading order recommendation:** start with I2 (the access vector and link to INC-2026-001), then I3 (the escalation that made everything else possible), then I4 to I7 (what root access enabled). I1 gives the diversion context.

## Detection engineering

Phase 2 ran MITRE Caldera's `lab2-linux-privesc` adversary profile against the target VM `tgt-blue11` to observe how the existing Wazuh ruleset performed against a live post-exploitation campaign. The 5.5-minute run generated 13 attack-attributable Wazuh alerts and exposed three classes of detection deficiency: rules firing on benign daemon activity (false positives), one task detected only as a side effect of an unrelated rule (imprecise detection), and one task generating no alert at all (blind spot).

The deliverable is **4 Wazuh XML rules** addressing these findings, with explicit deployment status:

| Rule | Type | Status | Closes | Finding |
|---|---|---|---|---|
| [`100201`](detection/100201-shadow-access-tuned.xml) | Tuning | **Deployed** | False positives from Wazuh FIM and cron daemon on `/etc/shadow` | I4 |
| [`100202`](detection/100202-useradd-tuned.xml) | Tuning | **Deployed** | False positive from Wazuh syscollector `useradd -D` | I5 |
| [`100205`](detection/100205-cron-persistence-new.xml) | New rule | **Deployed** | Blind spot on `/etc/cron.d/` file creation | I7 |
| [`100203`](detection/100203-suid-escalation-proposed.xml) | New rule | **Proposed (not deployed in this lab run)** | Phase 1 Task 3 gap: 55 SUID escalation events captured but no Wazuh rule fired | I3 |

**Why one rule is "proposed" and not deployed.** The Caldera adversary profile starts at root (it operates as a systemd service, not as an SSH-authenticated intruder) and therefore skips the SUID escalation phase entirely. The `100203` rule design closes a real Phase 1 detection gap, but it could not be validated against live attack telemetry within this lab's architecture. Promoting it from proposed to deployed would require Atomic Red Team or a manual SSH replay to exercise the privesc step. Distinguishing deployed-and-validated rules from designed-but-untested ones matters for a recruiter reading this work as honest output.

**Auditd companion configuration.** Rule `100205` only fires if the agent's auditd is configured to watch the cron directories. The required watches are in [`detection/auditd-config.conf`](detection/auditd-config.conf) and documented in [`detection/workflow.md`](detection/workflow.md).

**Phase 2 false positive analysis.** The Caldera run exposed four categories of benign noise: Wazuh self-monitoring (FIM probes on `/etc/shadow`), Wazuh inventory (`useradd -D` for default-value lookups), cron daemon user-cache rebuilds, and systemd cleanup traversing SSH directories. All four share `auid=4294967295` (unset), but so does Caldera itself (no SSH login behind it), which rules out `auid` as a tuning discriminator. The fix is per-executable path exclusion and argument-pattern matching, as implemented in the two tuning rules above.

## Methodology

The engagement follows three industry-standard frameworks layered together.

### NIST SP 800-61r2: Computer Security Incident Handling Guide

NIST's 4-phase model (Preparation, Detection & Analysis, Containment / Eradication / Recovery, Post-Incident Activity) provides the high-level structure. In this engagement, **Phase 1 of the deliverable maps to NIST "Detection & Analysis"** (offline log forensics, attacker timeline reconstruction). **Phase 2 maps to NIST "Lessons Learned"** translated into preventive controls (the four Wazuh rules and the prioritized recommendation list in report section 8).

### SANS PICERL: tactical investigation flow

PICERL (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned) is the SANS Incident Response Process. Applied in this engagement:

| PICERL phase | This engagement |
|---|---|
| **Preparation** | Coach-validated lab environment, defined scope (forensic + detection eng), evidence bundle handed off by the engagement coordinator |
| **Identification** | auth.log + audit.log + cron.log correlation, hypothesis-driven reconstruction (initial access vector, escalation mechanism, persistence inventory) |
| **Containment / Eradication / Recovery** | Documented as P0 recommendations in report section 8 (key rotation, backdoor user removal, cron file removal, SUID baseline audit) but not executed: the engagement scope is forensic analysis and detection engineering, not active response |
| **Lessons Learned** | Phase 2 detection engineering: four Wazuh rules with false positive analysis (report section 9) |

### MITRE ATT&CK: technique mapping

Every finding is mapped to one or more MITRE ATT&CK techniques to allow the client to correlate this incident with their existing threat model. **12 distinct techniques** are referenced across the 7 findings:

- **Reconnaissance :** T1595.002
- **Initial Access :** T1078.003, T1133
- **Credential Access :** T1110.001, T1552.004, T1003.008
- **Command and Control :** T1572
- **Privilege Escalation :** T1548.001
- **Discovery :** T1057, T1083
- **Persistence :** T1136.001, T1053.003

The complete technique table per finding is in **report section 6** and the per-finding deep dives in section 5.

### Reproducibility

Every claim in the report is traceable to a log line in the evidence bundle, with the exact `grep` or `awk` filter needed to reproduce it. The investigation commands are documented inline within each finding subsection in the report. See **Appendix A (Investigation Tooling)** in the [PDF](reports/INC-2026-002_Findings_Report.pdf) and the **[Reproducibility](#reproducibility) section below** for a quick-start.

## Tools used

**Offline log forensics (Phase 1)**

- Standard Unix toolchain: `grep`, `awk`, `sort`, `uniq`, `xxd` for log mining, pattern extraction, and binary inspection
- `auditctl` reference documentation for decoding audit syscall records and rule keys
- No specialized commercial DFIR tooling required: the entire Phase 1 investigation is reproducible from the evidence bundle with the commands documented inline in the report

**SIEM and host telemetry (Phase 1 + Phase 2)**

- [Wazuh](https://wazuh.com/) (manager + dashboard, version 4.x): alert review via Threat Hunting / Discover, field-level filtering on `data.audit.exe`, `data.audit.key`, `data.audit.auid`, `data.audit.execve.a*`, rule lookup and ruleset edits
- Linux audit daemon (`auditd`): syscall recording on the target, key-tagged rules for `shadow_access`, `useradd`, `suid_escalation`, `ssh_keys`, and the proposed `cron_persistence` watch documented in [`detection/auditd-config.conf`](detection/auditd-config.conf)

**Adversary emulation (Phase 2)**

- [MITRE Caldera 5.x](https://caldera.mitre.org/): `lab2-linux-privesc` adversary profile, deployed Sandcat agent as systemd service, 5.5 min run against `tgt-blue11`
- `lab attack` lab harness: triggers the Caldera operation against the learner's assigned target

**Reference frameworks**

- [NIST SP 800-61r2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final): Computer Security Incident Handling Guide
- [SANS PICERL](https://www.sans.org/blog/incident-handlers-handbook/): tactical investigation flow
- [MITRE ATT&CK Enterprise v15](https://attack.mitre.org/): technique attribution
- [MITRE Caldera documentation](https://caldera.readthedocs.io/): adversary emulation framework reference

## Repository layout

```text
NexaCorp-DFIR-INC-2026-002/
├── README.md                                            (this file)
├── LICENSE                                              (MIT)
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml                                      markdownlint + typography + XML validation
├── reports/
│   ├── INC-2026-002_Findings_Report.pdf                  canonical 39-page deliverable
│   └── INC-2026-002_Findings_Report.md                  same content, Markdown source
├── detection/
│   ├── workflow.md                                      rationale, deployment status, mapping to findings
│   ├── 100201-shadow-access-tuned.xml                   Wazuh tuning (deployed)
│   ├── 100202-useradd-tuned.xml                         Wazuh tuning (deployed)
│   ├── 100203-suid-escalation-proposed.xml              Wazuh new rule (proposed)
│   ├── 100205-cron-persistence-new.xml                  Wazuh new rule (deployed)
│   └── auditd-config.conf                               auditd watches required by 100205
└── notes/
    └── journal.md                                       analyst investigation notebook
```

**File classifications :**

| Path | Role | Audience |
|---|---|---|
| `reports/*.pdf` | Canonical deliverable, formal report | Client, recruiter, auditor |
| `reports/*.md` | Same content, grep-friendly source | Anyone citing or diffing |
| `detection/*.xml` | Wazuh-ready ruleset (XML format) | SOC / detection engineer |
| `detection/auditd-config.conf` | Auditd watches required by rule `100205` | SOC / detection engineer |
| `detection/workflow.md` | Per-rule rationale and deployment status | Detection engineer onboarding |
| `notes/journal.md` | Investigation working notebook | DFIR practitioner studying the method |
| `.github/workflows/ci.yml` | Automated markdownlint, typography, and XML validation (`xmllint`, runs when `detection/*.xml` is present) on push | CI |

## Reproducibility

Every claim in the findings report is traceable to a log line in the evidence bundle. The bundle itself is not redistributed (BeCode lab property), but the commands and queries are documented so that anyone with their own copy can reproduce the analysis.

### Reproduce key findings (log analysis)

Requires the evidence bundle (`auth.log`, `audit.log`, `cron.log`, `syslog`, `INCIDENT_METADATA.txt`):

```bash
# I1: Reconnaissance volume and time window
grep "Failed password" auth.log | wc -l                                  # expect 39
grep "Failed password" auth.log | head -1                                # first attempt
grep "Failed password" auth.log | tail -1                                # last attempt
grep "Failed password" auth.log | grep -oE "from [0-9.]+" | sort -u      # 36 distinct IPs
grep "Failed password" auth.log | grep -oE "invalid user [^ ]+" | sort -u  # 8 enumerated usernames

# I2: Initial access via SSH publickey
grep "Accepted publickey" auth.log | wc -l                                            # expect 40
grep "Accepted publickey" auth.log | head -1                                          # initial access timestamp
grep "Accepted publickey" auth.log | grep -oE "SHA256:[A-Za-z0-9+/=]+" | sort -u      # single key fingerprint

# I3: Privilege escalation via SUID find
grep "/usr/bin/find" audit.log | grep 'key="suid_escalation"' | wc -l   # expect 55
grep "type=PROCTITLE" audit.log | awk -F'proctitle=' '{print $2}' \
  | sort | uniq -c | sort -rn                                            # 6 unique commands

# I4 / I6: Shadow dump and SSH key harvest
grep '/etc/shadow' audit.log | wc -l                                     # shadow reads
grep 'find /home -name id_rsa' audit.log | wc -l                         # 54 key sweeps

# I5: Backdoor user creation
grep -i "useradd\|new user\|chpasswd" auth.log
```

### Reproduce Phase 2 live detection (Wazuh + Caldera)

Requires a Wazuh manager (4.x), an agent on the target VM with auditd enabled, and a Caldera 5.x instance with the `lab2-linux-privesc` adversary profile deployed. The exact lab harness command used in this engagement is documented in [`detection/workflow.md`](detection/workflow.md).

Validating the four delivered Wazuh rules :

```bash
# 1. Validate XML syntax (same check the CI runs)
xmllint --noout detection/*.xml

# 2. Drop the rules into the Wazuh manager's custom rule directory
sudo cp detection/100201-shadow-access-tuned.xml /var/ossec/etc/rules/
sudo cp detection/100202-useradd-tuned.xml /var/ossec/etc/rules/
sudo cp detection/100205-cron-persistence-new.xml /var/ossec/etc/rules/
# (100203 is proposed-only, do not deploy without validation)

# 3. Drop the auditd watches on every agent (cron persistence rule prerequisite)
sudo cp detection/auditd-config.conf /etc/audit/rules.d/cron-persistence.rules
sudo augenrules --load

# 4. Restart Wazuh manager to load the new ruleset
sudo systemctl restart wazuh-manager

# 5. Confirm parse / sanity
sudo /var/ossec/bin/wazuh-logtest
```

## Known limits

- **audit.log coverage window.** The available `audit.log` only spans 22:47:02 to 23:41:54 local on 2026-05-16. The attack reference timestamp (19:43:01) and the useradd it_support creation (19:47:07) fall outside this window. Both events were confirmed through alternate sources (auth.log for useradd) and the metadata file (escalation moment), but the direct audit-syscall record for these specific events is absent.
- **No file-write tracing in Phase 1 evidence.** auth.log and syslog do not capture file write operations. The cron persistence file `/etc/cron.d/svc-updater` is asserted by metadata and confirmed by Phase 2 live inspection, but is not directly visible in Phase 1 logs.
- **Sudo grant on it_support not log-corroborated.** The metadata states the backdoor account has sudo rights, but no related entries appear in the available logs. Documented as a Phase 2 system-inspection item.
- **Caldera emulation does not exercise the upstream kill chain.** Caldera starts as a root systemd service, skipping the SSH publickey initial access and SUID find escalation phases. Phase 2 detection validation is therefore scoped to post-exploitation tasks only (4A through 4D). The SUID escalation rule (`100203`) remains a proposed rule, not deployed-and-validated. Complete detection-validation coverage would require Atomic Red Team or a manual SSH replay to exercise Tasks 1 to 3.
- **Caldera and benign daemons share `auid=4294967295`.** The unset audit-login UID is not a viable discriminator for tuning, because the legitimate Caldera detections share this signature with the false-positive daemons (Wazuh modulesd, cron, systemd-tmpfile). Tuning is per-executable path and argument pattern instead.
- **Timezone normalization.** The INCIDENT_METADATA.txt asserts UTC, but cross-correlation with auth.log timestamps confirms the metadata is in fact in local Brussels time (CEST, UTC+02:00). All timestamps in this report are normalized to local time.
- **Scope was forensic + detection engineering, not live response.** Containment, eradication, forensic acquisition (memory image, disk image), and trust-relationship audit across NexaCorp infrastructure are documented as **P0 recommendations** in the report, but were not executed: the engagement did not have multi-host access. A follow-up engagement would be required to close those loops.

## NexaCorp DFIR series

- [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001): Linux infrastructure compromise (vsftpd backdoor, Caldera C2)
- **INC-2026-002**: this repository
- [INC-2026-003](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003): month-1 cross-incident assessment
- [INC-2026-004](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-004): SQL injection (web portal)
- [INC-2026-005](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005): OS command injection and web shell (web portal)
- [INC-2026-006](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-006): stored XSS and session hijacking (web portal)

## Acknowledgments

- **Thomas B.** (BeCode lab coach): scenario design, evidence bundle preparation, publication authorization for portfolio use (2026-05-17).
- **MITRE** for the Caldera framework that powered Phase 2 adversary emulation, and for the ATT&CK knowledge base used to map every finding.
- **Wazuh project** for the open-source SIEM that ingested the audit telemetry and ran the deployed ruleset.

## About

Solo DFIR + detection engineering engagement delivered during the [BeCode Brussels](https://becode.org) Blue & Red Team bootcamp (November 2025 to September 2026), Mission 02, on 2026-05-27.

Author: **Johan-Emmanuel Hatchi**, French national based in Brussels, cybersecurity student at BeCode Brussels (Nov 2025 to Sep 2026), active internship search for September 2026.

[GitHub](https://github.com/Jhatchi) - [LinkedIn](https://www.linkedin.com/in/johan-emmanuel-hatchi/)

Open to cybersecurity internship opportunities starting September 2026 in Belgium. Looking for SOC L1/L2, DFIR junior, or detection engineering roles where this kind of end-to-end work (offline forensics, SIEM tuning, adversary emulation, formal client reporting) is in scope.

## License

[MIT](LICENSE), 2026 Johan-Emmanuel Hatchi.

The Wazuh rules in `detection/*.xml`, the auditd configuration, and the report text are all released under the same MIT license: free to copy, adapt, and redeploy with attribution. The evidence bundle, lab infrastructure, and engagement briefings remain BeCode Brussels property and are not redistributed.
