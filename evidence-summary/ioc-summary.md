# Indicators of Compromise: INC-2026-002

Indicators observed during the investigation of the privilege-escalation and persistence incident on the Brussels application server (`bru-app-01`, 16 May 2026). NexaCorp is a fictitious BeCode lab scenario on isolated infrastructure; these indicators are not real-world threat intelligence. The evidence bundle is pre-filtered to `svc_api` activity. The `Source` column records where each indicator was observed.

## Network indicators

| Type | Value | Source |
|---|---|---|
| Initial-access source | 185.220.101.68 (Tor exit) | auth.log |
| Tor exit blocks observed | 185.220.101.0/24, 45.142.212.0/24, 89.248.167.0/24, 193.32.162.0/24 (36 distinct IPs) | auth.log |
| Access protocol | SSH publickey, TCP/22 | auth.log |

## Host and application indicators

| Type | Value | Source |
|---|---|---|
| Target host | bru-app-01 (NexaCorp Brussels application server, Debian 12) | metadata, auth.log |
| Privilege-escalation primitive | SUID bit on /usr/bin/find (mode 0104755) | audit.log |
| Escalation signature | audit records with uid=1000 (svc_api), euid=0 (root), key=suid_escalation | audit.log |
| SSH key harvest target | /home/*/.ssh/id_rsa | audit.log |
| Sensitive file accessed | /etc/shadow (read as root via the SUID primitive) | audit.log |

## Behavioral indicators

| Type | Value | Source |
|---|---|---|
| Automated foothold callbacks | 40 successful svc_api publickey logins at ~3-minute intervals, rotating Tor IPs | auth.log |
| Beacon-style command set | repeating commands at ~60-second intervals via the SUID find primitive (ps aux 112, find -newer log 56, find id_rsa 54, cat /etc/shadow and wrappers 27 each, bash loadavg 28) | audit.log |
| SUID find executions | 55 find executions tagged key=suid_escalation | audit.log |

## Account indicators

| Type | Value | Source |
|---|---|---|
| Compromised service account | svc_api (uid=1000), key reused from the prior incident | auth.log |
| Backdoor account created | it_support (uid=1002), created 19:47:07 (useradd + chpasswd) | auth.log |

## Persistence indicators

| Type | Value | Source |
|---|---|---|
| Cron persistence file | /etc/cron.d/svc-updater | metadata |
| Cron payload | /tmp/.svc_updater (executed by root every 10 minutes) | cron.log |

> No credentials are stored in clear text in this repository. The evidence bundle is BeCode lab property and is not redistributed.
