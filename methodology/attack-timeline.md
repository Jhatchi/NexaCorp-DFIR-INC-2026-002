# Attack Timeline: INC-2026-002

Chronology of the privilege-escalation and persistence incident on `bru-app-01`. Host log timestamps are local (CEST, UTC+02:00). NexaCorp is a fictitious BeCode lab scenario. The evidence bundle is pre-filtered to svc_api activity.

| Time (CEST) | Event | Source |
|---|---|---|
| 16 May 17:43:43 | Initial access : SSH publickey authentication as svc_api from 185.220.101.68 (Tor) | auth.log |
| 16 May 17:43:43 - 19:42:37 | 40 successful svc_api publickey logins at ~3-minute intervals from rotating Tor exit nodes (automated foothold) | auth.log |
| 16 May 19:43:01 | Privilege escalation to root via the SUID /usr/bin/find primitive (attack reference timestamp) | metadata |
| 16 May 19:47:07 | Backdoor account it_support created (useradd, then chpasswd) | auth.log |
| 16 May 19:47 (approx) | Cron persistence installed : /etc/cron.d/svc-updater running /tmp/.svc_updater every 10 minutes | metadata, cron.log |
| 16 May 22:47:02 - 23:41:54 | SUID find exploitation window captured in audit.log : 55 find executions (key=suid_escalation), including SSH key sweeps (find /home -name id_rsa) and /etc/shadow reads | audit.log |
| 16 May 23:41:54 | End of audit.log coverage | audit.log |

The audit.log coverage (22:47-23:41) starts later than the 19:43:01 escalation reference and the 19:47:07 backdoor creation, due to a logging gap; those earlier events are confirmed through auth.log and the incident metadata. The intrusion is the continuation of INC-2026-001 : the svc_api SSH key was harvested there and reused here.
