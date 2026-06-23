# MITRE ATT&CK Mapping: INC-2026-002

Mapping of the INC-2026-002 findings to MITRE ATT&CK Enterprise techniques (v15). NexaCorp is a fictitious BeCode lab scenario.

| Tactic | Technique ID | Technique Name | Observed evidence |
|---|---|---|---|
| Initial Access | T1078.003 | Valid Accounts: Local Accounts | svc_api SSH key reused for login |
| Initial Access | T1133 | External Remote Services | SSH access from external (Tor) sources |
| Command and Control | T1572 | Protocol Tunneling | access routed through the Tor network |
| Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | low-volume account probing below brute-force thresholds |
| Credential Access | T1110.001 | Brute Force: Password Guessing | username enumeration across accounts |
| Privilege Escalation | T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | SUID /usr/bin/find (mode 0104755) used for root |
| Discovery | T1057 | Process Discovery | ps aux enumeration via the SUID primitive |
| Discovery | T1083 | File and Directory Discovery | find sweeps of home directories and logs |
| Credential Access | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | /etc/shadow read as root |
| Credential Access | T1552.004 | Unsecured Credentials: Private Keys | systematic search for SSH private keys (find /home -name id_rsa) |
| Persistence | T1136.001 | Create Account: Local Account | backdoor account it_support |
| Persistence | T1053.003 | Scheduled Task/Job: Cron | /etc/cron.d/svc-updater running /tmp/.svc_updater every 10 minutes |

Framework version : MITRE ATT&CK Enterprise v15.
