# Security Analyst Portfolio

Hands-on cybersecurity labs and analysis writeups, built while working L1 IT support (Microsoft/Entra/M365 environment) and pursuing a SOC analyst career path through Empirical Training's SOC+ apprenticeship.

Each project includes a full writeup, MITRE ATT&CK mapping where applicable, and supporting evidence (screenshots, packet captures, logs).

## Projects

| Project | Focus | Techniques |
|---|---|---|
| [Remote Shell Detection](./01-remote-shell-detection/) | Network forensics — Wireshark analysis of a Telnet-based reverse shell | T1595, T1046, T1071.001, T1083, T1210 |
| [EDR Alert Simulation](./02-edr-alert-simulation/) | Endpoint detection — Microsoft Defender for Business EDR validation via EICAR and PowerShell behavioral simulation | T1204.001, T1059.001, T1053.002, T1106, T1057 |
| [Phishing Header Analysis](./03-phishing-header-analysis/) | Email security — header-level analysis of a brand-impersonation phishing attempt | SPF/DKIM/DMARC, sender spoofing |
| [Nessus Vulnerability Scanning](./nessus-vulnerability-scanning/README.md) | Vulnerability assessment — Nessus scan of a deliberately misconfigured Ubuntu server | T1557, T1078, T1110, T1210, T1068 |
| [Azure Arc + AMA Lockout Lab](./azure-arc-ama-lockout-lab/README.md) | Identity/log pipeline — Arc onboarding, AMA deployment, and AD lockout detection testing | T1110, 4625, 4776, 4740 |
| [Insight Investigation: Brute Force on nac-ps01](./insight-19362-brute-force-nac-ps01/README.md) | SIEM alert triage — Sumo Logic insight investigation of a rotating-IP brute-force campaign against a NAC admin account | T1110.001 |

## Background

Currently working toward a SOC analyst role, with hands-on experience in Microsoft Defender for Business, Entra ID, Intune, and Azure Sentinel/Log Analytics from day-to-day IT support work, supplemented by structured lab work in network forensics, IDS (Suricata), and vulnerability scanning (Nessus).

More projects added as they're completed.