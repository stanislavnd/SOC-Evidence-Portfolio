# Vulnerability Assessment of an Ubuntu Server Using Nessus

**1. Objective**

Use Nessus vulnerability assessment to identify introduced
vulnerabilities on an Ubuntu server and propose remediation methods to
secure and harden the server.

**2. Lab Environment**

- Ubuntu Server (Target)

**3. Ubuntu Server Preparation**

- Installed Ubuntu Server

- Updated the system: sudo apt-get update

- OpenSSH installed during initial setup

**4. Introducing Security Weaknesses (Lab Only)**

The following intentional misconfigurations were introduced to simulate
a vulnerable environment for assessment purposes only:

- **Root password set** via sudo passwd root

- **SSH password authentication enabled** — PasswordAuthentication yes
  in /etc/ssh/sshd_config

- **Root login over SSH permitted** — PermitRootLogin yes in
  /etc/ssh/sshd_config

- **Samba installed and exposed** — ports 137/138 (UDP), 139/445 (TCP)
  reachable on the network

**5. Scan Setup and Execution**

Nessus Essentials was installed on the Ubuntu server to target its IPv4
address: 192.168.0.170. A Basic Network Scan was run against the target,
returning 70 identified vulnerabilities across multiple severity levels.

<img src="./media/image1.png"
style="width:4.92647in;height:2.89847in" />

**6. Vulnerability Analysis**

**Key Findings**

| **Severity** | **Finding**                                | **Port/Service**         | **CVE**        |
|--------------|--------------------------------------------|--------------------------|----------------|
| Critical     | pyOpenSSL 22.0.x \< 26.0.0 Buffer Overflow | —                        | CVE-2026-27459 |
| High         | SSH root login permitted                   | 22/tcp                   | —              |
| High         | SSH password authentication enabled        | 22/tcp                   | —              |
| Medium       | Samba service exposed                      | 137,138/udp, 139,445/tcp | —              |
| Medium       | Running unencrypted Telnet service         | 23/tcp                   |                |
| Medium       | SMB Signing not required                   | 445 /tcp                 | CVSSv3.0 5.3.y |

**Notable Detail**

The pyOpenSSL buffer overflow (CVE-2026-27459) affects versions ≥22.0.0
and \<26.0.0, triggered when a user-supplied cookie callback returns a
value greater than 256 bytes, overflowing an OpenSSL-provided buffer.
Nessus flags this based on self-reported version data rather than direct
exploitation testing.

**7. MITRE ATT&CK Mapping**

| **Finding**                         | **Technique**                         | **ID** |
|-------------------------------------|---------------------------------------|--------|
| SMB Signing is not required         | Credential Access, Collection         | T1557  |
| Root SSH login enabled              | Valid Accounts                        | T1078  |
| Running Telnet                      | Valid Accounts                        | T1078  |
| SSH password auth (brute-forceable) | Brute Force                           | T1110  |
| Samba exposed                       | Exploitation of Remote Services       | T1210  |
| pyOpenSSL buffer overflow           | Exploitation for Privilege Escalation | T1068  |

**8. Recommendations**

- Disable root SSH login: set PermitRootLogin no

- Disable password authentication; enforce key-based SSH auth only

- Restrict or firewall Samba (137/138/139/445) to trusted hosts only, or
  disable if unused

- Disable Telnet service and restrict port 23

- Enforce message signing in the host’s configuration for SMB

- Upgrade pyOpenSSL to version 26.0.0 or later

- Re-scan after remediation to confirm findings are resolved

**9. Conclusion**

This lab demonstrated end-to-end vulnerability assessment on a
deliberately weakened Ubuntu server — from introducing realistic
misconfigurations, to scanning with Nessus, to mapping findings against
MITRE ATT&CK and producing actionable remediation steps. The exercise
reflects a practical SOC workflow: identify exposure, prioritize by
severity, and recommend hardening measures.
