# Cyberion ThreatShield — MITRE ATT&CK Coverage Matrix

| Rule    | Detection                               | ATT&CK Technique                                                      | Technique ID | Status | Validation Evidence   |
| ------- | --------------------------------------- | --------------------------------------------------------------------- | ------------ | ------ | --------------------- |
| Rule 01 | Scheduled Task Creation                 | Scheduled Task/Job: Scheduled Task                                    | T1053.005    | Tested | EVTX Event 4698       |
| Rule 02 | PowerShell Registry Value Deletion      | Modify Registry                                                       | T1112        | Tested | Sysmon Event 12       |
| Rule 03 | Windows Service Creation                | Windows Service                                                       | T1543.003    | Tested | System Event 7045     |
| Rule 04 | Windows Event Log Cleared               | Indicator Removal: Clear Windows Event Logs                           | T1070.001    | Tested | Event 104             |
| Rule 05 | Local Group Membership Enumeration      | Permission Groups Discovery: Local Windows Groups                     | T1069.001    | Tested | Security Event 4799   |
| Rule 06 | Windows Command Shell Execution         | Command and Scripting Interpreter: Windows Command Shell              | T1059.003    | Tested | Sysmon Event 1        |
| Rule 07 | Local Group Membership Addition         | Account Manipulation: Additional Local or Domain Groups               | T1098.007    | Tested | Security Event 4732   |
| Rule 08 | WMIC Process Discovery                  | Process Discovery                                                     | T1057        | Tested | Sysmon Event 1        |
| Rule 09 | IIS Local RDP Connection                | Proxy: Internal Proxy                                                 | T1090.001    | Tested | Sysmon Event 3        |
| Rule 10 | RDP Authentication                      | Remote Services: Remote Desktop Protocol                              | T1021.001    | Tested | Event 1149            |
| Rule 11 | Suspicious LSASS Process Access         | OS Credential Dumping: LSASS Memory                                   | T1003.001    | Tested | Sysmon Event 10       |
| Rule 12 | Registry Run Key Persistence            | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001    | Tested | Sysmon Event 13       |
| Rule 13 | WMI Provider Host Child Process         | Windows Management Instrumentation                                    | T1047        | Tested | Sysmon Event 1        |
| Rule 14 | Windows User Account Creation           | Create Account                                                        | T1136        | Tested | Security Event 4720   |
| Rule 15 | Suspicious PowerShell LSASS Dump Script | Command and Scripting Interpreter: PowerShell                         | T1059.001    | Tested | PowerShell Event 4104 |
| Gap 01 | System Network Configuration Discovery | System Network Configuration Discovery | T1016 | Assessed — Gap | No dedicated rule/test |
| Gap 02 | System Network Connections Discovery | System Network Connections Discovery | T1049 | Assessed — Gap | No dedicated rule/test |
| Gap 03 | System Information Discovery | System Information Discovery | T1082 | Assessed — Gap | No dedicated rule/test |
| Gap 04 | System Owner/User Discovery | System Owner/User Discovery | T1033 | Assessed — Gap | No dedicated rule/test |
| Gap 05 | Remote System Discovery | Remote System Discovery | T1018 | Assessed — Gap | No dedicated rule/test |

## Coverage Summary

* Sigma rules: **15 / 15**
* Tested rules: **15 / 15**
* ATT&CK techniques tested through detection rules: **15**
* Additional ATT&CK techniques assessed as coverage gaps: **5**
* Total ATT&CK techniques assessed: **20**
* ATT&CK tactics represented: **8**
  - Command and Control
  - Credential Access
  - Defense Evasion
  - Discovery
  - Execution
  - Lateral Movement
  - Persistence
  - Privilege Escalation
* Telemetry sources: **Sysmon, Windows Security Auditing, System/EventLog, PowerShell**
* Validation approach: Each submitted rule was tested against a real EVTX sample.

## Coverage Notes

Coverage is divided into two categories:

### Tested Detection Coverage
Fifteen ATT&CK techniques are mapped to implemented Sigma rules and were validated against real EVTX samples.

### Assessed Coverage Gaps
Five additional ATT&CK techniques were assessed to identify areas where no dedicated detection rule or test currently exists:

- T1016 — System Network Configuration Discovery
- T1049 — System Network Connections Discovery
- T1082 — System Information Discovery
- T1033 — System Owner/User Discovery
- T1018 — Remote System Discovery

These five techniques are included as assessed coverage gaps and are **not claimed as tested detections**.

Some detections are intentionally narrow to reduce false positives. Legitimate administrative, monitoring, software-deployment, and security-testing activity may trigger several rules.
