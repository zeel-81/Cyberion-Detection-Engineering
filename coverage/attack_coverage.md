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

## Coverage Summary

* Sigma rules: **15 / 15**
* Tested rules: **15 / 15**
* ATT&CK techniques covered: **15 rule mappings**
* Telemetry sources: **Sysmon, Windows Security Auditing, System/EventLog, PowerShell**
* Validation approach: Each rule was tested against a real EVTX sample.

## Coverage Notes

Coverage claims are based on observed event fields and successful local test matches.

Some detections are intentionally narrow to reduce false positives. Legitimate administrative, monitoring, software-deployment, and security-testing activity may trigger several rules.
