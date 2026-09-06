# Cyberion Detection Engineering — Data Dictionary

## 1. Microsoft-Windows-Sysmon

### Sample
UACME_59_Sysmon.evtx

### Description
Sysmon provides endpoint telemetry about process execution, process relationships, command-line activity, and network-related activity.

### Observed Provider
Microsoft-Windows-Sysmon

### Detection Use
Used for endpoint detection such as suspicious process execution, parent-child process relationships, command-line activity, and network connections.

---

## 2. Microsoft-Windows-Security-Auditing

### Sample
Execution/temp_scheduled_task_4698_4699.evtx

### Description
Windows Security auditing events provide security-relevant activity recorded by the Windows Security event log.

### Observed Provider
Microsoft-Windows-Security-Auditing

### Important Event
4698 — Scheduled Task Created

### Detection Use
Used to detect creation of scheduled tasks that may indicate execution or persistence.

---

## 3. Service Control Manager

### Sample
Defense Evasion/DE_WinEventLogSvc_Crash_System_7036.evtx

### Description
Service Control Manager records Windows service state and service-related activity in the System event log.

### Observed Provider
Service Control Manager

### Important Event
7036 — Service entered a running/stopped state

### Detection Use
Used to investigate suspicious service activity, service state changes, and potential service-based execution or persistence.
