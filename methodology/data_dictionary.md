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

---

## 4. Important Sysmon Fields

The following fields are relevant to detection and threat hunting when present in Sysmon telemetry:

| Field | Purpose |
|---|---|
| Event ID | Identifies the Sysmon event type |
| Image | Executable/process path |
| ParentImage | Parent process path |
| CommandLine | Command-line arguments used to execute a process |
| User | Account associated with the activity |
| ProcessId | Identifier of the process |
| ParentProcessId | Identifier of the parent process |
| TargetImage | Target process involved in process-access activity |
| GrantedAccess | Access rights requested against the target process |
| SourceImage | Source process involved in process-access activity |
| DestinationIp | Destination IP address when network telemetry is available |
| DestinationPort | Destination port when network telemetry is available |

### Detection / Hunting Relevance

These fields can be used to identify:

- Suspicious process execution
- Unusual parent-child relationships
- Suspicious command-line activity
- Process access to sensitive processes
- Network connections associated with suspicious processes

---

## 5. Important Windows Security Auditing Fields

When available, the following fields are useful for Windows Security event analysis:

| Field | Purpose |
|---|---|
| Event ID | Identifies the Windows Security event |
| SubjectUserName | Account performing the activity |
| TargetUserName | Account affected by the activity |
| Computer | System where the event occurred |
| LogonType | Indicates the type of authentication/logon |
| IpAddress | Source IP address when provided |
| ProcessName | Process associated with the event when available |

### Detection / Hunting Relevance

These fields can support investigation of:

- Account activity
- Authentication activity
- Scheduled task creation
- Privilege-related activity
- Suspicious remote access

---

## 6. Important Service Control Manager Fields

When available, service-related events may contain fields such as:

| Field | Purpose |
|---|---|
| Event ID | Identifies the service event |
| ServiceName | Name of the affected service |
| ImagePath | Executable path associated with the service when available |
| AccountName | Account used by the service when available |
| Computer | System where the event occurred |

### Detection / Hunting Relevance

These fields can support investigation of:

- Service creation or modification
- Suspicious service execution
- Service-based persistence
- Unexpected service state changes

---

## 7. Data Dictionary Limitations

Field availability can vary between datasets and individual EVTX event types.

Therefore, a field listed above should only be used when it is actually present in the relevant telemetry.

Detection and hunting analysis should be based on fields observed in the dataset rather than assuming that every source contains every field.
