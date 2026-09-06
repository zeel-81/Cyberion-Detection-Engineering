# Cyberion Detection Engineering — Data Dictionary

## Telemetry Source 1: Windows Security Event Log

### Sample
EVTX-ATTACK-SAMPLES

### Event
Windows Scheduled Task Creation (Event ID 4698)

### Fields
- EventID:
- TimeCreated:
- Computer:
- SubjectUserName:
- SubjectDomainName:
- TaskName:
- TaskContent:

### Detection Use
Used to identify creation of scheduled tasks that may be used for persistence or execution.

---

## Telemetry Source 2: Sysmon

### Sample
UACME_59_Sysmon.evtx

### Fields
- EventID:
- Image:
- CommandLine:
- ParentImage:
- ParentCommandLine:
- User:
- ProcessId:
- ParentProcessId:
- Hashes:
- DestinationIp:
- DestinationPort:

### Detection Use
Used for process execution, parent-child relationships, command-line activity and network-related detections.

---

## Telemetry Source 3: Windows Event / Other

### Source:
To be finalized after dataset inspection.

### Detection Use
To be documented after selecting the third telemetry source.
