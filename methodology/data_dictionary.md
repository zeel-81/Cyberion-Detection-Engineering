# Cyberion Detection Engineering — Data Dictionary

## Telemetry Source 1: Windows Sysmon

### Sample
UACME_59_Sysmon.evtx

### Purpose
Provides endpoint telemetry for process execution, process relationships, file and network activity, and other host-level detection opportunities.

### Observed Event IDs
To be documented from the dataset.

### Observed Fields
To be populated from the parsed Sysmon sample.

### Detection Use
Used to detect suspicious process execution, command-line activity, parent-child relationships, network connections, and other endpoint behaviors.

## Telemetry Source 2: Windows Security Event Log

### Sample
EVTX-ATTACK-SAMPLES

### Event
4698 — Scheduled Task Creation

### Detection Use
Used to identify scheduled task creation that may indicate execution or persistence.

## Telemetry Source 3

### Source
To be selected and documented.

### Detection Use
To be determined after source selection.
