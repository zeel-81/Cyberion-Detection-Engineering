# Cyberion Detection Engineering — Initial ATT&CK Techniques

## 1. T1053.005 — Scheduled Task/Job: Scheduled Task
Why selected:
Windows scheduled task creation is directly represented by Event ID 4698 in the selected dataset and can support execution/persistence detection.

## 2. T1059.001 — Command and Scripting Interpreter: PowerShell
Why selected:
PowerShell is commonly used for command and script execution. The dataset contains a PowerShell-related Sysmon sample.

## 3. T1057 — Process Discovery
Why selected:
Process enumeration is a common discovery behavior and can be detected using process creation/process telemetry.

## 4. T1082 — System Information Discovery
Why selected:
System information enumeration can reveal OS and host characteristics and is suitable for endpoint discovery detection.

## 5. T1569.002 — System Services: Service Execution
Why selected:
Windows Service Control Manager activity can be associated with service-based execution and is represented by service-related telemetry in the selected dataset.
