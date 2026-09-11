# Incident Response Playbook — Lateral Movement

## 1. Purpose

This playbook provides a structured response process for suspected lateral movement within an environment.

The objective is to identify remote execution activity, determine affected systems, contain the activity, and document the final outcome.

---

## 2. Trigger

Initiate this playbook when one or more of the following are observed:

- Suspicious WinRM activity
- PowerShell Remoting activity
- PsExec or service-based remote execution
- Unusual remote authentication
- Suspicious process execution on multiple systems
- Detection rule or threat hunt identifies potential lateral movement

---

## 3. Initial Investigation

### Step 1 — Identify affected systems

Collect:

- Source hostname
- Source IP address
- Destination hostname
- Destination IP address
- Username
- Account privilege level
- Time of activity

### Step 2 — Review relevant telemetry

Review available:

- Sysmon Event ID 1 — Process Creation
- Windows Security Authentication Events
- PowerShell logs
- Windows Remote Management logs
- Service creation events

### Step 3 — Identify remote execution indicators

Look for:

- `winrshost.exe`
- `wsmprovhost.exe`
- PowerShell Remoting
- PsExec/service-based execution
- Suspicious parent-child process relationships
- Hidden or encoded PowerShell commands

### Step 4 — Reconstruct movement

Determine:

1. Which system was the source?
2. Which system was the destination?
3. Which account was used?
4. What process was executed?
5. What happened after remote execution?

---

## 4. Evidence Validation

Where possible, confirm the activity using at least two telemetry sources.

Examples:

- Sysmon process creation + authentication event
- WinRM activity + process creation
- Service creation + subsequent process execution

If sufficient corroborating evidence is unavailable, classify the activity as suspicious rather than confirmed lateral movement.

---

## 5. Containment

Depending on investigation findings:

- Isolate affected endpoints
- Disable or restrict compromised accounts
- Reset potentially compromised credentials
- Restrict unnecessary remote administration protocols
- Block suspicious source/destination communication
- Preserve relevant logs and forensic evidence

Containment actions should consider business impact and authorization.

---

## 6. Eradication and Recovery

After confirming malicious activity:

- Remove malicious tools or scripts
- Remove unauthorized persistence
- Reset compromised credentials
- Review privileged accounts
- Verify remote administration configurations
- Restore affected systems where required
- Monitor source and destination systems for recurring activity

---

## 7. Communications

Notify appropriate stakeholders based on incident severity:

- Security team
- System owner
- IT/endpoint team
- Incident response lead
- Management when required

Document significant investigation and containment decisions.

---

## 8. Closure Criteria

Close the incident when:

- The activity is determined to be legitimate, or
- Malicious lateral movement has been contained and eradicated, or
- Evidence is insufficient and the case is formally classified as unresolved/suspicious

Record:

- Final classification
- Root cause
- Affected systems
- Impact
- Actions taken
- Detection gap
- Lessons learned

---

## 9. Related MITRE ATT&CK

Primary techniques:

- T1021.006 — Windows Remote Management
- T1059.001 — PowerShell

Additional techniques should only be added when supported by investigation evidence.

---

## 10. Detection Improvement

After closure, review whether existing detections could have:

- Detected remote execution earlier
- Improved source/destination visibility
- Reduced false positives
- Correlated authentication and process activity
- Provided better investigation context

Document any required tuning or new detection logic.
