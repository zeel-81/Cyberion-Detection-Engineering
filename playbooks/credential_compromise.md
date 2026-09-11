# Incident Response Playbook — Credential Compromise

## 1. Purpose

This playbook provides a structured response process for suspected credential compromise or credential-access activity.

The objective is to identify suspicious credential-related activity, investigate supporting evidence, contain the affected systems or accounts, and document the final outcome.

---

## 2. Trigger

Initiate this playbook when one or more of the following are observed:

- Suspicious access to LSASS
- Credential dumping indicators
- Suspicious PowerShell activity related to credential access
- Unexpected privileged account activity
- Authentication activity inconsistent with normal administrative behavior
- Detection rule or threat hunt identifies potential credential-access behavior

---

## 3. Initial Investigation

### Step 1 — Identify the affected account or system

Collect:

- Hostname
- IP address
- Username
- Account privilege level
- Source system
- Destination system

### Step 2 — Review relevant logs

Review available telemetry such as:

- Sysmon Event ID 10 — Process Access
- Windows Security Authentication Events
- PowerShell logs
- Process creation events

### Step 3 — Identify suspicious processes

Look for:

- Unexpected processes accessing LSASS
- Credential-dumping tools
- Suspicious PowerShell commands
- Unusual parent-child process relationships

### Step 4 — Build a timeline

Record:

- First suspicious activity
- Process execution
- Authentication activity
- Privilege-related activity
- Subsequent network or system activity

---

## 4. Evidence Validation

Where possible, confirm the finding using evidence from at least two telemetry sources.

Examples:

- Sysmon process-access event + Windows authentication event
- Process creation + PowerShell logging
- LSASS access + subsequent suspicious account activity

If sufficient corroborating evidence is unavailable, classify the activity as suspicious rather than confirmed compromise.

---

## 5. Containment

Depending on investigation findings:

- Disable or restrict the affected account
- Reset potentially compromised credentials
- Isolate the affected endpoint
- Restrict suspicious remote access
- Preserve relevant logs and forensic evidence

Containment actions should consider business impact and authorization.

---

## 6. Eradication and Recovery

After confirming malicious activity:

- Remove malicious tools or persistence mechanisms
- Reset compromised credentials
- Review privileged accounts
- Verify endpoint security controls
- Restore affected systems where required
- Monitor the affected account and host for recurring activity

---

## 7. Communications

Notify appropriate stakeholders based on incident severity:

- Security team
- System owner
- IT/endpoint team
- Incident response lead
- Management when required

Document all major investigation and containment decisions.

---

## 8. Closure Criteria

Close the incident when:

- The activity is determined to be benign, or
- Malicious activity has been contained and eradicated, or
- Investigation evidence is insufficient and the case is formally classified as unresolved/suspicious

Record:

- Final classification
- Root cause
- Impact
- Actions taken
- Detection gap
- Lessons learned

---

## 9. Related MITRE ATT&CK

Primary technique:

- T1003.001 — LSASS Memory

Related techniques may be added when supported by investigation evidence.

---

## 10. Detection Improvement

After closure, review whether existing detections could have:

- Detected the activity earlier
- Reduced false positives
- Provided better context
- Correlated multiple events

Document any required tuning or new detection logic.
