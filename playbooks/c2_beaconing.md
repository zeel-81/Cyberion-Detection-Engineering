# Incident Response Playbook — C2 Beaconing

## 1. Purpose

This playbook provides a structured response process for suspected Command and Control (C2) beaconing activity.

The objective is to identify suspicious outbound communication patterns, investigate the associated host and process, contain the activity, and document the final outcome.

---

## 2. Trigger

Initiate this playbook when one or more of the following are observed:

- Repeated outbound connections to a suspicious destination
- Suspicious or previously unidentified external IP/domain communication
- Regular or periodic network communication patterns
- Unexpected network activity from a workstation or server
- Detection rule or threat hunt identifies potential C2 activity
- Threat intelligence identifies a communicating destination as suspicious

---

## 3. Initial Investigation

### Step 1 — Identify the affected system

Collect:

- Hostname
- IP address
- Username
- Process responsible for the connection
- Destination IP/domain
- Destination port
- First and last observed communication time

### Step 2 — Review available telemetry

Review:

- Network connection logs
- DNS logs
- Proxy/firewall logs
- Sysmon network telemetry when available
- Process creation events
- Authentication activity

### Step 3 — Examine communication pattern

Look for:

- Repeated connections to the same destination
- Similar connection intervals
- Unusual destination ports
- Unexpected external destinations
- Connections initiated by unusual processes
- Communication from systems that normally have limited internet access

### Step 4 — Identify the responsible process

Determine:

1. Which process initiated the connection?
2. Is the process legitimate?
3. What user executed the process?
4. What destination did it contact?
5. What activity occurred before and after the connection?

---

## 4. IOC Investigation

For identified indicators, document:

- IP addresses
- Domains
- URLs
- File hashes
- Associated processes

Where appropriate, compare indicators against available threat-intelligence sources.

Record the source and context of any threat-intelligence assessment.

---

## 5. Evidence Validation

Where possible, confirm suspected C2 activity using multiple telemetry sources.

Examples:

- Network connection + process creation
- DNS query + network connection
- Network connection + suspicious process execution
- Threat-intelligence context + endpoint telemetry

A suspicious destination alone should not automatically be classified as confirmed C2.

If sufficient corroborating evidence is unavailable, classify the activity as suspicious and document the investigation gap.

---

## 6. Containment

Depending on investigation findings:

- Isolate the affected endpoint
- Block confirmed malicious IPs/domains
- Restrict suspicious outbound communication
- Disable or restrict compromised accounts
- Preserve relevant logs and forensic evidence
- Prevent execution of identified malicious files where appropriate

Containment actions should consider business impact and authorization.

---

## 7. Eradication and Recovery

After confirming malicious C2 activity:

- Remove malicious files or tools
- Remove unauthorized persistence
- Reset compromised credentials
- Review scheduled tasks and services
- Verify endpoint security controls
- Restore affected systems where required
- Monitor the environment for recurring communication

---

## 8. Communications

Notify appropriate stakeholders based on incident severity:

- Security team
- Network team
- System owner
- IT/endpoint team
- Incident response lead
- Management when required

Document significant investigation and containment decisions.

---

## 9. Closure Criteria

Close the incident when:

- The communication is determined to be legitimate, or
- Malicious C2 activity has been contained and eradicated, or
- Evidence is insufficient and the case is formally classified as unresolved/suspicious

Record:

- Final classification
- Root cause
- Affected system
- Indicators identified
- Impact
- Actions taken
- Detection gap
- Lessons learned

---

## 10. Related MITRE ATT&CK

Potential related techniques include:

- T1071 — Application Layer Protocol
- T1071.001 — Web Protocols
- T1095 — Non-Application Layer Protocol

Only map techniques that are supported by the available evidence.

---

## 11. Detection Improvement

After closure, review whether existing detections could have:

- Detected the communication earlier
- Provided better process-to-network context
- Reduced false positives
- Improved IOC visibility
- Correlated endpoint and network telemetry

Document any required tuning or new detection logic.
