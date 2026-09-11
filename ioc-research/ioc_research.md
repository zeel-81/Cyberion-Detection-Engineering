# IOC Research Notes

## 1. Purpose

This document records Indicators of Compromise (IOCs) identified during the Cyberion Defense Labs detection engineering and threat hunting engagement.

The objective is to document relevant indicators, provide available threat-intelligence context, and describe how the indicators could be operationalized during detection and incident response.

---

## 2. IOC Categories

The following IOC categories are considered:

- IP addresses
- Domains
- URLs
- File hashes
- File names
- Process names
- Host artifacts
- Other relevant indicators

---

## 3. IOC Sources

Potential sources used during this engagement include:

- Public security log datasets
- EVTX-ATTACK-SAMPLES
- Threat-intelligence references associated with public security research
- Public incident write-ups
- Findings identified during threat hunts

Only indicators supported by available evidence should be recorded as confirmed findings.

---

## 4. IOC Analysis Methodology

For each IOC:

1. Identify the indicator from available telemetry.
2. Record the indicator type.
3. Record the source dataset or investigation.
4. Determine the context in which the indicator was observed.
5. Research available threat-intelligence information where appropriate.
6. Record the confidence level.
7. Document how the IOC could be used operationally.

---

## 5. IOC Register

| IOC | Type | Source | Context | Threat Intelligence Context | Confidence | Operational Use |
|---|---|---|---|---|---|---|
| `ppldump.exe` | File/Process | Hunt 01 | Observed accessing LSASS | Suspicious credential-access context | Medium | Process-based detection and investigation |
| `procdump.exe` | File/Process | Hunt 01 | Observed accessing LSASS | Can be legitimate administrative/diagnostic software; context required | Medium | Correlate process access with execution context |
| `Outflank-Dumpert.exe` | File/Process | Hunt 01 | Observed accessing LSASS | Suspicious credential-access context | High | Endpoint detection and investigation |
| `winrshost.exe` | Process | Hunt 02 | Observed with WinRM-related execution | Legitimate Windows component; suspicious context depends on activity | Medium | Correlate with remote execution activity |
| `wsmprovhost.exe` | Process | Hunt 02 | Observed in PowerShell remoting-related dataset | Legitimate Windows component used by PowerShell Remoting | Medium | Detect unusual remote PowerShell execution |

---

## 6. Threat Intelligence Context

### PPLdump.exe

Observed in the LSASS access hunt while accessing:

`C:\Windows\system32\lsass.exe`

The observed access level was:

`0x001fffff`

This activity is suspicious because access to LSASS can be associated with credential-access techniques.

However, the presence of the process name alone should not be treated as definitive proof of compromise.

---

### Outflank-Dumpert.exe

Observed accessing LSASS during Hunt 01.

The activity is relevant to credential-access investigation and should be correlated with:

- Process creation
- Parent process
- User context
- Host activity
- Authentication events

---

### WinRM-Related Processes

`winrshost.exe` and `wsmprovhost.exe` are legitimate Windows processes.

Their presence alone is not sufficient to classify activity as malicious.

During Hunt 02, WinRM/PowerShell-remoting-related execution was investigated together with process creation telemetry.

---

## 7. Operationalization

IOCs can be operationalized through:

### Detection Rules

Use high-confidence indicators as supporting conditions in Sigma detections where appropriate.

Avoid relying exclusively on static filenames because legitimate software can produce the same indicators.

### Threat Hunting

Search historical telemetry for:

- Repeated occurrences
- Related processes
- Associated users
- Source and destination systems
- Similar command lines

### Incident Response

During an investigation, use IOCs to:

- Search affected hosts
- Search related telemetry
- Identify additional affected systems
- Determine the scope of activity
- Support timeline reconstruction

### Monitoring

Where supported by available telemetry, monitor recurring occurrences of high-confidence indicators.

---

## 8. Confidence Classification

### High

Strong evidence indicates that the indicator is associated with suspicious or malicious activity in the investigated context.

### Medium

The indicator is suspicious in context but may also have legitimate uses.

### Low

The indicator requires additional evidence before it can be considered meaningful.

---

## 9. False Positive Considerations

IOC matching should not automatically result in an incident classification.

Examples:

- `procdump.exe` may be used by legitimate administrators.
- `winrshost.exe` is a legitimate Windows process.
- `wsmprovhost.exe` can occur during legitimate PowerShell Remoting.

Context, process relationships, user activity, authentication events, and other available telemetry should be considered before escalation.

---

## 10. Investigation Limitations

The available datasets do not necessarily provide complete network, DNS, endpoint, and threat-intelligence telemetry for every finding.

Therefore:

- Absence of an IOC does not prove absence of compromise.
- IOC reputation alone does not prove malicious activity.
- Indicators should be correlated with behavioral evidence.
- Findings should be classified according to the available evidence.

---

## 11. Summary

IOC research supports detection engineering and incident response by providing reusable indicators and contextual intelligence.

For this engagement, IOC analysis is treated as supporting evidence rather than a standalone method for confirming compromise.

Indicators should be continuously reviewed and correlated with telemetry before being used for high-confidence incident classification.
