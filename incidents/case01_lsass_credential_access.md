# Incident Case 01 — Suspicious LSASS Process Access

## Case Summary

### Case ID
CYB-IR-001

### Incident Type
Potential Credential Access

### Data Source
EVTX-ATTACK-SAMPLES

### Related Hunt
Hunt 01 — LSASS Process Access

### Initial Classification
Suspicious Activity — Requires Investigation

---

## Detection

The investigation originated from telemetry identifying processes accessing `lsass.exe` through Sysmon Event ID 10.

A notable event involved:

- Source Process: `c:\Users\Public\BYOV\ZAM64\ppldump.exe`
- Target Process: `C:\Windows\system32\lsass.exe`
- GrantedAccess: `0x001fffff`
- Dataset File: `Defense Evasion/DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx`

---

## Investigation Hypothesis

A process obtaining high-level access to the LSASS process may indicate credential-access activity, including potential credential dumping.

The investigation therefore focused on determining whether the observed LSASS access was consistent with suspicious credential-access behavior.

---

## Evidence Reviewed

### Primary Evidence

**Sysmon Event ID 10 — Process Access**

The event records access from `ppldump.exe` to `lsass.exe` with:

`GrantedAccess = 0x001fffff`

### Hunt Evidence

Hunt 01 identified **28 LSASS access events** while analyzing **37,364 total events** across the dataset.

Other source processes observed accessing LSASS included:

- `procdump.exe`
- `taskmgr.exe`
- `Outflank-Dumpert.exe`
- `rundll32.exe`
- `AndrewSpecial.exe`
- `python.exe`
- `powershell.exe`

---

## Timeline

| Stage | Evidence |
|---|---|
| Detection | Sysmon Event ID 10 identified LSASS process access |
| Investigation | Hunt 01 analyzed LSASS access telemetry |
| Finding | `ppldump.exe` accessed `lsass.exe` |
| Assessment | High-access LSASS activity identified as suspicious |
| Closure | Activity remains classified as suspicious based on available evidence |

---

## MITRE ATT&CK Mapping

### T1003.001 — OS Credential Dumping: LSASS Memory

The observed process access to `lsass.exe` is relevant to credential-access activity involving LSASS memory.

---

## Impact Assessment

Potential impact includes exposure of credentials or authentication material if the LSASS access represented credential-dumping activity.

The available dataset does not provide sufficient evidence in this investigation to quantify actual credential exposure.

---

## Root Cause

A definitive root cause cannot be established from the available telemetry alone.

The dataset demonstrates suspicious LSASS access but does not provide sufficient corroborating evidence to determine how the activity originated.

---

## Containment Considerations

For a real production incident, recommended containment actions would include:

1. Isolate the affected endpoint.
2. Identify the account associated with the suspicious process.
3. Investigate the executable and its origin.
4. Review additional authentication and process telemetry.
5. Reset potentially exposed credentials if credential theft is confirmed.

---

## Detection Gap

The existing LSASS detection successfully identified suspicious process access.

However, additional corroborating telemetry would improve incident confirmation, including:

- Process creation events
- File creation/hash information
- Authentication events
- User/account context
- Network telemetry

---

## Final Classification

**Classification: Suspicious Activity — Not Confirmed Compromise**

The investigation identified strong suspicious telemetry involving `ppldump.exe` accessing `lsass.exe` with a high access mask.

However, based on the available EVTX evidence, the activity cannot be conclusively classified as a confirmed compromise.

---

## Closure

Case CYB-IR-001 is closed as **Suspicious Activity / Requires Additional Corroboration**.

The finding demonstrates that the detection and hunting workflow can identify potentially malicious LSASS access and provides a basis for further investigation.
