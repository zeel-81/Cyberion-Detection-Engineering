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
Confirmed Detection — LSASS Credential Access Activity

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

**Sysmon Event ID 1 — Process Creation**

The suspicious process was created as:

- Image: `c:\Users\Public\BYOV\ZAM64\ppldump.exe`
- Process ID: `5016`
- Process GUID: `{747f3d96-2b98-5e41-0000-00109c904700}`
- Description: `ppldump.exe -p lsass.exe -o a.png`

**Sysmon Event ID 10 — Process Access**

The same process accessed LSASS:

- SourceImage: `c:\Users\Public\BYOV\ZAM64\ppldump.exe`
- TargetImage: `C:\Windows\system32\lsass.exe`
- GrantedAccess: `0x001fffff`
- SourceProcessGUID matches the Event ID 1 process.
- CallTrace contains multiple `ppldump.exe` frames.

**Sysmon Event ID 7 — Image Load**

Shortly after the LSASS access, Sysmon recorded image-load activity in `lsass.exe` involving:

- `C:\Windows\System32\dbgcore.dll`
- `C:\Windows\System32\dbghelp.dll`

The dataset labels these events `Suspicious ImageLoad - Possible Memdump`.

The DLLs are recorded as Microsoft-signed with valid signatures and are therefore not treated as malicious evidence by themselves.

**Sysmon Event ID 5 — Process Termination**

The `ppldump.exe` process later terminated at approximately `10:08:27.779`, using the same Process GUID as the Event ID 1 process.

### Correlated Evidence

The telemetry establishes the following sequence on host `MSEDGEWIN10`:

`ppldump.exe execution → LSASS process access → LSASS image-load activity → ppldump.exe termination`

Event ID 1 and Event ID 10 occurred approximately **0.13 seconds apart**, with the matching Process GUID linking them to the same process.

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
| Assessment | Correlated Sysmon telemetry confirmed LSASS credential-access activity |
| Closure | True Positive (TP) — Confirmed LSASS Credential Access Activity |

---

## MITRE ATT&CK Mapping

### T1003.001 — OS Credential Dumping: LSASS Memory

The observed process access to `lsass.exe` is relevant to credential-access activity involving LSASS memory.

---

## Impact Assessment

Observed activity is consistent with LSASS credential-access / memory-dumping behavior and could expose credentials or authentication material.

The available dataset does not provide sufficient evidence to quantify actual credential exposure or establish broader host compromise.

---

## Root Cause

A definitive root cause or initial access vector cannot be established from the available telemetry alone.

The observed execution chain shows `cmd.exe` launching `ppldump.exe`, followed by LSASS access and related image-load activity. User intent and the original source of the execution remain unknown.

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

The existing LSASS detection successfully identified and, through correlated Sysmon telemetry, confirmed the observed LSASS credential-access activity.

Additional telemetry would improve investigation scope and impact assessment rather than the confirmation of the observed activity, including:

- Authentication events
- User/account context
- Network telemetry
- File creation and broader host telemetry

---

## Final Classification

**Classification: Confirmed Detection — LSASS Credential Access Activity**

The investigation identified correlated Sysmon telemetry showing `ppldump.exe` execution, high-access interaction with `lsass.exe`, suspicious image-load activity, and subsequent process termination.

The detection is therefore classified as a True Positive (TP) for LSASS credential-access activity. This does not establish the full scope or downstream impact of a broader host compromise.

---

## Closure

Case CYB-IR-001 is closed as **True Positive (TP) — Confirmed LSASS Credential Access Activity**.

The finding demonstrates that the detection and hunting workflow identified and corroborated LSASS credential-access activity through correlated Sysmon telemetry.
