# Hunt 01 — LSASS Process Access

## Hypothesis
Processes accessing `lsass.exe` through Windows Sysmon Event ID 10 may indicate credential-access activity involving LSASS.

## Dataset
- Source: EVTX-ATTACK-SAMPLES
- Analysis scope: All `.evtx` files under the dataset
- Event ID analyzed: 10 — Process Access

## Method
The hunt recursively analyzed all EVTX files and:
1. Parsed each Windows event.
2. Selected Event ID 10.
3. Checked whether `TargetImage` ended with `\lsass.exe`.
4. Recorded the source process, target process, and `GrantedAccess` value.

## Findings
Total events analyzed: **37,364**

LSASS access events identified: **28**

A notable finding was:

- File: `Defense Evasion/DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx`
- SourceImage: `c:\Users\Public\BYOV\ZAM64\ppldump.exe`
- TargetImage: `C:\Windows\system32\lsass.exe`
- GrantedAccess: `0x001fffff`

## Assessment
The finding shows a process named `ppldump.exe` obtaining access to the LSASS process with a high access mask. This is suspicious and warrants investigation as potential credential-access activity.

This hunt identifies suspicious telemetry but does not, by itself, establish full incident confirmation.

## Conclusion
The hypothesis is supported: LSASS process-access telemetry can identify potentially suspicious credential-access behavior.

Further corroborating evidence should be reviewed before classifying the activity as a confirmed incident.
