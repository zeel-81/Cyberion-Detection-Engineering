# Incident Case 02 — WinRM Remote-Shell Execution

## Case Summary

### Case ID
CYB-IR-002

### Incident Type
WinRM Remote-Shell Execution / Potential Lateral Movement

### Data Source
EVTX-ATTACK-SAMPLES

### Related Hunt
Hunt 02 — WinRM / PowerShell Remoting Lateral Movement

### Initial Classification
Suspicious Activity — Requires Additional Corroboration

---

## Detection

The investigation originated from telemetry associated with WinRM and PowerShell Remoting activity in the Lateral Movement dataset.

The primary evidence was identified in:

- File: `LM_winrm_exec_sysmon_1_winrshost.evtx`
- Host: `DC1.insecurebank.local`
- User: `insecurebank\Administrator`
- Image: `C:\Windows\System32\winrshost.exe`
- ParentImage: `C:\Windows\System32\svchost.exe`
- CommandLine: `C:\Windows\system32\WinrsHost.exe -Embedding`

The Sysmon telemetry showed a complete process execution chain:

`svchost.exe → winrshost.exe → cmd.exe → ipconfig.exe`

---

## Investigation Hypothesis

WinRM and PowerShell Remoting activity associated with unusual process execution may indicate lateral movement or remote execution.

The investigation therefore examined process creation telemetry for WinRM-related processes and their child processes.

---

## Evidence Reviewed

### Primary Evidence

**Sysmon Event ID 1 — Process Creation**

Three related process-creation events were identified.

### Event 1 — WinRM Remote Shell

- Time: `2019-05-16 01:31:36.408`
- Host: `DC1.insecurebank.local`
- User: `insecurebank\Administrator`
- Image: `C:\Windows\System32\winrshost.exe`
- CommandLine: `C:\Windows\system32\WinrsHost.exe -Embedding`
- ParentImage: `C:\Windows\System32\svchost.exe`
- Integrity Level: High
- LogonId: `0x000000000012fe05`
- ProcessGuid: `{dfae8213-bd78-5cdc-0000-0010c7fe1200}`

The event description identifies `winrshost.exe` as the **Host Process for WinRM's Remote Shell plugin**.

### Event 2 — Command Execution

- Time: `2019-05-16 01:31:36.443`
- Image: `C:\Windows\System32\cmd.exe`
- CommandLine: `C:\Windows\system32\cmd.exe /C ipconfig`
- User: `insecurebank\Administrator`
- ParentImage: `C:\Windows\System32\winrshost.exe`
- ParentProcessId: `3948`
- LogonId: `0x000000000012fe05`

The `ParentProcessGuid` matches the `ProcessGuid` of the WinRM `winrshost.exe` process.

### Event 3 — Child Process Execution

- Time: `2019-05-16 01:31:36.447`
- Image: `C:\Windows\System32\ipconfig.exe`
- CommandLine: `ipconfig`
- User: `insecurebank\Administrator`
- ParentImage: `C:\Windows\System32\cmd.exe`
- ParentProcessId: `3136`
- LogonId: `0x000000000012fe05`

The `ParentProcessGuid` matches the `cmd.exe` process from Event 2.

### Correlated Process Chain

The telemetry therefore establishes the following process relationship:

`svchost.exe → winrshost.exe → cmd.exe /C ipconfig → ipconfig.exe`

The WinRM process spawned `cmd.exe`, which subsequently launched `ipconfig.exe`. The events occurred within approximately 39 milliseconds and share the same user and LogonId.

This provides strong evidence of **WinRM remote-shell execution activity**.

However, all observed processes are legitimate Microsoft Windows system binaries, and the telemetry does not establish whether the activity was authorized or malicious.

---

## Related Telemetry

Additional WinRM and PowerShell-remoting samples were identified in the dataset, including:

- `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`
- `lm_sysmon_18_remshell_over_namedpipe.evtx`
- `LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx`
- `RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx`

These samples were treated as separate dataset evidence because they contain different hosts and/or timestamps and were not merged into the primary incident timeline.

---

## Timeline

| Stage | Evidence |
|---|---|
| Detection | Sysmon Event ID 1 identified `winrshost.exe` execution |
| 01:31:36.408 | `svchost.exe` launched `winrshost.exe` |
| 01:31:36.443 | `winrshost.exe` launched `cmd.exe /C ipconfig` |
| 01:31:36.447 | `cmd.exe` launched `ipconfig.exe` |
| Assessment | Correlated telemetry confirmed WinRM remote-shell execution |
| Closure | Confirmed detection of WinRM remote-shell activity; malicious intent/lateral movement not established |

---

## MITRE ATT&CK Mapping

### T1021.006 — Windows Remote Management

WinRM remote-shell execution was identified through `winrshost.exe` and its child-process activity.

### T1059.003 — Windows Command Shell

`cmd.exe /C ipconfig` was executed as a child of the WinRM remote-shell process.

---

## Impact Assessment

The observed activity confirms execution through a WinRM remote shell.

Potential impact includes remote command execution and possible lateral movement.

However, the available telemetry does not establish:

- the source host of the WinRM connection
- whether the activity was authorized
- whether another host was compromised
- whether additional malicious actions occurred after `ipconfig.exe`

Therefore, broader host compromise or successful unauthorized lateral movement cannot be concluded from this evidence alone.

---

## Root Cause

A definitive root cause or initial access vector cannot be established from the available telemetry.

The evidence establishes that a WinRM remote-shell process executed commands under the `insecurebank\Administrator` account.

Additional authentication, source-host, destination-host, and network telemetry would be required to determine how the session originated and whether it was unauthorized.

---

## Containment Considerations

For a real production incident:

1. Identify the source and destination hosts associated with the WinRM session.
2. Validate whether `insecurebank\Administrator` was authorized to initiate the session.
3. Review Windows authentication and WinRM/WSMan operational logs.
4. Review subsequent process and network activity on the destination host.
5. Isolate affected systems if unauthorized activity is confirmed.
6. Reset affected credentials if compromise is established.

---

## Detection Gap

The investigation successfully identified a WinRM remote-shell process chain using Sysmon Event ID 1.

However, Sysmon process creation telemetry alone does not provide sufficient context to determine the source of the remote WinRM connection or whether the activity was authorized.

Additional telemetry that would improve detection confidence includes:

- Windows authentication events
- WinRM/WSMan operational logs
- Source and destination host information
- Network connection telemetry
- PowerShell logging
- Additional process creation telemetry

---

## Final Classification

**Classification: Confirmed Detection — WinRM Remote-Shell Execution Activity**

The investigation identified correlated Sysmon telemetry showing:

`svchost.exe → winrshost.exe → cmd.exe → ipconfig.exe`

The process hierarchy, shared LogonId, matching parent-process GUIDs, and WinRM-specific `winrshost.exe` description provide sufficient evidence to confirm **WinRM remote-shell execution activity**.

This classification confirms the observed detection/activity. It does **not** establish malicious intent, unauthorized access, successful lateral movement, or broader host compromise.

---

## Closure

Case CYB-IR-002 is closed as **True Positive (TP) — Confirmed WinRM Remote-Shell Execution Activity**.

The case demonstrates that the threat-hunting workflow can identify and validate a WinRM remote-execution process chain using Sysmon telemetry.

The primary limitation is the absence of source-host, authentication, and network telemetry required to determine whether the observed WinRM activity represented unauthorized lateral movement.
