# Incident Case 02 — WinRM / PowerShell Remoting Activity

## Case Summary

### Case ID
CYB-IR-002

### Incident Type
Potential Lateral Movement

### Data Source
EVTX-ATTACK-SAMPLES

### Related Hunt
Hunt 02 — WinRM / PowerShell Remoting Lateral Movement

### Initial Classification
Suspicious Activity — Requires Additional Corroboration

---

## Detection

The investigation originated from telemetry associated with WinRM and PowerShell Remoting activity in the Lateral Movement dataset.

A relevant event was identified in:

- File: `LM_winrm_exec_sysmon_1_winrshost.evtx`
- Image: `C:\Windows\System32\winrshost.exe`
- ParentImage: `C:\Windows\System32\svchost.exe`
- CommandLine: `C:\Windows\system32\WinrsHost.exe -Embedding`

Additional suspicious activity was observed in:

- File: `LM_sysmon_psexec_smb_meterpreter.evtx`
- `cmd.exe` launched by `services.exe`
- PowerShell executed with `-nop -w hidden -noni`
- Command contained encoded/compressed PowerShell content.

---

## Investigation Hypothesis

WinRM and PowerShell Remoting activity associated with unusual process execution may indicate lateral movement or remote execution.

The investigation therefore examined process creation telemetry for WinRM and PowerShell-related processes and suspicious command-line characteristics.

---

## Evidence Reviewed

### Primary Evidence

**Sysmon Event ID 1 — Process Creation**

The hunt examined:

- `Image`
- `ParentImage`
- `CommandLine`

Relevant processes included:

- `winrshost.exe`
- `wsmprovhost.exe`
- `powershell.exe`

### Suspicious Process Chain

Observed activity included:

`services.exe → cmd.exe → powershell.exe`

The PowerShell execution included:

- `-nop`
- `-w hidden`
- `-noni`

The command also contained encoded/compressed PowerShell content.

---

## Related Telemetry

Additional PowerShell remoting-related activity was observed in:

- `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`
- `lm_sysmon_18_remshell_over_namedpipe.evtx`
- `LM_sysmon_3_12_13_1_SharpRDP.evtx`

---

## Timeline

| Stage | Evidence |
|---|---|
| Detection | WinRM/PowerShell-related process telemetry identified |
| Investigation | Sysmon Event ID 1 process creation telemetry reviewed |
| Finding | `winrshost.exe` activity identified |
| Additional Finding | Service-launched hidden PowerShell with encoded/compressed content |
| Assessment | Activity considered suspicious and consistent with possible lateral movement |
| Closure | Requires additional corroborating evidence |

---

## MITRE ATT&CK Mapping

### T1021.006 — Windows Remote Management

WinRM-related process activity was identified during the hunt.

### T1059.001 — PowerShell

PowerShell execution was identified, including suspicious command-line characteristics.

---

## Impact Assessment

Potential impact includes unauthorized remote execution or lateral movement between systems.

The available hunt telemetry does not provide sufficient evidence to determine whether unauthorized access to another host actually occurred.

---

## Root Cause

A definitive root cause cannot be established from the available telemetry.

Additional authentication, source/target host, and network telemetry would be required to determine how the observed activity originated and whether it resulted in unauthorized lateral movement.

---

## Containment Considerations

For a real production incident:

1. Identify the source and destination hosts.
2. Validate the account associated with the remote activity.
3. Isolate affected systems if unauthorized activity is confirmed.
4. Review PowerShell and authentication telemetry.
5. Investigate the suspicious executable or command content.
6. Reset affected credentials if compromise is confirmed.

---

## Detection Gap

The hunt successfully identified WinRM and PowerShell-related process activity.

However, the current investigation is primarily based on Sysmon Event ID 1 process creation telemetry.

Additional corroborating evidence should be reviewed, including:

- Windows authentication events
- WinRM/WSMan telemetry
- Source and destination host information
- Network connection telemetry
- Additional process creation events

This would improve confidence when determining whether the activity represents confirmed lateral movement.

---

## Final Classification

**Classification: Suspicious Activity — Not Confirmed Compromise**

The investigation identified telemetry consistent with possible WinRM/PowerShell remote execution and lateral movement.

The combination of service-based execution and hidden PowerShell containing encoded/compressed content is suspicious.

However, the available evidence does not conclusively establish a confirmed compromise or successful lateral movement.

---

## Closure

Case CYB-IR-002 is closed as **Suspicious Activity / Requires Additional Corroboration**.

The case demonstrates that the threat-hunting workflow can identify potentially suspicious remote-execution activity and highlights the need for authentication and network telemetry for stronger incident confirmation.
