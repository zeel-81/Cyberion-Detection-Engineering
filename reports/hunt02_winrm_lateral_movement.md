# Hunt 02 — WinRM / PowerShell Remoting Lateral Movement

## Hypothesis
WinRM and PowerShell Remoting activity, particularly when associated with unusual or suspicious process execution, may indicate lateral movement.

## Dataset
- Source: EVTX-ATTACK-SAMPLES
- Analysis scope: Lateral Movement `.evtx` files
- Primary telemetry: Sysmon Process Creation (Event ID 1)
- Focus: WinRM / PowerShell Remoting related processes and commands

## Method
The hunt recursively analyzed EVTX files under the Lateral Movement dataset and:
1. Parsed each Windows event.
2. Selected Sysmon Event ID 1.
3. Examined `Image`, `ParentImage`, and `CommandLine` fields.
4. Identified activity involving `winrshost.exe`, `wsmprovhost.exe`, and `powershell.exe`.
5. Reviewed command-line arguments for suspicious execution characteristics.

## Findings

A relevant finding was:

- File: `LM_winrm_exec_sysmon_1_winrshost.evtx`
- Image: `C:\Windows\System32\winrshost.exe`
- ParentImage: `C:\Windows\System32\svchost.exe`
- CommandLine: `C:\Windows\system32\WinrsHost.exe -Embedding`

Additional suspicious telemetry was observed in:

- File: `LM_sysmon_psexec_smb_meterpreter.evtx`
- `cmd.exe` launched by `services.exe`
- PowerShell executed with `-nop -w hidden -noni`
- Command contained encoded/compressed PowerShell content.

Other PowerShell remoting-related activity was observed in:
- `LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`
- `lm_sysmon_18_remshell_over_namedpipe.evtx`
- `LM_sysmon_3_12_13_1_SharpRDP.evtx`

## Assessment
The hunt identified WinRM and PowerShell-related telemetry consistent with remote execution and lateral movement scenarios.

The strongest suspicious evidence was the combination of service-based execution and hidden PowerShell with encoded/compressed command content. This activity warrants further investigation.

However, the telemetry alone does not establish that a confirmed compromise occurred.

## MITRE ATT&CK Mapping
- T1021.006 — Windows Remote Management
- T1059.001 — PowerShell

## Conclusion
The hypothesis is supported: WinRM and PowerShell Remoting telemetry can identify activity potentially associated with lateral movement.

Further corroborating evidence, including authentication events, source/target host information, and additional process or network telemetry, should be reviewed before classifying the activity as a confirmed incident.
