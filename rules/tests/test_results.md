# Sigma Detection Rule Test Results

## Summary

- Total Sigma rules tested: **15**
- Rules with detection matches: **15/15**
- Dataset: **EVTX-ATTACK-SAMPLES**
- Testing method: Python-based EVTX parsing and detection-condition checks
- Overall status: **All submitted rules produced detection matches against actual log data**

---

## Rule 1 — Scheduled Task Creation

- Test: `test_scheduled_task.py`
- Events checked: 2
- Matches: 1
- Detection condition: Windows Security Event ID 4698
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 2 — Windows Command Shell Execution

- Test: `test_cmd_execution.py`
- Total events: 4
- Matches: 1
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 3 — Windows Event Log Cleared

- Test: `test_event_log_cleared.py`
- Total events: 1
- Matches: 1
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 4 — IIS Local RDP Tunnel

- Test: `test_iis_local_rdp_tunnel.py`
- Total events: 12
- Matches: 2
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 5 — Local Group Discovery

- Test: `test_local_group_discovery.py`
- Total events: 5
- Matches: 5
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 6 — Local Group Membership Change

- Test: `test_local_group_membership_change.py`
- Total events: 2
- Matches: 2
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 7 — LSASS Credential Access

- Test: `test_lsass_credential_access.py`
- Total events: 1
- Matches: 1
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 8 — PowerShell LSASS Script Block

- Test: `test_powershell_lsass_scriptblock.py`
- Total events: 4
- Matches: 1
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 9 — PowerShell Registry Value Deletion

- Test: `test_powershell_registry.py`
- Total events: 1
- Matches: 1
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 10 — WMIC Process Discovery

- Test: `test_process_discovery_wmic.py`
- Total events: 8
- Matches: 1
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 11 — RDP Authentication

- Test: `test_rdp_authentication.py`
- Total events: 228
- Matches: 11
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 12 — Registry Run Keys

- Test: `test_registry_run_keys.py`
- Total events: 7
- Matches: 1
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 13 — User Account Creation

- Test: `test_user_account_creation.py`
- Total events: 2
- Matches: 2
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 14 — Windows Service Creation

- Test: `test_windows_service.py`
- Total events: 3
- Matches: 2
- Result: **DETECTION MATCHED**
- Status: **Tested**

## Rule 15 — WMI Child Process

- Test: `test_wmi_child_process.py`
- Total events: 27
- Matches: 3
- Result: **DETECTION MATCHED**
- Status: **Tested**

---

## Overall Test Result

All **15/15 Sigma detection rules** produced at least one detection match against the EVTX-ATTACK-SAMPLES dataset.

This provides evidence that all submitted rules were tested against actual log data.

**Note:** Detection matching confirms that the rule logic can identify matching telemetry. It does not by itself establish that every match represents malicious activity. False-positive review is documented separately as required by the engagement.
