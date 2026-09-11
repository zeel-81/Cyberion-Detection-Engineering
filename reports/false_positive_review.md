# False-Positive Review — Sigma Detection Rules

## Purpose

This document records the false-positive considerations for all submitted Sigma detection rules.

The review identifies legitimate activities that may trigger each rule and provides analyst considerations for distinguishing expected administrative activity from potentially malicious behavior.

The presence of a listed false-positive scenario does not mean that a false positive was observed in the dataset. It represents a documented review consideration.

---

## Rule 1 — Scheduled Task Creation

**Rule:** `scheduled_task_creation.yml`

**Potential False Positives:**
- Legitimate administrative task creation
- Software installers creating scheduled tasks

**Review Consideration:**
Review the task name, creator account, command/action, and parent process.

**Tuning Consideration:**
Known enterprise task names and approved software deployment activity may be allowlisted where appropriate.

**Review Status:** Documented

---

## Rule 2 — Windows Command Shell Execution

**Rule:** `windows_cmd_execution.yml`

**Potential False Positives:**
- Legitimate administrative command execution
- System scripts and software installers

**Review Consideration:**
Review the command line, parent process, user account, and execution context.

**Tuning Consideration:**
Focus on suspicious command-line patterns and unusual parent-child relationships rather than all command-shell execution.

**Review Status:** Documented

---

## Rule 3 — Windows Event Log Cleared

**Rule:** `windows_event_log_cleared.yml`

**Potential False Positives:**
- Authorized administrative log clearing
- System maintenance or troubleshooting

**Review Consideration:**
Verify the initiating account, host, timing, and administrative change activity.

**Tuning Consideration:**
Correlate log-clearing activity with approved maintenance windows and administrator activity.

**Review Status:** Documented

---

## Rule 4 — IIS Local RDP Tunnel

**Rule:** `iis_local_rdp_tunnel.yml`

**Potential False Positives:**
- Legitimate IIS applications using local RDP-related services
- Authorized security testing

**Review Consideration:**
Review the IIS process context, destination/connection details, and whether the activity is expected for the server.

**Tuning Consideration:**
Approved application behavior and authorized testing infrastructure may require exception handling.

**Review Status:** Documented

---

## Rule 5 — Local Group Discovery

**Rule:** `local_group_discovery.yml`

**Potential False Positives:**
- Legitimate administrative activity
- Security and management software

**Review Consideration:**
Review the executing account, process, command line, and host role.

**Tuning Consideration:**
Known management tools may be excluded where their activity is expected and well understood.

**Review Status:** Documented

---

## Rule 6 — Local Group Membership Change

**Rule:** `local_group_membership_change.yml`

**Potential False Positives:**
- Legitimate administrator group management
- Authorized software installation or provisioning
- Enterprise identity-management activity

**Review Consideration:**
Verify the account performing the change, affected group, target account, and change authorization.

**Tuning Consideration:**
Approved identity-management systems and provisioning workflows may require contextual filtering.

**Review Status:** Documented

---

## Rule 7 — LSASS Credential Access

**Rule:** `lsass_credential_access.yml`

**Potential False Positives:**
- Legitimate security software accessing LSASS
- Endpoint monitoring and diagnostic tools
- Authorized credential security testing

**Review Consideration:**
Review the source process, process path, signer, user context, and GrantedAccess value.

**Tuning Consideration:**
Known security products and trusted diagnostic tools should be evaluated before creating exclusions.

**Review Status:** Documented

---

## Rule 8 — PowerShell LSASS Script Block

**Rule:** `powershell_lsass_scriptblock.yml`

**Potential False Positives:**
- Authorized credential-security testing
- Legitimate forensic or diagnostic tooling
- Security research in an isolated lab

**Review Consideration:**
Review the PowerShell command, user, parent process, execution host, and whether the activity belongs to an authorized investigation or lab.

**Tuning Consideration:**
Use command-line and execution-context details to distinguish authorized testing from suspicious PowerShell activity.

**Review Status:** Documented

---

## Rule 9 — PowerShell Registry Value Deletion

**Rule:** `powershell_registry_value_deletion.yml`

**Potential False Positives:**
- Legitimate PowerShell administration
- Software configuration changes

**Review Consideration:**
Review the registry path, initiating user, PowerShell command, parent process, and change context.

**Tuning Consideration:**
Approved configuration-management activity can be identified through known users, hosts, or software.

**Review Status:** Documented

---

## Rule 10 — WMIC Process Discovery

**Rule:** `process_discovery_wmic.yml`

**Potential False Positives:**
- Legitimate administrative process inventory
- Monitoring and management software

**Review Consideration:**
Review the executing process, account, command line, and frequency of the activity.

**Tuning Consideration:**
Expected monitoring and inventory tools may require contextual exclusions.

**Review Status:** Documented

---

## Rule 11 — RDP Authentication

**Rule:** `rdp_authentication.yml`

**Potential False Positives:**
- Legitimate Remote Desktop access
- Authorized administrative activity

**Review Consideration:**
Review the source host, destination host, account, authentication timing, and whether the user normally performs RDP activity.

**Tuning Consideration:**
Expected administrative RDP patterns should be evaluated before introducing exclusions.

**Review Status:** Documented

---

## Rule 12 — Registry Run Keys

**Rule:** `registry_run_keys.yml`

**Potential False Positives:**
- Legitimate software installation
- Authorized application startup configuration
- Enterprise software deployment

**Review Consideration:**
Review the registry path, executable, parent process, user, and software installation context.

**Tuning Consideration:**
Known enterprise software deployment processes may be excluded after validation.

**Review Status:** Documented

---

## Rule 13 — User Account Creation

**Rule:** `user_account_creation.yml`

**Potential False Positives:**
- Legitimate user provisioning
- Service account creation
- Authorized administrative activity

**Review Consideration:**
Verify the creating account, new account name, account type, and provisioning workflow.

**Tuning Consideration:**
Known identity-management and provisioning systems should be evaluated for expected activity.

**Review Status:** Documented

---

## Rule 14 — Windows Service Creation

**Rule:** `windows_service_creation.yml`

**Potential False Positives:**
- Legitimate software installation
- Authorized service deployment
- System administration activity

**Review Consideration:**
Review the service name, binary path, creator account, parent process, and installation context.

**Tuning Consideration:**
Known software installers and approved service deployment processes may require contextual filtering.

**Review Status:** Documented

---

## Rule 15 — WMI Child Process

**Rule:** `wmi_child_process.yml`

**Potential False Positives:**
- Legitimate WMI administration
- Monitoring and management software
- Enterprise automation

**Review Consideration:**
Review the parent process, child process, command line, account, and host role.

**Tuning Consideration:**
Known enterprise automation and management tooling should be validated before exclusions are introduced.

**Review Status:** Documented

---

# Overall Review

All **15/15 submitted Sigma rules** have documented potential false-positive scenarios and analyst review considerations.

The review distinguishes between:

1. **Potential false positives** — legitimate activity that could trigger a rule.
2. **Observed detection matches** — events where the rule condition matched actual dataset telemetry.
3. **Confirmed malicious activity** — requires additional investigation and corroborating evidence.

No claim is made that every potential false positive was observed in the dataset.

Further tuning should be performed after reviewing representative benign events and should preserve detection coverage for the targeted attacker behavior.
