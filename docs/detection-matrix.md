# Detection Matrix

This matrix summarizes the detection scenarios implemented and evaluated in the Wazuh-Sysmon Detection Engineering Lab.

| # | Scenario | Data Source | Detection Type | Rule ID | MITRE ATT&CK | Result |
|---|---|---|---|---|---|---|
| 01 | Encoded PowerShell | Sysmon / Windows Event Channel | Native Wazuh | 92057 | T1059.001 | ✅ Detected live |
| 02 | User added to local Administrators group | Windows Security | Native Wazuh | 60154 | T1484 | ✅ Detected live |
| 03 | PowerShell launched by Windows Script Host | Sysmon Event ID 1 | Custom | 100100 | T1059.001, T1059.005 | ✅ Detected live |
| 04 | Scheduled Task persistence | TaskScheduler Operational | Experimental | 100101 | T1053.005 | ⚠️ Rule matched in `wazuh-logtest`, but no live alert generated |
| 05 | PowerShell launched with hidden window | Sysmon Event ID 1 | Custom | 100102 | T1059.001, T1564.003 | ✅ Detected live |
| 06 | Defender Tamper Protection blocked configuration change | Windows Defender Operational | Experimental | 100103 | T1562.001 | ⚠️ Event ID 5013 collected, but no live custom alert generated |
| 07 | PowerShell web download command | Sysmon Event ID 1 | Custom | 100104 | T1059.001, T1105 | ✅ Detected live |
| 08 | Registry Run Key persistence | Sysmon Event ID 13 | Experimental | 100105 | T1547.001 | ⚠️ Registry activity observed; custom live detection required further tuning |
| 09 | MSHTA launched with remote URL | Sysmon Event ID 1 | Custom | 100106 | T1218.005 | ✅ Detected live |
| 10 | Certutil remote download attempt | Sysmon Event ID 1 | Experimental | 100107 | T1105 | 🛡️ Endpoint blocked remote execution before expected Sysmon telemetry was generated |

## Summary

### Production-ready custom rules

The following custom detections were validated successfully in the live Wazuh pipeline:

- `100100` — PowerShell launched by Windows Script Host
- `100102` — PowerShell launched with hidden window
- `100104` — PowerShell launched with web download command
- `100106` — MSHTA launched with remote URL

### Native Wazuh detections validated

- Encoded PowerShell execution — Rule `92057`
- Local Administrators group modification — Rule `60154`

### Experimental / research outcomes

The lab also exposed several useful limitations and tuning challenges:

- Custom rules matching some Windows Event Channel events behaved differently between `wazuh-logtest` and the live analysis pipeline.
- Registry-based detection produced excessive noise before additional context was introduced.
- Endpoint security controls prevented the Certutil remote-download scenario from fully executing.
- Microsoft Defender Tamper Protection successfully blocked attempted changes to real-time protection.

These outcomes were retained because they are part of the detection-engineering lifecycle: collection validation, rule development, testing, tuning, troubleshooting, and documenting limitations.