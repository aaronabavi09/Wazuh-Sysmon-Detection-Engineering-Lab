# Scenario 04 - Scheduled Task Persistence

## Objective

Detect the registration of a scheduled task by a non-system user.

## Data Source

- `Microsoft-Windows-TaskScheduler/Operational`
- Windows Event ID `106`

## Test

A harmless scheduled task was created to execute a PowerShell command.

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -Command "Write-Output ScheduledTaskDetectionLab"'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)

Register-ScheduledTask `
  -TaskName "DetectionLab-Persistence-Test" `
  -Action $action `
  -Trigger $trigger `
  -Description "Detection Engineering Lab scheduled task test"
```

## Experimental Rule

- **Rule ID:** `100101`
- **Severity Level:** `9`
- **MITRE ATT&CK:** `T1053.005` - Scheduled Task

## Validation

The raw Event ID `106` was successfully collected in Wazuh archives and the real event matched rule `100101` in `wazuh-logtest`.

## Result

 **Offline rule validation succeeded, but no live alert was generated.**

The rule was therefore moved to the experimental ruleset.

## Detection Engineering Takeaway

A successful `wazuh-logtest` match does not guarantee that the live Wazuh analysis pipeline will generate an alert.

## Cleanup

```powershell
Unregister-ScheduledTask -TaskName "DetectionLab-Persistence-Test" -Confirm:$false
```

## Evidence

No screenshot was retained for this scenario.

The relevant Task Scheduler Event ID `106` was collected in Wazuh archives and the real event matched Rule ID `100101` in `wazuh-logtest`, but no live dashboard alert was generated. The scenario is therefore documented as an experimental detection.
