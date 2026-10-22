# Lessons Learned

This project was not only about creating alerts. It was designed to reproduce a small detection-engineering workflow: collect telemetry, understand the event source, test existing coverage, build custom rules where necessary, validate them in a live pipeline, tune noisy detections, and document technical limitations.

## 1. Validate existing detections before creating new ones

One of the most important lessons was that a custom rule should not be created simply because a behavior looks suspicious.

For example:

- Encoded PowerShell was already detected by Wazuh rule `92057`.
- Changes to the local Administrators group were already detected by Wazuh rule `60154`.

Creating duplicate rules would have added noise without improving coverage.

The better approach was:

1. Generate the behavior.
2. Observe existing Wazuh detections.
3. Determine whether the existing alert provides sufficient context.
4. Create a custom rule only when a meaningful detection gap exists.

This reduced unnecessary duplication and made the custom rules more purposeful.

---

## 2. Sysmon Event ID 1 proved to be the most reliable source for custom live detections

The most successful custom rules in the lab were based on Sysmon Process Create events.

Validated examples included:

- `100100` - PowerShell launched by Windows Script Host
- `100102` - PowerShell launched with a hidden window
- `100104` - PowerShell launched with a web download command
- `100106` - MSHTA launched with a remote URL

Sysmon Event ID 1 provided useful fields such as:

- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `User`
- process hashes
- process identifiers

These fields made it possible to build detections based on behavioral context instead of detecting a binary name alone.

---

## 3. Parent-child process relationships provide strong detection context

A process is not necessarily suspicious by itself.

For example, `powershell.exe` is a legitimate Windows component. However, the context becomes more interesting when it is launched by an unusual parent such as:

`wscript.exe -> powershell.exe`

The custom rule `100100` demonstrated how parent-child relationships can improve detection quality.

This reinforced an important principle:

> Detection logic should focus on behavior and context, not only on executable names.

---

## 4. Command-line telemetry is highly valuable

Several successful detections relied on command-line arguments.

Examples included:

- `-WindowStyle Hidden`
- `Invoke-WebRequest`
- an HTTP/HTTPS URL passed to `mshta.exe`

Without command-line logging, these processes would appear much less suspicious.

For example:

`powershell.exe`

is common.

But:

`powershell.exe -WindowStyle Hidden`

provides a much stronger detection signal.

Sysmon command-line telemetry therefore became one of the most valuable data sources in this lab.

---

## 5. A rule that generates alerts is not necessarily a good rule

The Registry Run Key scenario demonstrated this clearly.

An early version of the detection generated a large number of alerts because its matching conditions were too broad.

This showed the importance of:

- reviewing alert volume;
- identifying false-positive sources;
- adding process or path context;
- narrowing regular expressions;
- testing again after tuning.

Detection engineering therefore requires more than making a rule trigger.

A useful rule must also produce a manageable signal-to-noise ratio.

---

## 6. Testing should use real telemetry whenever possible

During the project, synthetic events were initially used with `wazuh-logtest`.

This was useful for checking rule syntax and logic, but real endpoint telemetry proved more reliable for final validation.

The preferred workflow became:

1. Generate an actual event on the Windows endpoint.
2. Verify it in Event Viewer or Sysmon.
3. Confirm that Wazuh collected it.
4. Use the real event with `wazuh-logtest` if troubleshooting is required.
5. Validate the final rule in the live Threat Hunting interface.

This helped expose differences between offline rule testing and live processing.

---

## 7. `wazuh-logtest` and the live pipeline can behave differently

Several experimental scenarios produced an important observation.

Examples:

- Scheduled Task registration (`100101`)
- Defender Tamper Protection (`100103`)
- Registry Run Key persistence (`100105`)

The relevant events were successfully collected and some rules matched when tested with `wazuh-logtest`, but equivalent alerts were not consistently generated in the live Wazuh pipeline.

This reinforced the need to distinguish between:

- rule syntax validation;
- offline rule matching;
- real-time event processing;
- alert generation;
- dashboard indexing.

A successful `wazuh-logtest` result is useful, but it should not automatically be considered a successful production detection.

---

## 8. Event collection must be validated before troubleshooting rules

Some scenarios initially appeared to be rule failures but were actually collection issues.

For example, the Task Scheduler Operational log was initially disabled.

The workflow had to become:

`Windows event source -> Event Viewer -> Wazuh agent configuration -> Manager archives -> Rule engine -> Dashboard`

Checking each stage separately prevented unnecessary changes to detection rules.

---

## 9. Security controls can change the outcome of a detection test

The Microsoft Defender and Certutil scenarios demonstrated that preventive controls may stop an action before the expected detection telemetry is produced.

Examples:

- Tamper Protection prevented changes to Defender real-time protection.
- Remote Certutil execution was blocked before the expected process telemetry with download arguments was produced.

These were not failed experiments.

They demonstrated the interaction between:

- prevention;
- telemetry;
- detection;
- response.

A defensive lab should document when an action was prevented instead of forcing the behavior to execute.

---

## 10. Failed or incomplete scenarios still provide useful engineering evidence

Not every scenario produced a production-ready rule.

Instead of hiding these results, the project separates:

- validated production rules;
- native detections;
- experimental rules;
- endpoint-blocked scenarios.

This better reflects real detection-engineering work.

The unsuccessful scenarios demonstrated:

- troubleshooting methodology;
- event-source validation;
- tuning decisions;
- platform limitations;
- understanding of defensive controls.

---

## 11. Detection rules should be separated by maturity

The project therefore uses two rule categories:

### Production

Rules that were successfully validated through the complete live pipeline:

- `100100`
- `100102`
- `100104`
- `100106`

### Experimental

Rules or scenarios requiring further investigation, tuning, or platform changes:

- `100101`
- `100103`
- `100105`
- `100107`

This separation prevents unvalidated detections from being presented as production-ready.

---

## 12. A useful detection-engineering workflow

The final workflow developed during the lab can be summarized as:

1. Define the suspicious behavior.
2. Map the behavior to MITRE ATT&CK.
3. Identify the best telemetry source.
4. Generate the behavior safely.
5. Verify that telemetry exists on the endpoint.
6. Confirm collection by Wazuh.
7. Check native detection coverage.
8. Develop a custom rule only if necessary.
9. Validate rule syntax.
10. Test using real telemetry.
11. Confirm live alert generation.
12. Review false positives and alert volume.
13. Tune the rule.
14. Document limitations and evidence.
15. Promote only validated rules to the production ruleset.

---

## Key Takeaway

The main lesson from this lab is that detection engineering is not simply writing SIEM rules.

It is an iterative process involving:

**telemetry collection -> behavioral analysis -> detection design -> testing -> validation -> tuning -> documentation**

The most valuable outcome was not the number of rules created, but the ability to understand why a detection worked, why another did not, and how to systematically investigate the difference.