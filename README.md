# Lab 2 - Detecting Registry Run Key Persistence with Sysmon and Splunk

## Overview

This lab demonstrates how to detect Windows registry-based persistence using Sysmon and Splunk. The objective was to simulate persistence through the Run key, verify telemetry generation on the endpoint, confirm ingestion into Splunk, troubleshoot parsing issues, and refine the detection from simple payload-based searches to a behavior-based query with context.

## Lab Environment

* Host Hypervisor: Hyper-V
* SIEM: Splunk Enterprise on Ubuntu
* Endpoint: Windows 11 VM
* Telemetry Source: Sysmon
* Log Forwarding: Splunk Universal Forwarder

## Goal

Detect registry persistence created through:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

and capture:

* the user responsible
* the process that made the change
* the registry path modified
* the payload written to the Run key

## Attack Simulation

### Command Used

```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Test5 /t REG_SZ /d "calc.exe"
```

### What It Does

This command creates a user-level Run key value that causes `calc.exe` to launch when the user logs in.

### MITRE ATT&CK

* T1547.001 - Registry Run Keys / Startup Folder

## Telemetry Validation

The simulated persistence generated:

* Sysmon Event ID 13 (Registry value set)

Validation path:

1. Confirmed the event in Event Viewer on the Windows VM
2. Confirmed the event was ingested into Splunk
3. Confirmed the event could be detected with increasingly refined queries

## Detection Evolution

### 1. Raw Telemetry Check

Initial search used to validate Sysmon registry events in Splunk:

```spl
index=main "EventID>13"
```

This worked because the data was initially being ingested as raw XML rather than fully parsed fields.

### 2. Payload-Based Detection

Initial detection pivot:

```spl
index=main "calc.exe"
```

This confirmed that the payload appeared in Splunk, but it was tied to a specific executable and not the persistence behavior itself.

### 3. Behavior-Based Detection with Context

Final detection query:

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| xmlkv
| search EventID=13
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex "<Data Name='TargetObject'>(?<TargetObject>[^<]+)</Data>"
| rex "<Data Name='Details'>(?<Details>[^<]+)</Data>"
| rex "<Data Name='User'>(?<User>[^<]+)</Data>"
| search TargetObject="*CurrentVersion\\Run*"
| table _time User Image TargetObject Details
```

### Why This Query Matters

This final query detects the persistence behavior rather than a single payload. It identifies:

* the user account involved
* the process responsible for writing the registry value
* the exact autorun location modified
* the payload configured to execute at logon

## Key Findings

* Raw XML ingestion can prevent direct field-based searching
* `EventID=13` did not initially work as expected because the fields were not fully searchable at base search time
* `xmlkv` extracted top-level XML fields such as `EventID`
* nested Sysmon `<Data Name="...">` values still required `rex` extraction
* behavior-based detection is stronger than payload-based detection
* a valid detection query can still return zero results when no fresh matching telemetry exists in the selected time range

## Troubleshooting

### Issue 1

**Problem:** `EventCode=13` / `EventID=13` searches initially returned no results

**Root Cause:** Sysmon logs were ingested as raw XML without fully searchable extracted fields

**Fix:** Validated events using raw string searches and then moved to `xmlkv` plus targeted `rex` extraction

**Lesson Learned:** Always verify whether data is parsed or raw before relying on field-based queries

### Issue 2

**Problem:** Final detection query returned zero results

**Root Cause:** No recent Run key persistence event existed within the selected time range

**Fix:** Re-ran the registry persistence command to generate fresh telemetry

**Lesson Learned:** A valid detection can return no results if no relevant activity exists in the search window

## Evidence Captured

Recommended screenshot set:

1. Sysmon Event Viewer - Event ID 13 on the endpoint
2. Splunk raw XML view showing Event ID 13 ingestion
3. Splunk payload pivot using `calc.exe`
4. Splunk noise-reduction view showing filtered Run key activity
5. Splunk final detection query showing user, process, target object, and payload

## Skills Demonstrated

* Windows registry persistence analysis
* Sysmon telemetry validation
* Splunk search and troubleshooting
* Search-time XML field extraction
* Detection tuning and noise reduction
* Behavior-based detection development
* Incident-style documentation

## Conclusion

This lab progressed from simple telemetry validation to a behavior-based persistence detection with investigation context. The most valuable part of the exercise was not just generating the event, but diagnosing why initial detection logic failed and refining the query based on how the data was actually parsed in Splunk.
