# Lab 2 — Query Reference (Registry Persistence Detection)

---

## Attack Command

```
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Test /t REG_SZ /d "calc.exe"
```

### Expected Behavior

* Creates a Run key for persistence
* Value "Test" executes `calc.exe` at user logon

### Actual Result

* Registry key successfully created under HKCU Run
* `calc.exe` configured to execute on login

### Why this works

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` is a common persistence location
* Programs in this key automatically execute when the user logs in
* Frequently abused by malware for persistence

### When I’d use this

* Simulating registry-based persistence (MITRE ATT&CK T1547.001)
* Testing Sysmon Event ID 12/13 visibility
* Validating detection coverage for autorun keys

---

## Queries

### Query 1 — Field-Based (FAILED)

```
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=13
```

**Expected Result**

* Return Sysmon registry events (Event ID 13)

**Actual Result**

* No results returned

**Why this works**

* Assumes EventID/EventCode is a parsed field in Splunk

**When I’d use this**

* Environments with properly parsed Sysmon data

---

### Query 2 — Raw XML Search (WORKING)

```
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "EventID>13"
```

**Expected Result**

* Return Sysmon registry events

**Actual Result**

* Successfully returned events

**Why this works**

* Searches raw XML instead of relying on parsed fields

**When I’d use this**

* Environments with raw/unparsed log ingestion

---

## Detection 1 — Payload-Based

### Detection

Suspicious Persistence via Run Key (calc.exe)

### Query

```
index=main "calc.exe"
```

### Logic

* Searches for execution of `calc.exe`, which was configured via Run key persistence
* Correlates process activity with prior registry modification

### Why this works

* Persistence mechanisms often lead to execution of payloads at login
* Searching for the payload validates persistence behavior
* Useful pivot when registry events are not easily searchable

### When I’d use this

* Hunting for persistence tied to known payloads
* Validating whether persistence mechanisms successfully execute
* Pivoting from registry modification → process execution

### Note

* Initial detection relied on payload (`calc.exe`)
* Improved detection focuses on persistence behavior (Run key)

---

## Detection 2 — Behavior-Based (Improved)

### Query

```
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

### Purpose

* Detect registry-based persistence via Run key with full context

### Result

* Identified `reg.exe` writing `calc.exe` to Run key
* Captured user, process, persistence location, and payload

### Insight

* Behavior-based detection requires context (user + process + payload)
* Registry activity alone is insufficient without enrichment

---

## Troubleshooting

### Issue

Sysmon Event ID 13 not appearing in Splunk using field-based query

### What I expected

* Event ID 13 to be searchable using EventID/EventCode field

### What actually happened

* No results returned using structured query
* Event confirmed in Event Viewer

### Root Cause

* Sysmon logs ingested as raw XML without field extraction
* EventID/EventCode field not parsed

### Fix

* Switched to raw string search ("EventID>13")
* Used `xmlkv` and `rex` for field extraction

### Lesson Learned

* Must validate parsing before using field-based queries
* Raw search is required when fields are not extracted
* Behavior-based detection depends on proper data parsing

### Additional Insight

* Detection logic was valid; lack of results was due to no matching event in the selected time window
* Fresh telemetry must exist for behavior-based detections to return results

---
