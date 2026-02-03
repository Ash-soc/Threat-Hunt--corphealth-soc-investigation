# 🛡 CorpHealth Operations Activity Review  
## SOC Investigation Report – Privileged Account Misuse Investigation  

**Host Investigated:** ch-ops-wks02  
**Platform:** Microsoft Defender for Endpoint (Advanced Hunting)  
**Analyst Role:** SOC Analyst (Internship Project)  
**Incident Classification:** Confirmed Security Incident  

---

## Table of Contents
- Introduction
- Scope & Data Sources
- Executive Summary
- Investigation Methodology
- Flag-Based Findings
- Visual Attack Chain
- MITRE ATT&CK Summary
- Lessons Learned
- Skills Demonstrated
- Final Assessment
- Conclusion

---

# Introduction

CorpHealth is an internal endpoint monitoring and maintenance framework designed to automate health checks, diagnostics, and post-patch validation across operational workstations. Dedicated operational accounts were provisioned with administrative privileges strictly for automation workflows and were not intended for interactive use.

In mid-November, off-hours telemetry from workstation `ch-ops-wks02` showed activity inconsistent with approved maintenance windows. Although initially categorized as operational activity, deeper analysis revealed behavioral patterns consistent with credential misuse and post-compromise activity.

This report documents the complete investigative sequence.

---

# Scope & Data Sources

The investigation was conducted using Microsoft Defender for Endpoint Advanced Hunting.

Telemetry reviewed included:

- DeviceLogonEvents  
- DeviceProcessEvents  
- DeviceFileEvents  
- DeviceRegistryEvents  
- DeviceNetworkEvents  
- DeviceEvents (Application logs)  

No live endpoint access was available. Findings are based solely on recorded telemetry.

---

# Executive Summary

Anomalous activity on `ch-ops-wks02` was investigated following off-hours telemetry deviations.

Analysis confirmed interactive misuse of a privileged operational account (`chadmin`) originating from external IP `104.164.168.17` (geolocated to Vietnam). Post-authentication activity included credential file access, enumeration commands, privilege token manipulation, Windows Defender exclusion modification, external tool download via ngrok tunnel, execution of an unsigned binary (`revshell.exe`), outbound TCP connection attempts to `13.228.171.119:11746`, and persistence via registry Run key and Startup folder placement.

The activity is inconsistent with CorpHealth automated maintenance workflows and meets the threshold for formal incident response escalation.

---

# Investigation Methodology

1. Identify earliest suspicious logon  
2. Trace post-logon process execution  
3. Review early file access  
4. Identify enumeration behavior  
5. Confirm privilege escalation indicators  
6. Detect defense evasion activity  
7. Track external tool transfer  
8. Validate persistence mechanisms  
9. Correlate network telemetry  
10. Map activity to MITRE ATT&CK  

All findings were validated through structured KQL queries.

---

# Flag-Based Findings

---

## 🚩 Flag 1 – Unique Maintenance Script

### 📌 Description  
A PowerShell maintenance script was identified on `ch-ops-wks02` that was not present across peer systems during baseline comparison.

### ✅ Answer  
Host-specific PowerShell maintenance script identified.

### ⚠️ Impact  
Deviation from standardized automation scripts demonstrates potential manual modification or misuse of privileged execution context.

```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where FileName endswith ".ps1"
```

---

## 🚩 Flag 2 – Outbound Beacon Initiation

### 📌 Description  
PowerShell initiated outbound network communication outside the approved maintenance window.

### ✅ Answer  
Outbound PowerShell-initiated network activity detected.

### ⚠️ Impact  
Unexpected external communication from privileged script execution indicates interactive misuse rather than automation.

```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessFileName =~ "powershell.exe"
```

---

## 🚩 Flag 3 – Beacon Destination

### 📌 Description  
Network telemetry revealed loopback connection attempts.

### ✅ Answer  
127.0.0.1:8080

### ⚠️ Impact  
Loopback relay behavior may indicate tunneling preparation or proxy staging.

---

## 🚩 Flag 4 – Successful Beacon Timestamp

### 📌 Description  
A successful outbound connection event was recorded.

### ✅ Answer  
2025-11-23T03:46:08.400686Z

### ⚠️ Impact  
Confirms outbound communication was fully operational at this point.

---

## 🚩 Flag 5 – Primary Staging Artifact

### 📌 Description  
A new inventory file was written to the CorpHealth diagnostics directory during the suspicious window.

### ✅ Answer  
C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv

### ⚠️ Impact  
Unexpected file staging indicates preparation for data manipulation or exfiltration.

---

## 🚩 Flag 6 – SHA256 of Staged File

### 📌 Description  
File metadata revealed cryptographic hash for validation.

### ✅ Answer  
7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8

### ⚠️ Impact  
Enables artifact validation and intelligence correlation.

---

## 🚩 Flag 7 – Duplicate Staging Artifact

### 📌 Description  
A second inventory-style file was observed in a separate directory.

### ✅ Answer  
Secondary inventory artifact created in alternate directory.

### ⚠️ Impact  
Demonstrates redundant staging behavior often associated with attacker testing.

---

## 🚩 Flag 8 – Registry Modification

### 📌 Description  
Registry modification events occurred near staging timeframe.

### ✅ Answer  
RegistryKeyCreated / RegistryValueSet events observed.

### ⚠️ Impact  
Unauthorized registry activity indicates configuration tampering.

---

## 🚩 Flag 9 – Scheduled Task Artifact

### 📌 Description  
Registry entries under TaskCache were created.

### ✅ Answer  
Scheduled task registry artifact created.

### ⚠️ Impact  
Provides recurring execution capability (persistence).

---

## 🚩 Flag 10 – Run Key Persistence

### 📌 Description  
Run key value was created and later deleted.

### ✅ Answer  
Transient Run key value created.

### ⚠️ Impact  
Indicates stealth persistence technique.

---

## 🚩 Flag 11 – Privilege Escalation Event

### 📌 Description  
Application log recorded elevated configuration adjustment.

### ✅ Answer  
2025-11-23T03:47:21.8529749Z

### ⚠️ Impact  
Confirms privilege escalation activity.

---

## 🚩 Flag 12 – Defender Exclusion Attempt

### 📌 Description  
PowerShell executed Add-MpPreference to modify Defender exclusions.

### ✅ Answer  
Defender exclusion modification detected.

### ⚠️ Impact  
Defense evasion technique to reduce detection.

---

## 🚩 Flag 13 – Encoded PowerShell Execution

### 📌 Description  
PowerShell executed with -EncodedCommand parameter.

### ✅ Answer  
Encoded command execution confirmed.

### ⚠️ Impact  
Obfuscation of script intent.

---

## 🚩 Flag 14 – Token Privilege Modification

### 📌 Description  
ProcessPrimaryTokenModified event recorded.

### ✅ Answer  
Process ID 4888

### ⚠️ Impact  
Privilege escalation via token manipulation.

---

## 🚩 Flag 15 – Modified SID

### 📌 Description  
Security identifier associated with modified token extracted.

### ✅ Answer  
S-1-5-21-1605642021-30596605-784192815-1000

### ⚠️ Impact  
Identifies affected security principal.

---

## 🚩 Flag 16 – Executable Written

### 📌 Description  
New executable written to disk post-escalation.

### ✅ Answer  
revshell.exe

### ⚠️ Impact  
Marks introduction of attacker tooling.

---

## 🚩 Flag 17 – Download Source

### 📌 Description  
Executable retrieved via ngrok tunnel domain.

### ✅ Answer  
https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe

### ⚠️ Impact  
External dynamic tunnel infrastructure used.

---

## 🚩 Flag 18 – Binary Execution

### 📌 Description  
Downloaded executable was executed.

### ✅ Answer  
revshell.exe executed

### ⚠️ Impact  
Transition from staging to active tooling.

---

## 🚩 Flag 19 – Outbound C2 Attempt

### 📌 Description  
Executable attempted TCP communication to external host.

### ✅ Answer  
13.228.171.119:11746

### ⚠️ Impact  
Reverse-shell style communication attempt.

---

## 🚩 Flag 20 – Startup Folder Persistence

### 📌 Description  
Executable copied into Startup directory.

### ✅ Answer  
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\

### ⚠️ Impact  
Ensures execution at user logon.

---

## 🚩 Flag 21 – Remote Session Label

### 📌 Description  
Remote session metadata identified session label.

### ✅ Answer  
对手

---

## 🚩 Flag 22 – Remote Session IP

### 📌 Description  
Remote session IP extracted.

### ✅ Answer  
100.64.100.6

---

## 🚩 Flag 23 – Internal Pivot Host

### 📌 Description  
Internal IP observed within session metadata.

### ✅ Answer  
10.168.0.6

---

## 🚩 Flag 24 – Earliest Suspicious Logon

### 📌 Description  
Earliest interactive logon identified.

### ✅ Answer  
2025-11-23T03:08:31.1849379Z

---

## 🚩 Flag 25 – Source IP of First Logon

### 📌 Description  
Remote IP associated with first suspicious logon extracted.

### ✅ Answer  
104.164.168.17

---

## 🚩 Flag 26 – Account Used

### 📌 Description  
Account involved in earliest suspicious logon identified.

### ✅ Answer  
chadmin

---

## 🚩 Flag 27 – Geographic Origin

### 📌 Description  
IP geolocation enrichment performed.

### ✅ Answer  
Vietnam

---

## 🚩 Flag 28 – First Process After Logon

### 📌 Description  
First process executed post-authentication.

### ✅ Answer  
explorer.exe

---

## 🚩 Flag 29 – First File Accessed

### 📌 Description  
First file opened after authentication identified.

### ✅ Answer  
CH-OPS-WKS02 user-pass.txt

---

## 🚩 Flag 30 – Enumeration Activity

### 📌 Description  
System and account discovery commands executed.

### ✅ Answer  
ipconfig, whoami, net user

---

## 🚩 Flag 31 – Secondary Account Accessed

### 📌 Description  
Following enumeration, an additional account was accessed.

### ✅ Answer  
ops.maintenance

---

# Visual Attack Chain

Remote Logon (chadmin - 104.164.168.17)  
↓  
Explorer.exe Interactive Session  
↓  
Credential File Access  
↓  
Enumeration  
↓  
Privilege Escalation  
↓  
Defender Exclusion  
↓  
Tool Download (ngrok → revshell.exe)  
↓  
Execution  
↓  
Outbound Attempt (13.228.171.119:11746)  
↓  
Persistence  

---

# MITRE ATT&CK Summary

| Tactic | Technique | ID |
|--------|------------|-----|
| Initial Access | Valid Accounts | T1078 |
| Execution | PowerShell | T1059.001 |
| Discovery | System Discovery | T1082 |
| Privilege Escalation | Token Manipulation | T1134 |
| Defense Evasion | Modify Security Tools | T1562.001 |
| Command & Control | Application Layer Protocol | T1071 |
| Persistence | Run Key / Startup Folder | T1547.001 |

---

# Lessons Learned

- Privileged automation accounts must be monitored for interactive usage.
- Early file access can reveal attacker objectives.
- Token modification events are strong escalation indicators.
- Defender exclusion commands require immediate review.
- Dynamic tunnel domains represent elevated risk.
- Persistence mechanisms typically follow successful execution.

---

# Skills Demonstrated

- Advanced Hunting (KQL)
- Cross-table telemetry correlation
- Authentication and privilege analysis
- Defense evasion detection
- Command-and-control identification
- Persistence mechanism analysis
- Timeline reconstruction
- MITRE ATT&CK mapping
- Structured SOC escalation reporting

---

# Final Assessment

Telemetry analysis confirms interactive misuse of privileged credentials, execution of unauthorized tooling, defense evasion activity, and persistence establishment.

The activity does not align with CorpHealth automation baselines and represents a confirmed security incident.

Containment, credential reset, and endpoint isolation would be recommended in a production environment.

---

# Conclusion

Structured telemetry correlation and behavioral analysis validated suspicious post-compromise activity on `ch-ops-wks02`. What initially appeared as operational maintenance was confirmed as interactive credential misuse through systematic investigation.

---
