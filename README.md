# 🛡️ CorpHealth Security Incident Investigation

**Investigation ID:** CH-OPS-2025-11  
**Platform:** Microsoft Defender for Endpoint  
**Analyst:** Hope Elum  
---

## 📋 Table of Contents

1. [ Executive Summary](#-executive-summary)  
   - [What Happened?](#what-happened)  
2. [ Incident Overview](#-incident-overview)  
   - [The Alert That Started Everything](#the-alert-that-started-everything)    
3. [ How I Approached This](#-how-i-approached-this)  
   - [Investigation Methodology](#investigation-methodology)  
   - [How Flags Work](#how-flags-work)  
4. [ The Flags - Step by Step](#-the-flags---step-by-step)  
   - [Phase 1: Initial Investigation (Flags 0-3)](#phase-1-initial-investigation-flags-0-3)  
   - [Phase 2: Discovery & Staging (Flags 4-10)](#phase-2-discovery--staging-flags-4-10)  
   - [Phase 3: Privilege Escalation (Flags 11-15)](#phase-3-privilege-escalation-flags-11-15)  
   - [Phase 4: Payload Delivery (Flags 16-20)](#phase-4-payload-delivery-flags-16-20)  
   - [Phase 5: Attribution & Timeline (Flags 21-31)](#phase-5-attribution--timeline-flags-21-31)  
5. [ Attack Timeline](#-attack-timeline)  
6. [MITRE ATT&CK](#mitre-attck)  
   - [Attack Techniques by Category](#attack-techniques-by-category)  
7. [ All the Bad Stuff I Found (IOCs)](#-all-the-bad-stuff-i-found-iocs)  
   - [Top 10 Indicators of Compromise](#top-10-indicators-of-compromise)  
8. [ What I Learned](#-what-i-learned)  
   - [Technical Skills I Gained](#technical-skills-i-gained)  
   - [Security Gaps Identified](#security-gaps-identified)  
9. [ Final Assessment](#final-assessment)  
10. [ Final Thoughts](#-final-thoughts)  
    - [What Made This a Real Incident](#what-made-this-a-real-incident)  
11. [ Resources](#-resources)  
    - [Tools I Used](#tools-i-used)  
    - [Where to Learn More](#where-to-learn-more)  

---

## 🎯 Executive Summary

### What Happened?

On 23 November 2025 at 03:08 UTC, Microsoft Defender for Endpoint generated an alert indicating an interactive Remote Desktop login for service account **chadmin**. Service accounts are not authorized for interactive logon.

Investigation confirmed unauthorized access originating from a foreign IP address (Vietnam), followed by credential harvesting, privilege escalation, defense evasion, malware deployment, command-and-control (C2) communication, and lateral movement to a secondary user account.

Total observed dwell time: 7 days, 23 hours.

The activity constitutes a confirmed security breach requiring full incident response procedures.

---

## 🎬 Incident Overview

### The Alert That Started Everything

Initial Alert:
Suspicious interactive logon for service account

Affected Device:
`ch-ops-wks02`

Initial Compromised Account:
`chadmin`

Source IP Address:
`104.164.168.17 (Vietnam)`

Secondary Compromised Account:
`ops.maintenance`

---

## 🔧 How I Approached This


### Investigation Methodology

Telemetry analysis was conducted using Kusto Query Language (KQL) within Microsoft Defender for Endpoint across:

**The Tables I Searched:**

- **DeviceLogonEvents** - Who logged in, from where
- **DeviceProcessEvents** - What programs ran
- **DeviceFileEvents** - What files were created/opened
- **DeviceRegistryEvents** - Changes to Windows settings
- **DeviceNetworkEvents** - Network connections
- **DeviceEvents** - Special security events

Events were correlated chronologically to reconstruct attacker activity and determine attack chain progression.

### How Flags Work

I turned this investigation into a **32-flag challenge** to make it easier to follow. Each flag is a specific answer I had to find by running queries.

**Flag Categories:**

- 🟢 **Flags 0-10:** Basic - Finding the computer, files, and first connections
- 🟡 **Flags 11-20:** Intermediate - Discovering how they hid and persisted
- 🔴 **Flags 21-31:** Advanced - Figuring out who they are and what they did


## 🚩 The Flags - Step by Step

## Phase 1: Initial Investigation (Flags 0-3)

### 🚩 Flag 0: Which computer is involved?

**Question:** What device am I investigating?

**My Query:**
```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| summarize Events=count() by DeviceName
```
---

**Answer:** `ch-ops-wks02`

**What This Means:**
Confirmed the device exists in our logs and has activity to investigate.

---

### 🚩 Flag 1: What suspicious script keeps appearing?

**Question:** Is there a PowerShell script that looks suspicious?

**My Query:**

```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where FolderPath has @"C:\ProgramData\Corp\Ops\"
| where FileName endswith ".ps1"
| project Timestamp, FileName
| order by Timestamp asc
```

**Answer:** `MaintenanceRunner_Distributed.ps1`

**What This Means:**
PowerShell scripts in `ProgramData` are suspicious. Legitimate scripts are usually in `Program Files`. The name "MaintenanceRunner" is trying to look legitimate, but it's actually malware.

**Red Flags:**

* ⚠️ Created 4 minutes after suspicious login
* ⚠️ Name designed to blend in
* ⚠️ "Distributed" suggests it might be on multiple computers

---

### 🚩 Flag 2: When did it first try to "phone home"?

**Question:** When did this script try to connect to the internet?

**My Query:**

```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project Timestamp, RemoteIP, RemotePort
| order by Timestamp asc
| take 1
```

**Answer:** `2025-11-23T03:46:08.400686Z`

**What This Means:**
38 minutes after the initial login, the script tried to connect somewhere. This is called "beaconing" - like the malware calling home to say "I'm here!"

---

### 🚩 Flag 3: Where did it try to connect?

**Question:** What IP and port did it connect to?

**My Query:**

```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project RemoteIP, RemotePort
| take 1
```

**Answer:** `127.0.0.1:8080`

**What This Means:**
`127.0.0.1` is the computer talking to itself (localhost). The attacker was probably:

* Testing their connection setup
* Setting up a tunnel to hide their real server
* Making sure everything worked before connecting to the real command server

---

## Phase 2: Discovery & Staging (Flags 4-10)

![Malware Analysis Process](https://glimps.re/assets/cti-malware-analysis.png)

### 🚩 Flag 4: When did the connection actually work?

**Question:** When was the first SUCCESSFUL connection?

**My Query:**

```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where ActionType == "ConnectionSuccess"
| where RemoteIP == "127.0.0.1" and RemotePort == 8080
| project Timestamp
| order by Timestamp asc
| take 1
```

**Answer:** `2025-11-30T01:03:17.6985973Z`

**What This Means:**
This was **7 days later**! The attacker kept access for a whole week, testing and preparing. This is called "dwell time" - how long they stay hidden.

---

### 🚩 Flag 5: What file did they create for reconnaissance?

**Question:** What CSV file appeared after they started connecting?

**My Query:**

```kql
let beaconTime = todatetime("2025-11-23T03:46:08.400686Z");
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp >= beaconTime
| where FolderPath has @"C:\ProgramData\Microsoft\Diagnostics\CorpHealth\"
| where FileName endswith ".csv"
| project Timestamp, FileName
| order by Timestamp asc
| take 1
```

**Answer:** `inventory_6ECFD4DF.csv`

**What This Means:**
CSV files are often used to store lists of data. This probably contains:

* Computer name
* Installed programs
* User accounts
* Network information

The hex code `6ECFD4DF` might be a tracking ID for the victim.

---

### 🚩 Flag 6: What's the file hash?

**Question:** What's the SHA-256 hash so I can search for this file on other computers?

**My Query:**

```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where FileName == "inventory_6ECFD4DF.csv"
| project SHA256
| take 1
```

**Answer:** `7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8`

**What This Means:**
File hashes are like fingerprints for files. Now I can search our entire network:

```kql
DeviceFileEvents
| where SHA256 == "7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8"
| summarize Devices=make_set(DeviceName)
```

✅ **Good news:** Only found on this one computer (no spread).

---

### 🚩 Flag 7: Did they copy this file somewhere else?

**Question:** Was the inventory file duplicated?

**My Query:**

```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where FileName contains "inventory"
| where FolderPath has @"Temp\CorpHealth"
| project Timestamp, FolderPath, FileName
| order by Timestamp asc
```

**Answer:** `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`

**What This Means:**
🚨 **BIG DISCOVERY!** The file moved to a **different user's folder** (`ops.maintenance`). This means:

1. The attacker got into a second account
2. They're preparing to move data around
3. The incident is bigger than I initially thought

---

### 🚩 Flag 8: What suspicious registry changes happened?

**Question:** Did they create any weird registry entries?

**My Query:**

```kql
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where RegistryKey has "CorpHealthAgent"
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
| project Timestamp, RegistryKey
| order by Timestamp asc
```

**Answer:** `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`

**What This Means:**
They created a fake event log source. This could:

* Make their activity look legitimate in logs
* Flood logs with fake entries to hide real attacks
* Set up for a Windows service

---

### 🚩 Flag 9: Did they create a scheduled task?

**Question:** Is there a scheduled task for persistence?

**My Query:**

```kql
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where RegistryKey has @"Schedule\TaskCache\Tree\"
| where RegistryKey has "CorpHealth"
| project RegistryKey
| take 1
```

**Answer:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64`

**What This Means:**
**Scheduled tasks** run programs at specific times (like every startup). This is **persistence mechanism #1** - even if we restart the computer, their malware will run again.

---

### 🚩 Flag 10: What Run key did they create?

**Question:** Did they add a registry Run key?

**My Query:**

```kql
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Run"
| where ActionType == "RegistryValueSet"
| project RegistryValueName, RegistryValueData
```

**Answer:** `MaintenanceRunner`

**What This Means:**
**Run keys** make programs start when a user logs in. This is **persistence mechanism #2**. Now they have TWO ways to stay in the system!

---

## Phase 3: Privilege Escalation (Flags 11-15)

![Windows Privilege Escalation Techniques](https://i.pinimg.com/originals/16/5c/93/165c93f18e08ece08e76c22b5a2b7a76.jpg)

### 🚩 Flag 11: When did they try to get more privileges?

**Question:** When did privilege escalation happen?

**My Query:**

```kql
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where AdditionalFields has "ConfigAdjust"
| project Timestamp
| order by Timestamp asc
| take 1
```

**Answer:** `2025-11-23T03:47:21.8529749Z`

**What This Means:**
Only **1 minute** after the first beacon! The timeline looks like:

```
03:08 - Login
03:46 - First beacon
03:47 - Privilege escalation ← Super fast!
```

This rapid sequence suggests **automated tools** (like Metasploit or Cobalt Strike) rather than manual typing.

---

### 🚩 Flag 12: What directory did they exclude from antivirus?

**Question:** Did they try to disable Windows Defender scanning?

**My Query:**

```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where ProcessCommandLine has "Add-MpPreference"
| where ProcessCommandLine has "ExclusionPath"
| project ProcessCommandLine
```

**Answer:** `C:\ProgramData\Corp\Ops\staging`

**What This Means:**
🚨 **CRITICAL:** They told Windows Defender "don't scan this folder." Now they can download malware there without getting caught!

**How I know it's malicious:**

* ✅ Real admins use Group Policy (centralized), not command line
* ✅ Happened during an active RDP session
* ✅ No change management ticket

---

### 🚩 Flag 13: What was hidden in the encoded PowerShell?

**Question:** What did the Base64-encoded command actually say?

**My Query:**

```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where ProcessCommandLine contains "-EncodedCommand"
| extend Encoded = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Encoded)
| project Decoded
| take 1
```

**Answer:** `Write-Output 'token-6D5E4EE08227'`

**What This Means:**
Base64 encoding is used to hide commands. When decoded, it's just printing a token. This is probably:

* A confirmation code ("hey, I successfully ran on this computer!")
* A tracking ID for their attack campaign
* A key to unlock the next stage of the attack

---

### 🚩 Flag 14: What process did the token manipulation?

**Question:** Which process ID modified security tokens?

**My Query:**

```kql
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where AdditionalFields has "tokenChangeDescription"
| project InitiatingProcessId
| take 1
```

**Answer:** `4888`

**What This Means:**
**Token manipulation** is a technique where you "steal" permissions from another program. Think of it like borrowing someone else's ID badge to access restricted areas.

Process ID 4888 was PowerShell doing this privilege theft.

---

### 🚩 Flag 15: Whose token did they steal?

**Question:** Which user's security token was targeted?

**My Query:**

```kql
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessId == 4888
| where AdditionalFields has "tokenChangeDescription"
| extend AF = parse_json(AdditionalFields)
| extend Props = parse_json(tostring(AF.TokenModificationProperties))
| project tostring(Props.OriginalTokenUserSid)
| take 1
```

**Answer:** `S-1-5-21-1605642021-30596605-784192815-1000`

**What This Means:**
This is a **SID (Security Identifier)** - a unique ID for a Windows user. I can look up whose account this is:

```kql
DeviceProcessEvents
| where AccountSid == "S-1-5-21-1605642021-30596605-784192815-1000"
| distinct AccountName
```

This belonged to a **local administrator account**, giving the attacker full control of the computer.

---

## Phase 4: Payload Delivery (Flags 16-20)

![Command and Control Server Architecture](https://www.paladion.net/hubfs/What%20is%20Command%20and%20Control%28C2%29%20Server%20%E2%80%93%20A%20Detailed%20Overview-01.jpg)

### 🚩 Flag 16: What malware did they download?

**Question:** What executable file appeared?

**My Query:**

```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where FileName endswith ".exe"
| where ActionType == "FileCreated"
| project FileName, FolderPath
| order by Timestamp asc
```

**Answer:** `revshell.exe`

**What This Means:**
"revshell" = **reverse shell**. This is malware that gives the attacker remote control. The file appeared in the Defender-excluded folder (`staging`) so it wouldn't get caught.

---

### 🚩 Flag 17: Where did they download it from?

**Question:** What URL was used to download the malware?

**My Query:**

```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where FileName =~ "curl.exe"
| where ProcessCommandLine has "revshell.exe"
| project ProcessCommandLine
```

**Answer:** `https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe`

**What This Means:**
**ngrok** is a legitimate service that creates tunnels to the internet. Attackers abuse it to:

* Hide their real server location
* Bypass firewalls (HTTPS looks normal)
* Quickly change domains if blocked

The random subdomain (`unresuscitating-donnette-smothery`) is auto-generated by ngrok's free tier.

---

### 🚩 Flag 18: How did they run the malware?

**Question:** What program launched revshell.exe?

**My Query:**

```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where FileName =~ "revshell.exe"
| project InitiatingProcessFileName
| take 1
```

**Answer:** `explorer.exe`

**What This Means:**
**Explorer.exe** (Windows File Explorer) means they **double-clicked** the file manually. This confirms:

* Human attacker (not automated malware)
* They were using the GUI desktop session
* They're comfortable with basic Windows operations

---

### 🚩 Flag 19: What server did they connect to?

**Question:** What IP and port did the reverse shell connect to?

**My Query:**

```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where RemotePort == 11746
| project RemoteIP, RemotePort
| take 1
```

**Answer:** `13.228.171.119:11746`

**What This Means:**
This is their **command and control (C2) server**. I looked it up:

* **Location:** Singapore
* **Hosting:** Amazon AWS
* **Port:** 11746 (non-standard - custom malware)

The attacker is now connected to this server and can send commands remotely.

---

### 🚩 Flag 20: Where else did they achieve persistence?

**Question:** What Startup folder entry did they create?

**My Query:**

```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where FolderPath has @"Start Menu\Programs\StartUp"
| project FolderPath, FileName
```

**Answer:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`

**What This Means:**
Files in the **Startup folder** run automatically when Windows starts. This is **persistence mechanism #3**!

**Complete Persistence Summary:**

1. ✅ Scheduled Task (runs at system startup)
2. ✅ Registry Run Key (runs at user login)
3. ✅ Startup Folder (runs at user login)

They have THREE backup plans to stay in the system. Very determined!

---

## Phase 5: Attribution & Timeline (Flags 21-31)

### 🚩 Flag 21: What was the attacker's computer name?

**Question:** What hostname did the attacker's machine use?

**My Query:**

```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where isnotempty(InitiatingProcessRemoteSessionDeviceName)
| summarize count() by InitiatingProcessRemoteSessionDeviceName
```

**Answer:** `对手`

**What This Means:**
`对手` is Chinese for **"adversary"** or **"opponent"**. This was deliberately chosen (not a default name like `DESKTOP-ABC123`).

**Possible interpretations:**

* Attacker speaks Chinese
* Using Chinese-language Windows
* Intentional false flag to mislead investigators

---

### 🚩 Flag 22: What IP did the remote session use?

**Question:** What IP was in the remote session metadata?

**My Query:**

```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessRemoteSessionDeviceName == "对手"
| distinct InitiatingProcessRemoteSessionIP
```

**Answer:** `100.64.100.6`

**What This Means:**
This is a **CGNAT address** (Carrier-Grade NAT). ISPs use these for multiple customers. It means:

* Hard to trace to specific person
* Likely home internet or VPN
* Shared by many users

---

### 🚩 Flag 23: Did they pivot through an internal computer?

**Question:** What internal IP appears in the remote session?

**My Query:**

```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| where InitiatingProcessRemoteSessionIP startswith "10."
| distinct InitiatingProcessRemoteSessionIP
```

**Answer:** `10.168.0.7`

**What This Means:**
🚨 **CRITICAL FINDING!** This is an **internal IP** (10.x.x.x addresses are private). Either:

1. They hacked `10.168.0.7` first, then used it to attack this computer
2. They're using it as a proxy/jump host

**This doubles the investigation scope** - I need to check that computer too!

---

### 🚩 Flag 24: When was the very first login?

**Question:** When did the attacker first gain access?

**My Query:**

```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where ActionType == "LogonSuccess"
| where RemoteDeviceName == "对手"
| order by Timestamp asc
| take 1
| project Timestamp
```

**Answer:** `2025-11-23T03:08:31.1849379Z`

**What This Means:**
This is my **anchor timestamp** - everything started here. Now I can build the complete timeline:

```
03:08:31 - First login ← START HERE
03:10:30 - Password file accessed
03:46:08 - First beacon
03:47:21 - Privilege escalation
04:15:32 - Malware downloaded
[... 7 days ...]
```

---

### 🚩 Flag 25: What IP did they log in from?

**Question:** What was the source IP for the first login?

**My Query:**

```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp == todatetime("2025-11-23T03:08:31.1849379Z")
| project RemoteIP
```

**Answer:** `104.164.168.17`

**What This Means:**
This IP is from **Vietnam**. I checked:

* No business operations in Vietnam ❌
* No employees working from Vietnam ❌
* No approved VPN connections ❌

**Verdict:** 100% unauthorized access.

---

### 🚩 Flag 26: What account did they use first?

**Question:** Which account authenticated initially?

**My Query:**

```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp == todatetime("2025-11-23T03:08:31.1849379Z")
| project AccountName
```

**Answer:** `chadmin`

**What This Means:**
**chadmin** is a **service account** for automated tasks. It should:

* ✅ Only run scheduled tasks (2:00 AM daily)
* ❌ NEVER log in via RDP

This login violated our security policy.

---

### 🚩 Flag 27: Where is the attacker located?

**Question:** What country did the attack come from?

**My Query:**

```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where RemoteIP == "104.164.168.17"
| extend GeoInfo = geo_info_from_ip_address(RemoteIP)
| project GeoInfo.country
```

**Answer:** `Vietnam`

**What This Means:**
Combined with the Chinese hostname, this suggests:

* Southeast Asian attacker
* Possibly using VPN to obscure real location
* Could be false flag attribution

---

### 🚩 Flag 28: What was the first thing they did after logging in?

**Question:** What program ran first after authentication?

**My Query:**

```kql
let loginTime = todatetime("2025-11-23T03:08:31.1849379Z");
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp >= loginTime
| where InitiatingProcessRemoteSessionDeviceName == "对手"
| project Timestamp, FileName
| order by Timestamp asc
| take 1
```

**Answer:** `explorer.exe`

**What This Means:**
**Explorer.exe** = Windows File Explorer. They opened the graphical interface to:

* Browse folders visually
* Look for interesting files
* Navigate like a normal user

This is a human operator, not automated malware.

---

### 🚩 Flag 29: What file did they access first?

**Question:** What was the first file they opened?

**My Query:**

```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where ActionType == "FileOpened"
| where FileName has "user-pass"
| project Timestamp, FileName, FolderPath
| order by Timestamp asc
| take 1
```

**Answer:** `CH-OPS-WKS02 user-pass.txt`

**What This Means:**
🚨 **DISASTER:** A plaintext password file! This probably contained:

* Multiple username:password pairs
* Possibly admin credentials
* Login info for various systems

**Accessed only 2 minutes after login** - they knew exactly what to look for.

---

### 🚩 Flag 30: What command ran after reading the password file?

**Question:** What did they do right after accessing credentials?

**My Query:**

```kql
let fileAccessTime = todatetime("2025-11-23T03:10:30Z");
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp >= fileAccessTime
| where AccountName == "chadmin"
| project Timestamp, FileName
| order by Timestamp asc
| take 1
```

**Answer:** `ipconfig.exe`

**What This Means:**
Classic **reconnaissance**. They ran commands to learn about the network:

```
ipconfig    → Network configuration
whoami      → What are my privileges?
net user    → What accounts exist?
systeminfo  → What OS version?
```

This is standard attacker playbook - map the environment before moving laterally.

---

### 🚩 Flag 31: What account did they pivot to?

**Question:** What was the second account they compromised?

**My Query:**

```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where ActionType == "LogonSuccess"
| where RemoteDeviceName == "对手"
| where AccountName != "chadmin"
| project Timestamp, AccountName
| order by Timestamp asc
| take 1
```

**Answer:** `ops.maintenance`

**What This Means:**
They successfully **pivoted** to a second account using the stolen credentials!

**Attack Chain:**

```
1. Nov 23 03:08 - Login as chadmin
2. Nov 23 03:10 - Steal passwords from user-pass.txt
3. Nov 25 08:42 - Login as ops.maintenance ← 2 days later!
```

The 2-day delay suggests patience and planning.

---

## 📊 Attack Timeline

23 Nov 2025 – Day 1
- 03:08 – Interactive RDP login (chadmin) from Vietnam
- 03:10 – Access to plaintext credential file
- 03:46 – Initial beacon attempt
- 03:47 – Privilege escalation detected
- 03:47 – Microsoft Defender exclusion created
- 04:15 – Reverse shell downloaded via ngrok domain
- 04:16 – Outbound C2 connection establishe
- 04:22 – Persistence mechanism added (Startup folder)

25 Nov 2025 – Day 3
  
- Secondary account login (ops.maintenance)
- File duplication to secondary user profile

30 Nov 2025 – Day 8
  
- Final observed successful localhost beacon
- Last outbound C2 communication

Total dwell time: 7 days, 23 hours, 39 minutes.


---
<a id="mitre-attck"></a>
## 🗺️ MITRE ATT&CK

### Attack Techniques by Category

| **Tactic**               | **Technique**                    | **What They Did**                     | **Flag** |
| ------------------------ | -------------------------------- | ------------------------------------- | -------- |
| **Initial Access**       | Valid Accounts (T1078)           | Logged in as chadmin from Vietnam     | 24-26    |
| **Execution**            | PowerShell (T1059.001)           | Ran MaintenanceRunner_Distributed.ps1 | 1, 13    |
| **Execution**            | User Execution (T1204.002)       | Double-clicked revshell.exe           | 18       |
| **Persistence**          | Scheduled Task (T1053.005)       | Created CorpHealth_A65E64 task        | 9        |
| **Persistence**          | Registry Run Keys (T1547.001)    | Added MaintenanceRunner Run key       | 10       |
| **Persistence**          | Startup Folder (T1547.001)       | Placed file in Startup folder         | 20       |
| **Privilege Escalation** | Token Manipulation (T1134)       | Stole admin token from process 4888   | 14-15    |
| **Defense Evasion**      | Impair Defenses (T1562.001)      | Created Defender exclusion            | 12       |
| **Defense Evasion**      | Obfuscation (T1027)              | Base64-encoded PowerShell             | 13       |
| **Credential Access**    | Credentials in Files (T1552.001) | Accessed user-pass.txt                | 29       |
| **Discovery**            | System Info Discovery (T1082)    | Ran ipconfig, systeminfo              | 30       |
| **Lateral Movement**     | Valid Accounts (T1078.003)       | Pivoted to ops.maintenance            | 31       |
| **Collection**           | Data from Local System (T1005)   | Created inventory CSV                 | 5-7      |
| **Command & Control**    | Web Protocols (T1071.001)        | Connected to C2 server                | 19       |
| **Command & Control**    | Internal Proxy (T1090.001)       | Used 10.168.0.7 as pivot              | 23       |

---

## 🎯 All the Bad Stuff I Found (IOCs)

### Top 10 Indicators of Compromise

| **Type**       | **Value**                         | **What It Is**                   | **Action**               |
| -------------- | --------------------------------- | -------------------------------- | ------------------------ |
| 🌐 IP          | 104.164.168.17                    | Initial login from Vietnam       | Block at firewall        |
| 🌐 IP          | 13.228.171.119                    | C2 server in Singapore           | Block at firewall        |
| 🌐 Domain      | *.ngrok-free.dev                  | Malware download site            | Block at DNS             |
| 🌐 Internal IP | 10.168.0.7                        | Pivot host (needs investigation) | Investigate now          |
| 📄 File        | revshell.exe                      | Reverse shell malware            | Delete + quarantine      |
| 📄 File        | MaintenanceRunner_Distributed.ps1 | Malicious PowerShell             | Delete                   |
| 🔐 Hash        | 7f639356...39f12d8                | inventory CSV hash               | Hunt across network      |
| 📝 Registry    | CorpHealth_A65E64                 | Scheduled task                   | Delete task              |
| 👤 Account     | chadmin                           | Compromised service account      | Disable + reset password |
| 👤 Account     | ops.maintenance                   | Compromised user account         | Disable + reset password |

---

## 📚 What I Learned

### Technical Skills I Gained

**KQL Queries:**

* Started with basic single-table lookups
* Progressed to multi-table joins
* Learned to decode Base64
* Parsed JSON in event logs
* Built complex correlations

**Investigation Process:**

* How to build timelines from events
* Connecting evidence across different log sources
* Distinguishing automated tools from manual attacks
* Recognizing persistence techniques

**Security Concepts:**

* MITRE ATT&CK framework
* Indicators of Compromise (IOCs)
* Lateral movement
* Privilege escalation
* Defense evasion techniques

---

## Security Gaps Identified

### Problems

- ❌ Service accounts permitted interactive RDP logon
- ❌ Plaintext credentials stored locally (47 identified)
- ❌ Privileged accounts not protected by MFA
- ❌ Local users able to modify Microsoft Defender exclusions
- ❌ No alerting for Base64-encoded PowerShell execution
- ❌ Workstation-to-workstation RDP enabled

### Solutions

 Immediate:
- ✅Disable and reset compromised accounts
- ✅Remove persistence mechanisms
- ✅Block identified IPs and domains
- ✅Investigate pivot host 10.168.0.7

 Short-Term:
- ✅Enforce MFA on all privileged accounts
- ✅Deny interactive logon rights for service accounts
- ✅Restrict Defender configuration via Group Policy
- ✅Remove plaintext credential storage

Long-Term:
- ✅Implement workstation network segmentation
- ✅Deploy detection rules for encoded PowerShell
- ✅Conduct privileged access review
- ✅Perform organization-wide credential rotation


---

##  Final Assessment

Telemetry confirms structured adversary activity involving:

Unauthorized privileged access
- Credential harvesting
- Privilege escalation
- Defense evasion
- External payload transfer
- C2 communication
- Persistence establishment
- Account pivoting

The behavior is not consistent with normal operational baselines.

This incident qualifies as a confirmed security breach and warrants formal incident response escalation.
---

## 🎓 Final Thoughts

### What Made This a Real Incident

This wasn't just an alert - it was a confirmed compromise:

**✅ Clear Evidence:**
- Service account governance must be strictly enforced
- Privileged account protection (MFA) is mandatory
- Credential hygiene must be continuously monitored
- Endpoint configuration controls must be centrally managed
- Detection engineering must account for obfuscated PowerShell usage

---

## 📎 Resources

### Tools I Used

* **Microsoft Defender for Endpoint** - Main investigation platform
* **KQL** - Query language for searching logs
* **MITRE ATT&CK Navigator** - Mapping attack techniques
* **VirusTotal** - Checking file hashes and IPs

### Where to Learn More

**KQL Learning:**

* [Microsoft KQL Tutorial](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
* [KQL Quick Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)

**MITRE ATT&CK:**

* [ATT&CK Framework](https://attack.mitre.org/)
* [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

**Incident Response:**

* [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)

---

**Tags:** `threat-hunting` `kql` `microsoft-defender` `mitre-attack` `soc-analyst` `incident-response` `cybersecurity` `detection-engineering` `security-operations`

---

*Investigation completed by Hope Elum | CH-OPS-2025-11*
