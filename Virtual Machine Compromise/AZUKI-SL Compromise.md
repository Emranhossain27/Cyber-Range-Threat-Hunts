# Threat Hunt Report — AZUKI-SL Compromise (Full Investigation)

**Date Range Investigated:** 2025-11-19 → 2025-11-20  
**Endpoint:** AZUKI-SL (IT Administrator Workstation)  
**Data Source:** Microsoft Defender for Endpoint  

**Incident Summary:**  
Complete intrusion lifecycle observed involving initial access, reconnaissance, staging, credential theft, persistence mechanisms, command-and-control communications, data exfiltration, anti-forensics activity, and attempted lateral movement.

---

## 1. Key Findings (High-Level) With MITRE ATT&CK Techniques

| Category | Evidence (From Logs) | MITRE ATT&CK Technique |
|---------|-----------------------|-------------------------|
| Initial Access | RDP login using stolen account `kenji.sato` from `88.97.178.12` | T1078 – Valid Accounts<br>T1021.001 – Remote Desktop Protocol |
| Reconnaissance | Network scan using `arp.exe - a` | T1016 – System Network Discovery |
| Staging | Hidden directory created using `attrib.exe` | T1564.001 – Hidden Files & Directories |
| Defender Evasion | File-extension exclusions + Temp path excluded | T1562.001 – Impair Defenses |
| Malware Delivery | `certutil.exe` used to download payloads | T1105 – Ingress Tool Transfer<br>T1218.010 – Certutil Execution |
| Credential Dumping | `mm.exe` Mimikatz executing `sekurlsa::logonpasswords` | T1003.001 – LSASS Credential Dumping |
| Persistence | Scheduled task Windows Update Check running malicious `svchost.exe` | T1053.005 – Scheduled Task |
| Command & Control | C2 connection to `78.141.196.6` over port 443 | T1071.001 – Web Protocols |
| Data Exfiltration | `export-data.zip` exfiltrated to Discord | T1567.002 – Exfiltration to Cloud Services |
| Anti-Forensics | Security event logs cleared using `wevtutil.exe` | T1070.001 – Clear Windows Logs |
| Backdoor Account | Malicious local admin user Support created | T1136.001 – Create Local Account |
| Lateral Movement | Attempted RDP to `10.1.0.188` using `mstsc.exe` | T1021.001 – RDP |
| Attack Automation | PowerShell script Wupdate.ps1 downloaded & executed | T1059.001 – PowerShell |

---

 2.1 ## Question: Identify the source IP address of the Remote Desktop Protocol connection? *

-  Source IP: `88.97.178.12`
- Attacker successfully logged in at **2025-11-19T18:36:18Z**

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| project Timestamp,DeviceName,ActionType,LogonType,AccountName,RemoteIP,RemoteIPType
| order by Timestamp asc
```
---
<img width="1320" height="286" alt="image" src="https://github.com/user-attachments/assets/53b45966-82a2-405e-bde7-ecb327ad0ee6" />

 2.2 ## Question: Identify the user account that was compromised for initial access?
-  Compromised User: `kenji.sato`

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonSuccess"
| where RemoteIP == "88.97.178.12"
| project Timestamp,DeviceName,AccountName
| order by Timestamp asc
```
---
<img width="1361" height="163" alt="image" src="https://github.com/user-attachments/assets/28e0ffe6-ca9d-48b1-a9d6-1b5c28244f6c" />

 2.3 ## Question: Identify the command and argument used to enumerate network neighbours?

`arp.exe -a` executed  
Timestamp: 2025-11-19T19:04:01.773778Z

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName has_any ("arp.exe","net.exe","ipconfig.exe")
| project Timestamp,DeviceName,AccountName,FileName,ProcessCommandLine
| order by Timestamp asc
```
- Question: Identify the command and argument used to enumerate network neighbours?
---

## 2.4 Staging Directory Created (attrib.exe)

Timestamp: 19:05:33.7665036Z

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName has_any ("cmd.exe","powershell.exe","attrib.exe")
| where ProcessCommandLine has_any ("attrib")
| project Timestamp,DeviceName,AccountName,FileName,ProcessCommandLine
| order by Timestamp asc
```

---

## 2.5 Defender Evasion (File Extension Exclusions)

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains @"Exclusions\Extensions"
| summarize count_distinct(RegistryValueName)
```

---

## 2.6 Temp Folder Excluded From AV

Excluded path: `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey has_any ("Exclusions","Extensions")
| project Timestamp,RegistryKey,RegistryValueName
| order by Timestamp asc
```

---

## 2.7 Malware Download via certutil.exe

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("http","https","ftp")
| project Timestamp,FileName,ProcessCommandLine
| order by Timestamp asc
```

---

## 2.8 Persistence (Scheduled Task)

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName has_any ("schtasks.exe")
| project Timestamp,FileName,ProcessCommandLine
| order by Timestamp asc
```

---

## 2.9 Malicious Executable Path

`C:\ProgramData\WindowsCache\svchost.exe`

---

## 2.10 Command & Control Server

C2 IP: `78.141.196.6`

```kql
let MainTime = datetime(2025-11-19T19:07:46.9796512Z);
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (MainTime -2m .. MainTime +10m)
| project Timestamp,RemoteIP,InitiatingProcessCommandLine
| order by Timestamp asc
```

---

## 2.11 C2 Port

443 (HTTPS)

---

## 2.12 Credential Dumping Tool (mm.exe)

```kql
let MainTime = datetime(2025-11-19T19:07:46.9796512Z);
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (MainTime -2m .. MainTime +20m)
| project Timestamp,FileName,FolderPath,ProcessCommandLine
| order by Timestamp asc
```

---

## 2.13 Credential Dumping Module

Executed: `sekurlsa::logonpasswords`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mimikatz","::")
| project Timestamp,FileName,FolderPath,ProcessCommandLine
| order by Timestamp asc
```

---

## 2.14 Data Exfiltration Archive

`export-data.zip`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any (".zip")
| project Timestamp,FileName,FolderPath,ProcessCommandLine
| order by Timestamp asc
```

---

## 2.15 Exfiltration to Discord

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemotePort == 443
| where InitiatingProcessCommandLine has_any ("http","https","ftp")
| project Timestamp,RemoteIP,RemotePort,RemoteUrl,InitiatingProcessCommandLine
| order by Timestamp asc
```

---

## 2.16 Logs Cleared (wevtutil.exe)

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "wevtutil.exe"
| project Timestamp,FileName,ProcessCommandLine
| order by Timestamp asc
```

---

## 2.17 Backdoor Local Admin Account

User created: Support

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("net user","localgroup administrators","New-LocalUser","Add-LocalGroupMember")
| project Timestamp,FileName,ProcessCommandLine
| order by Timestamp asc
```

---

## 2.18 Automation Script (Wupdate.ps1)

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName has_any (".ps1")
| where InitiatingProcessCommandLine has_any ("Invoke-WebRequest")
| project Timestamp,FileName,FolderPath,InitiatingProcessCommandLine
| order by Timestamp asc
```

---

## 2.19 Lateral Movement Target

Target: `10.1.0.188`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName has_any ("cmdkey.exe","mstsc.exe")
| order by Timestamp asc
```

---

## 2.20 Lateral Movement Tool Used

Tool: `mstsc.exe`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName has_any(".exe")
| where ProcessCommandLine has_any ("10.1.0.188")
| project Timestamp,FileName,ProcessCommandLine
| order by Timestamp desc
```

---

# Final Summary

This hunt confirms a full-chain compromise on AZUKI-SL, including:

- Stolen credentials  
- Network discovery  
- Malware staging  
- AV evasion  
- Credential dumping  
- Persistent scheduled tasks  
- HTTPS-based C2  
- ZIP archive exfiltration to Discord  
- Event log wiping  
- Backdoor local admin user  
- Lateral movement attempts

**Severity: HIGH (Domain-Wide Risk)**
