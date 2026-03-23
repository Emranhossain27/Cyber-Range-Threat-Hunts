# Akira Ransomware Investigation Report

## Analyst: Emran Hossain

Platform: Microsoft Defender for Endpoint (KQL)

------------------------------------------------------------------------

## SECTION 1: RANSOM NOTE ANALYSIS

### Q1 - Threat Actor

**Question:** Identify the ransomware group from the ransom note. What
ransomware group is responsible?\
**MITRE:** T1486 -- Data Encrypted for Impact\
**Answer:** akira

------------------------------------------------------------------------

### Q2 - Negotiation Portal

**Question:** What is the TOR negotiation address?\
**MITRE:** T1071 -- Application Layer Protocol\
**Answer:**
akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion

------------------------------------------------------------------------

### Q3 - Victim ID

**Question:** What is the company's unique ID?\
**MITRE:** T1486\
**Answer:** 813R-QWJM-XKIJ

------------------------------------------------------------------------

### Q4 - Encrypted Extension

**Question:** What file extension is added to encrypted files?\
**MITRE:** T1486\
**Answer:** .akira

``` kql
DeviceFileEvents
| where FileName endswith ".akira"
```

------------------------------------------------------------------------

## SECTION 2: INFRASTRUCTURE

### Q5 - Payload Domain

**Question:** What domain hosted the payloads?\
**MITRE:** T1105\
**Answer:** sync.cloud-endpoint.net

``` kql
let start_time = datetime(2026-01-15);
let end_start = datetime(2026-01-30);
let suspecious_file = "Daniel_Richardson_CV.pdf.exe";
DeviceNetworkEvents
| where DeviceName in ( "as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_start )
| where RemoteUrl contains ".net"
| where InitiatingProcessFileName in ("powershell.exe","cmd.exe","curl.exe","wget.exe","bitsadmin.exe")
| project TimeGenerated, DeviceName,RemoteUrl,RemoteIP

```
<img width="877" height="237" alt="image" src="https://github.com/user-attachments/assets/c7583a8e-882d-43b0-a063-995d025ca56f" />
------------------------------------------------------------------------

### Q6 - Ransomware Staging

**Question:** What domain staged the ransomware?\
**MITRE:** T1071\
**Answer:** cdn.cloud-endpoint.net

``` kql
let start_time = datetime(2026-01-15);
let end_start = datetime(2026-01-30);
let suspecious_file = "Daniel_Richardson_CV.pdf.exe";
DeviceNetworkEvents
| where DeviceName in ( "as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_start )
| where RemoteUrl contains "cloud"
| project TimeGenerated, DeviceName,RemoteUrl,RemoteIP

```
<img width="912" height="196" alt="image" src="https://github.com/user-attachments/assets/e23b7c99-c767-4e11-8bbc-25226918d76f" />
------------------------------------------------------------------------

### Q7 - C2 IP Addresses

**Question:** What are the two C2 IP addresses?\
**MITRE:** T1071\
**Answer:** 104.21.30.237, 172.67.174.46

``` kql
let start_time = datetime(2026-01-15);
let end_start = datetime(2026-01-30);
let suspecious_file = "Daniel_Richardson_CV.pdf.exe";
DeviceNetworkEvents
| where DeviceName in ( "as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_start )
| where RemoteUrl contains "cloud"
| project TimeGenerated, DeviceName,RemoteUrl,RemoteIP
| summarize count() by RemoteIP
```

<img width="647" height="216" alt="image" src="https://github.com/user-attachments/assets/e2dccdcb-d71c-410c-bea0-9e9cdaed0db6" />
------------------------------------------------------------------------

### Q8 - Remote Tool Relay

**Question:** What relay domain was used?\
**MITRE:** T1090\
**Answer:** relay-0b975d23.net.anydesk.com

``` kql
let start_time = datetime(2026-01-15);
let end_start = datetime(2026-01-30);
let suspecious_file = "Daniel_Richardson_CV.pdf.exe";
DeviceNetworkEvents
| where DeviceName in ( "as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_start )
| where RemoteUrl contains "relay"
| project TimeGenerated, DeviceName,RemoteUrl,RemoteIP
| summarize count() by RemoteUrl

```
<img width="978" height="262" alt="image" src="https://github.com/user-attachments/assets/493114df-7bfe-478a-8a24-3a75adc59685" />
------------------------------------------------------------------------

## SECTION 3: DEFENSE EVASION

### Q9 - Evasion Script

**Question:** What script disabled security?\
**MITRE:** T1562\
**Answer:** kill.bat

``` kql
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceFileEvents
| where DeviceName in ("as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated  between (start_time .. end_time)
| where FileName endswith ".bat"
| project TimeGenerated, DeviceName, FileName
| order by TimeGenerated desc
```
<img width="835" height="132" alt="image" src="https://github.com/user-attachments/assets/3a406070-bf40-4d60-8e4e-0d29e88f8b5c" />
------------------------------------------------------------------------

### Q10 - Evasion Hash

**Question:** What is the SHA256 of the script?\
**MITRE:** T1562\
**Answer:**
0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceFileEvents
| where DeviceName in ("as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated  between (start_time .. end_time)
| where FileName endswith ".bat"
| project TimeGenerated, DeviceName, FileName,SHA256
| order by TimeGenerated desc
```
<img width="1406" height="142" alt="image" src="https://github.com/user-attachments/assets/62f70a94-c855-439f-9d17-4cd6064d4ba9" />
------------------------------------------------------------------------


---

### 🚩 Q11  
**Question:** What registry value disabled Defender?  
**MITRE:** T1112 – Modify Registry  
**Answer:** DisableAntiSpyware  
```
let start_time = datetime(2026-01-15);
let end_start = datetime(2026-01-30);
let suspecious_file = "Daniel_Richardson_CV.pdf.exe";
DeviceRegistryEvents
| where DeviceName in ( "as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_start )
| where InitiatingProcessCommandLine contains "disable"
| project TimeGenerated,InitiatingProcessCommandLine,RegistryValueName,RegistryKey
```
<img width="1335" height="143" alt="image" src="https://github.com/user-attachments/assets/cabfb3e4-8304-485a-91d2-cc7cf73170ef" />
---

### 🚩 Q12  
**Question:** Registry modification time?  
**MITRE:** T1112  
**Answer:** 21:03:42  
```
let start_time = datetime(2026-01-15);
let end_start = datetime(2026-01-30);
let suspecious_file = "Daniel_Richardson_CV.pdf.exe";
DeviceRegistryEvents
| where DeviceName in ( "as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_start )
| where InitiatingProcessCommandLine contains "DisableAntiSpyware"
| project TimeGenerated,InitiatingProcessCommandLine
```

<img width="1272" height="97" alt="image" src="https://github.com/user-attachments/assets/6d4b66a2-856d-487c-948e-67a315a706fb" />
---

### 🧩 SECTION 4: CREDENTIAL ACCESS

### 🚩 Q13  
**Question:** What command was used?  
**MITRE:** T1057 – Process Discovery  
**Answer:** tasklist | findstr lsass  
```

let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceProcessEvents
| where DeviceName in ("as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_time)
| where ProcessCommandLine contains  "tasklist"
| project TimeGenerated, DeviceName, ProcessCommandLine

```
<img width="997" height="222" alt="image" src="https://github.com/user-attachments/assets/977ad86d-3ad7-4165-bae7-4e9e2b4823fb" />
---

### 🚩 Q14  
**Question:** What named pipe was accessed?  
**MITRE:** T1003 – Credential Dumping  
**Answer:** \\Device\\NamedPipe\\lsass  

```
let target_time = datetime(2026-01-27 21:11:00);
DeviceEvents
| where DeviceName in ("as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (target_time - 40m .. target_time + 40m)
| where AdditionalFields contains "lsass"
| project TimeGenerated,AdditionalFields,DeviceName

```
<img width="1388" height="262" alt="image" src="https://github.com/user-attachments/assets/740c91c5-edf1-4dff-b98a-514e888e9db4" />
---

### 🧩 SECTION 5: INITIAL ACCESS

## 🚩 Q15  
**Question:** What remote access tool was used?  
**MITRE:** T1219  
**Answer:** anydesk  
```
let start_time = datetime(2026-01-15);
let end_start = datetime(2026-01-30);
let suspecious_file = "Daniel_Richardson_CV.pdf.exe";
DeviceProcessEvents
| where DeviceName in ( "as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_start )
| where ProcessCommandLine contains "any"
| project TimeGenerated, ProcessCommandLine
````
<img width="1340" height="262" alt="image" src="https://github.com/user-attachments/assets/cc2dde97-a2c1-4aa2-862f-c0e426e5380d" />
---

### 🚩 Q16  
**Question:** Where was it executed from?  
**MITRE:** T1036  
**Answer:** C:\\Users\\Public\\  

```
let start_time = datetime(2026-01-15);
let end_start = datetime(2026-01-30);
let suspecious_file = "Daniel_Richardson_CV.pdf.exe";
DeviceProcessEvents
| where DeviceName in ("as-pc2")
| where TimeGenerated between (start_time .. end_start )
| where ProcessCommandLine contains "any"
| project TimeGenerated, ProcessCommandLine,FolderPath

```
<img width="1165" height="192" alt="image" src="https://github.com/user-attachments/assets/989182ba-6bea-4ed5-9b38-0dcf5e3f7996" />
---

### 🚩 Q17  
**Question:** What is attacker IP?  
**MITRE:** T1071  
**Answer:** 88.97.164.155  
```
let start_time = datetime(2026-01-15);
let end_start = datetime(2026-01-30);
let suspecious_file = "Daniel_Richardson_CV.pdf.exe";
DeviceNetworkEvents
| where DeviceName in ("as-pc2")
| where TimeGenerated between (start_time .. end_start )
| where InitiatingProcessCommandLine contains "any"
| project TimeGenerated,InitiatingProcessCommandLine,RemoteIP

```
<img width="906" height="71" alt="image" src="https://github.com/user-attachments/assets/0ccf7f57-5ef2-4fdc-91b4-30ba81819358" />
---

### 🚩 Q18  
**Question:** What user was compromised?  
**MITRE:** T1078  
**Answer:** david.mitchell  
```
let start_time = datetime(2026-01-15);
let end_start = datetime(2026-01-30);
let suspecious_file = "Daniel_Richardson_CV.pdf.exe";
DeviceNetworkEvents
| where DeviceName in ("as-pc2")
| where TimeGenerated between (start_time .. end_start )
| where InitiatingProcessCommandLine contains "any"
| project TimeGenerated,InitiatingProcessCommandLine,RemoteIP, InitiatingProcessAccountName
```
<img width="1111" height="77" alt="image" src="https://github.com/user-attachments/assets/cbf25d27-8645-4bdf-8f21-abfe3f67a1f5" />
---

# 🧩 SECTION 6: COMMAND & CONTROL

#### 🚩 Q19  
**Question:** What beacon was deployed?  
**MITRE:** T1071  
**Answer:** wsync.exe  
```
let target_time = datetime(2026-01-27 20:22:50);
DeviceProcessEvents
| where DeviceName in ("as-pc2")
| where FileName endswith ".exe"
| where not( FolderPath startswith "C:\\Windows")
| where not (FolderPath startswith "C:\\Program Files (x86)")
| where TimeGenerated between (target_time - 60m .. target_time + 60m)
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1415" height="47" alt="image" src="https://github.com/user-attachments/assets/0c8406b7-77dc-424d-a2bc-a577b67d20c0" />
---

#### 🚩 Q20  
**Question:** Where was beacon deployed?  
**MITRE:** T1105  
**Answer:** C:\\ProgramData
```
let target_time = datetime(2026-01-27 20:22:50);
DeviceProcessEvents
| where DeviceName in ("as-pc2")
| where FileName endswith ".exe"
| where not( FolderPath startswith "C:\\Windows")
| where not (FolderPath startswith "C:\\Program Files (x86)")
| where TimeGenerated between (target_time - 60m .. target_time + 60m)
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="891" height="43" alt="image" src="https://github.com/user-attachments/assets/6bafe8c3-517c-4822-91ea-3d777d01565a" />
---


### 🚩 Q21  
**Question:** SHA256 of original beacon?  
**MITRE:** T1071  
**Answer:** 66b876c52946f4aed47dd696d790972ff265b6f4451dab54245bc4ef1206d90b  
```
let target_time = datetime(2026-01-27 20:22:50);
DeviceProcessEvents
| where DeviceName in ("as-pc2")
| where FileName endswith ".exe"
| where not( FolderPath startswith "C:\\Windows")
| where not (FolderPath startswith "C:\\Program Files (x86)")
| where FileName contains "wsync.exe"
| where TimeGenerated between (target_time - 60m .. target_time + 60m)
| project TimeGenerated, FileName, SHA256
| order by TimeGenerated asc

```
<img width="1125" height="82" alt="image" src="https://github.com/user-attachments/assets/1e041095-09ab-4987-9cbe-b070d704e829" />

---

### 🚩 Q22  
**Question:** SHA256 of replacement beacon?  
**MITRE:** T1071  
**Answer:** 0072ca0d0adc9a1b2e1625db4409f57fc32b5a09c414786bf08c4d8e6a073654  
```
let target_time = datetime(2026-01-27 20:22:50);
DeviceProcessEvents
| where DeviceName in ("as-pc2")
| where FileName endswith ".exe"
| where not( FolderPath startswith "C:\\Windows")
| where not (FolderPath startswith "C:\\Program Files (x86)")
| where FileName contains "wsync.exe"
| where TimeGenerated between (target_time - 60m .. target_time + 60m)
| project TimeGenerated, FileName, SHA256
| order by TimeGenerated asc

```
<img width="1135" height="46" alt="image" src="https://github.com/user-attachments/assets/14b10562-4a28-43e3-8777-231113fdc859" />
```
---

# 🧩 SECTION 7: RECONNAISSANCE

### 🚩 Q23  
**Question:** What scanner tool was used?  
**MITRE:** T1046  
**Answer:** scan.exe
```

let target_time = datetime(2026-01-27 20:22:50);
DeviceProcessEvents
| where DeviceName in ( "as-pc","as-pc1","as-srv","as-pc2")
| where FileName endswith ".exe"
| where not( FolderPath startswith "C:\\Windows")
| where not (FolderPath startswith "C:\\Program Files (x86)")
| where ProcessCommandLine has_any ("scan")
| where TimeGenerated between (target_time - 60m .. target_time + 60m)
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1048" height="71" alt="image" src="https://github.com/user-attachments/assets/1699f6ec-9a2c-4019-83af-d9c6ef7df028" />
---

### 🚩 Q24  
**Question:** SHA256 of scanner?  
**MITRE:** T1046  
**Answer:** 26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b  
```
let target_time = datetime(2026-01-27 20:22:50);
DeviceProcessEvents
| where DeviceName in ( "as-pc","as-pc1","as-srv","as-pc2")
| where FileName endswith ".exe"
| where not( FolderPath startswith "C:\\Windows")
| where not (FolderPath startswith "C:\\Program Files (x86)")
| where ProcessCommandLine has_any ("scan")
| where TimeGenerated between (target_time - 60m .. target_time + 60m)
| project TimeGenerated, FileName,ProcessCommandLine,SHA256
| order by TimeGenerated asc

```
<img width="1355" height="105" alt="image" src="https://github.com/user-attachments/assets/80e15e4b-05da-4fba-90c9-705967fa4134" />
---

### 🚩 Q25  
**Question:** What arguments were used?  
**MITRE:** T1046  
**Answer:** /portable "C:/Users/david.mitchell/Downloads/" /lng en_us  
```
let target_time = datetime(2026-01-27 20:17:50);
DeviceProcessEvents
| where DeviceName in ( "as-pc","as-pc1","as-srv","as-pc2")
| where FileName endswith ".exe"
| where not( FolderPath startswith "C:\\Windows")
| where not (FolderPath startswith "C:\\Program Files (x86)")
| where TimeGenerated between (target_time - 2m .. target_time + 2m)
| project TimeGenerated, FileName,ProcessCommandLine,SHA256
| order by TimeGenerated asc

```
<img width="1200" height="35" alt="image" src="https://github.com/user-attachments/assets/8e7a3901-e987-41e5-bc0b-189d3dbf3f5b" />
---

### 🚩 Q26  
**Question:** What internal IPs were enumerated?  
**MITRE:** T1046  
**Answer:** 10.1.0.154,10.1.0.183  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceProcessEvents
| where DeviceName in ("as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_time)
| where ProcessCommandLine has_any ("net.exe")
| extend internalIP = extract(@"\\\\(\d+\.\d+\.\d+\.\d+)",1,ProcessCommandLine)
| summarize count() by internalIP

```
<img width="662" height="232" alt="image" src="https://github.com/user-attachments/assets/decfbbc8-b38f-4fd1-bcb7-4de681353835" />
---

# 🧩 SECTION 8: LATERAL MOVEMENT

### 🚩 Q27  
**Question:** What account accessed AS-SRV?  
**MITRE:** T1021  
**Answer:** as.srv.administrator  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceLogonEvents
| where DeviceName =="as-srv"
| where TimeGenerated between (start_time .. end_time)
| where ActionType == "LogonSuccess"
| project TimeGenerated,DeviceName,AccountName
| summarize count() by AccountName

```
<img width="407" height="42" alt="image" src="https://github.com/user-attachments/assets/9915612b-eb7f-4a0f-8223-5ee70a3b01d2" />

---

# 🧩 SECTION 9: TOOL TRANSFER

### 🚩 Q28  
**Question:** What LOLBIN used first?  
**MITRE:** T1105  
**Answer:** bitsadmin.exe  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceProcessEvents
| where DeviceName in ( "as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_time )
| where ProcessCommandLine has_any ("bitsadmin")
| project TimeGenerated,DeviceName,ProcessCommandLine,FileName

```
<img width="1016" height="45" alt="image" src="https://github.com/user-attachments/assets/c0102d7a-eaa8-45a4-81ee-3f7bdc246bd9" />

---

### 🚩 Q29  
**Question:** What PowerShell cmdlet used?  
**MITRE:** T1105  
**Answer:** Invoke-WebRequest  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceProcessEvents
| where DeviceName in ("as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_time)
| where InitiatingProcessFileName == "powershell.exe"
| where ProcessCommandLine has_any ("http","https","Download","WebClient","Invoke")
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

```

---

# 🧩 SECTION 10: EXFILTRATION

### 🚩 Q30  
**Question:** What tool compressed data?  
**MITRE:** T1041  
**Answer:** st.exe  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceFileEvents
| where DeviceName in ("as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_time)
| where ActionType == "FileCreated"
| where FileName has_any (".zip",".7z")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName

```
<img width="1127" height="30" alt="image" src="https://github.com/user-attachments/assets/f0276ee3-70db-4447-a7f7-def67a68b737" />

---

### 🚩 Q31  
**Question:** SHA256 of staging tool?  
**MITRE:** T1041  
**Answer:** 512a1f4ed9f512572608c729a2b89f44ea66a40433073aedcd914bd2d33b7015  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceFileEvents
| where DeviceName in ("as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_time)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName contains "st.exe"
| where FileName has_any (".zip",".7z")
| project TimeGenerated, DeviceName, InitiatingProcessFileName,InitiatingProcessSHA256

```
<img width="1371" height="37" alt="image" src="https://github.com/user-attachments/assets/aa75a91a-192d-4024-91fb-d01c6244af19" />

---

### 🚩 Q32  
**Question:** What archive created?  
**MITRE:** T1041  
**Answer:** exfil_data.zip  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceFileEvents
| where DeviceName in ("as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_time)
| where ActionType == "FileCreated"
| where FileName has_any (".zip",".7z")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName,SHA256

```
<img width="1165" height="56" alt="image" src="https://github.com/user-attachments/assets/906299b8-7418-4e0d-8432-d9dbb9dd7ec6" />

---

# 🧩 SECTION 11: RANSOMWARE DEPLOYMENT

### 🚩 Q33  
**Question:** Ransomware filename?  
**MITRE:** T1486  
**Answer:** updater.exe  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceFileEvents
| where DeviceName in ("as-srv")
| where TimeGenerated between (start_time .. end_time)
| where ActionType =="FileCreated"
| where FolderPath startswith @"C:\Users\AS.SRV.Administrator"
| project TimeGenerated, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc

```
<img width="1253" height="116" alt="image" src="https://github.com/user-attachments/assets/9220f61d-9c16-4d5e-820b-6eb05276d0a6" />

---

### 🚩 Q34  
**Question:** SHA256 of ransomware?  
**MITRE:** T1486  
**Answer:** e609d070ee9f76934d73353be4ef7ff34b3ecc3a2d1e5d052140ed4cb9e4752b  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceFileEvents
| where DeviceName in ("as-srv")
| where TimeGenerated between (start_time .. end_time)
| where ActionType =="FileCreated"
| where InitiatingProcessFileName == "updater.exe"
| where FolderPath startswith @"C:\Users\AS.SRV.Administrator"
| project TimeGenerated, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,InitiatingProcessSHA256
| order by TimeGenerated desc

```
<img width="1381" height="55" alt="image" src="https://github.com/user-attachments/assets/6021c179-ca90-4a10-8741-f9e56683b3cb" />

---

### 🚩 Q35  
**Question:** What process staged ransomware?  
**MITRE:** T1059  
**Answer:** powershell.exe  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceFileEvents
| where DeviceName in ("as-srv")
| where TimeGenerated between (start_time .. end_time)
| where ActionType =="FileCreated"
| where FolderPath startswith @"C:\Users\AS.SRV.Administrator"
| project TimeGenerated, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc

```
<img width="693" height="32" alt="image" src="https://github.com/user-attachments/assets/0f8afe3a-2d1b-4c15-bb85-4975dadc6529" />

---

### 🚩 Q36  
**Question:** What command deleted backups?  
**MITRE:** T1490  
**Answer:** vssadmin delete shadows /all /quiet  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceProcessEvents
| where DeviceName in ("as-pc","as-pc1","as-srv","as-pc2")
| where TimeGenerated between (start_time .. end_time)
| where ProcessCommandLine has_any ("vssadmin")
| project TimeGenerated, DeviceName, FileName, FolderPath,ProcessCommandLine

```
<img width="1413" height="90" alt="image" src="https://github.com/user-attachments/assets/efca705f-04b0-4131-9da3-c15773bf1b71" />

---

### 🚩 Q37  
**Question:** What process dropped ransom note?  
**MITRE:** T1486  
**Answer:** updater.exe  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceFileEvents
| where DeviceName in ("as-srv")
| where TimeGenerated between (start_time .. end_time)
| where ActionType =="FileCreated"
| where FileName contains ".txt"
| where InitiatingProcessFileName contains "updater.exe"
| where FolderPath startswith @"C:\Users\AS.SRV.Administrator"
| project TimeGenerated, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc

```
<img width="1238" height="73" alt="image" src="https://github.com/user-attachments/assets/17e27c63-fe9b-4da0-8d18-b56619add1db" />

---

### 🚩 Q38  
**Question:** What time encryption began?  
**MITRE:** T1486  
**Answer:** 22:18:33  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceFileEvents
| where DeviceName in ("as-srv")
| where TimeGenerated between (start_time .. end_time)
| where ActionType =="FileCreated"
| where FileName contains ".txt"
| where InitiatingProcessFileName contains "updater.exe"
| where FolderPath startswith @"C:\Users\AS.SRV.Administrator"
| project TimeGenerated, FileName, FolderPath
| order by TimeGenerated desc

```
<img width="1067" height="61" alt="image" src="https://github.com/user-attachments/assets/6fd0a50a-157a-4bfc-bfc8-b44dbff7cad2" />

---

# 🧩 SECTION 12: ANTI-FORENSICS

### 🚩 Q39  
**Question:** What script deleted ransomware?  
**MITRE:** T1070  
**Answer:** clean.bat  
```
let start_time = datetime(2026-01-15);
let end_time = datetime(2026-01-30);
DeviceFileEvents
| where DeviceName in ("as-srv")
| where TimeGenerated between (start_time .. end_time)
| where ActionType == "FileDeleted"
| where FolderPath startswith @"C:\Users\AS.SRV.Administrator"
| project TimeGenerated, FileName,InitiatingProcessCommandLine
| order by TimeGenerated desc

```
<img width="947" height="46" alt="image" src="https://github.com/user-attachments/assets/1e1ea2ec-8393-4e6f-a849-9453bb134167" />

---

### 🚩 Q40  
**Question:** What hosts were compromised?  
**MITRE:** T1486  
**Answer:** as-pc2, as-srv 
---

## 📌 Executive Summary

This investigation analyzes a multi-stage Akira ransomware attack using Microsoft Defender for Endpoint and KQL-based threat hunting techniques.

The attack began with the execution of a malicious file disguised as a resume (`Daniel_Richardson_CV.pdf.exe`), leading to initial access through a remote access tool (AnyDesk). The attacker established command and control (C2) communication with external infrastructure (`cloud-endpoint.net`) and deployed a beacon (`wsync.exe`) to maintain persistence.

Following initial compromise, the attacker performed credential discovery targeting LSASS, conducted network reconnaissance using a custom scanner (`scan.exe`), and enumerated internal systems. Lateral movement was observed through administrative account access to the server (`as-srv`).

Data was staged and compressed using `st.exe`, producing `exfil_data.zip`, indicating preparation for exfiltration. The final stage involved deployment of the Akira ransomware (`updater.exe`), execution of backup deletion commands (`vssadmin delete shadows`), and encryption of files with the `.akira` extension.

To evade detection and hinder investigation, the attacker disabled security controls via registry modification (`DisableAntiSpyware`) and executed a cleanup script (`clean.bat`) to remove artifacts.

The attack impacted multiple hosts, primarily `as-pc2` and `as-srv`, demonstrating a complete adversary lifecycle aligned with MITRE ATT&CK techniques including Initial Access, Execution, Persistence, Defense Evasion, Credential Access, Discovery, Lateral Movement, Exfiltration, and Impact.
