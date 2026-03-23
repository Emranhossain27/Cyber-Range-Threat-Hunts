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

