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
DeviceNetworkEvents
| where RemoteUrl contains "cloud"
```

------------------------------------------------------------------------

### Q7 - C2 IP Addresses

**Question:** What are the two C2 IP addresses?\
**MITRE:** T1071\
**Answer:** 104.21.30.237, 172.67.174.46

``` kql
DeviceNetworkEvents
| where RemoteUrl contains "cloud"
| summarize count() by RemoteIP
```

------------------------------------------------------------------------

### Q8 - Remote Tool Relay

**Question:** What relay domain was used?\
**MITRE:** T1090\
**Answer:** relay-0b975d23.net.anydesk.com

``` kql
DeviceNetworkEvents
| where RemoteUrl contains "relay"
```

------------------------------------------------------------------------

## SECTION 3: DEFENSE EVASION

### Q9 - Evasion Script

**Question:** What script disabled security?\
**MITRE:** T1562\
**Answer:** kill.bat

``` kql
DeviceFileEvents
| where FileName endswith ".bat"
```

------------------------------------------------------------------------

### Q10 - Evasion Hash

**Question:** What is the SHA256 of the script?\
**MITRE:** T1562\
**Answer:**
0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c

------------------------------------------------------------------------

## SECTION 12: FINAL IMPACT

### Q39 - Cleanup Script

**Question:** What script deleted the ransomware?\
**MITRE:** T1070\
**Answer:** clean.bat

``` kql
DeviceFileEvents
| where ActionType == "FileDeleted"
```

------------------------------------------------------------------------

### Q40 - Affected Hosts

**Question:** What hosts were compromised?\
**MITRE:** T1486\
**Answer:** as-pc2, as-srv

``` kql
DeviceProcessEvents
| summarize count() by DeviceName
```
