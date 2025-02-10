# APT41 - G0096

**Created**: 2019-09-23T13:43:36.945Z

**Modified**: 2024-10-10T14:31:35.326Z

**Contributors**: Kyaw Pyiyt Htet, @KyawPyiytHtet,Nikita Rostovcev, Group-IB

## Aliases

APT41,Wicked Panda,Brass Typhoon,BARIUM

## Description

[APT41](https://attack.mitre.org/groups/G0096) is a threat group that researchers have assessed as Chinese state-sponsored espionage group that also conducts financially-motivated operations. Active since at least 2012, [APT41](https://attack.mitre.org/groups/G0096) has been observed targeting various industries, including but not limited to healthcare, telecom, technology, finance, education, retail and video game industries in 14 countries.(Citation: apt41_mandiant) Notable behaviors include using a wide range of malware and tools to complete mission objectives. [APT41](https://attack.mitre.org/groups/G0096) overlaps at least partially with public reporting on groups including BARIUM and [Winnti Group](https://attack.mitre.org/groups/G0044).(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021)


## Techniques Used


[APT41](https://attack.mitre.org/groups/G0096) uses multiple built-in commands such as <code>systeminfo</code> and `net config Workstation` to enumerate victim system basic configuration information.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[APT41](https://attack.mitre.org/groups/G0096) gained access to production environments where they could inject malicious code into legitimate, signed files and widely distribute them to end users.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1195.002|Compromise Software Supply Chain|


[APT41](https://attack.mitre.org/groups/G0096) leverages various tools and frameworks to brute-force directories on web servers.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1595.003|Wordlist Scanning|


[APT41](https://attack.mitre.org/groups/G0096) developed a custom injector that enables an Event Tracing for Windows (ETW) bypass, making malicious processes invisible to Windows logging.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1562.006|Indicator Blocking|


[APT41](https://attack.mitre.org/groups/G0096) leveraged PowerShell to deploy malware families in victims’ environments.(Citation: FireEye APT41 Aug 2019)(Citation: FireEye APT41 March 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[APT41](https://attack.mitre.org/groups/G0096) used <code>net group</code> commands to enumerate various Windows user groups and permissions.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Office Suite, Identity Provider|T1069|Permission Groups Discovery|


[APT41](https://attack.mitre.org/groups/G0096) used compromised credentials to log on to other systems.(Citation: FireEye APT41 Aug 2019)(Citation: Crowdstrike GTR2020 Mar 2020)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[APT41](https://attack.mitre.org/groups/G0096) used exploit payloads that initiate download via [ftp](https://attack.mitre.org/software/S0095).(Citation: FireEye APT41 March 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.002|File Transfer Protocols|


[APT41](https://attack.mitre.org/groups/G0096) has used MiPing to discover active systems in the victim network.(Citation: apt41_dcsocytec_dec2022) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[APT41](https://attack.mitre.org/groups/G0096) modified legitimate Windows services to install malware backdoors.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021) [APT41](https://attack.mitre.org/groups/G0096) created the StorSyncSvc service to provide persistence for [Cobalt Strike](https://attack.mitre.org/software/S0154).(Citation: FireEye APT41 March 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1543.003|Windows Service|


[APT41](https://attack.mitre.org/groups/G0096) attempted to masquerade their files as popular anti-virus software.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[APT41](https://attack.mitre.org/groups/G0096) uses packers such as Themida to obfuscate malicious files.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1027.002|Software Packing|


[APT41](https://attack.mitre.org/groups/G0096) leveraged code-signing certificates to sign malware when targeting both gaming and non-gaming organizations.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021)
|['enterprise-attack']|enterprise-attack|macOS, Windows|T1553.002|Code Signing|


[APT41](https://attack.mitre.org/groups/G0096) used built-in <code>net</code> commands to enumerate domain administrator users.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[APT41](https://attack.mitre.org/groups/G0096) deployed rootkits on Linux systems.(Citation: FireEye APT41 Aug 2019)(Citation: Crowdstrike GTR2020 Mar 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1014|Rootkit|


[APT41](https://attack.mitre.org/groups/G0096) used BrowserGhost, a tool designed to obtain credentials from browsers, to retrieve information from password stores.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1555.003|Credentials from Web Browsers|


[APT41](https://attack.mitre.org/groups/G0096) has created user accounts.(Citation: FireEye APT41 Aug 2019) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, Containers|T1136.001|Local Account|


[APT41](https://attack.mitre.org/groups/G0096) used a hidden shell script in `/etc/rc.d/init.d` to leverage the `ADORE.XSEC`backdoor and `Adore-NG` rootkit.(Citation: apt41_mandiant)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux, Network|T1037|Boot or Logon Initialization Scripts|


[APT41](https://attack.mitre.org/groups/G0096) has transferred implant files using Windows Admin Shares and the Server Message Block (SMB) protocol, then executes files through Windows Management Instrumentation (WMI).(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: apt41_dcsocytec_dec2022)
|['enterprise-attack']|enterprise-attack|Windows|T1021.002|SMB/Windows Admin Shares|


[APT41](https://attack.mitre.org/groups/G0096) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002), [pwdump](https://attack.mitre.org/software/S0006), [PowerSploit](https://attack.mitre.org/software/S0194), and [Windows Credential Editor](https://attack.mitre.org/software/S0005).(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[APT41](https://attack.mitre.org/groups/G0096) uses the Chinese website fofa.su, similar to the Shodan scanning service, for passive scanning of victims.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1596.005|Scan Databases|


[APT41](https://attack.mitre.org/groups/G0096) has added user accounts to the User and Admin groups.(Citation: FireEye APT41 Aug 2019) 
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1098.007|Additional Local or Domain Groups|


[APT41](https://attack.mitre.org/groups/G0096) leveraged sticky keys to establish persistence.(Citation: FireEye APT41 Aug 2019) 
|['enterprise-attack']|enterprise-attack|Windows|T1546.008|Accessibility Features|


[APT41](https://attack.mitre.org/groups/G0096) used a compromised account to create a scheduled task on a system.(Citation: FireEye APT41 Aug 2019)(Citation: Crowdstrike GTR2020 Mar 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[APT41](https://attack.mitre.org/groups/G0096) created and modified startup files for persistence.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021) [APT41](https://attack.mitre.org/groups/G0096) added a registry key in <code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost</code> to establish persistence for [Cobalt Strike](https://attack.mitre.org/software/S0154).(Citation: FireEye APT41 March 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[APT41](https://attack.mitre.org/groups/G0096) has configured payloads to load via LD_PRELOAD.(Citation: Crowdstrike GTR2020 Mar 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS|T1574.006|Dynamic Linker Hijacking|


[APT41](https://attack.mitre.org/groups/G0096) used <code>cmd.exe /c</code> to execute commands on remote machines.(Citation: FireEye APT41 Aug 2019)
[APT41](https://attack.mitre.org/groups/G0096) used a batch file to install persistence for the [Cobalt Strike](https://attack.mitre.org/software/S0154) BEACON loader.(Citation: FireEye APT41 March 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[APT41](https://attack.mitre.org/groups/G0096) has used DGAs to change their C2 servers monthly.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1568.002|Domain Generation Algorithms|


[APT41](https://attack.mitre.org/groups/G0096) used  svchost.exe and [Net](https://attack.mitre.org/software/S0039) to execute a system service installed to launch a [Cobalt Strike](https://attack.mitre.org/software/S0154) BEACON loader.(Citation: FireEye APT41 March 2020)(Citation: Group IB APT 41 June 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1569.002|Service Execution|


[APT41](https://attack.mitre.org/groups/G0096) extracted user account data from the Security Account Managerr (SAM), making a copy of this database from the registry using the <code>reg save</code> command or by exploiting volume shadow copies.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1003.002|Security Account Manager|


[APT41](https://attack.mitre.org/groups/G0096) performed password brute-force attacks on the local admin account.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110|Brute Force|


[APT41](https://attack.mitre.org/groups/G0096) uses tools such as [Mimikatz](https://attack.mitre.org/software/S0002) to enable lateral movement via captured password hashes.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1550.002|Pass the Hash|


[APT41](https://attack.mitre.org/groups/G0096) used `NATBypass` to bypass firewall restrictions and to access compromised systems via RDP.(Citation: apt41_dcsocytec_dec2022)
|['enterprise-attack']|enterprise-attack|Network|T1599|Network Boundary Bridging|


[APT41](https://attack.mitre.org/groups/G0096) used scheduled tasks created via Group Policy Objects (GPOs) to deploy ransomware.(Citation: apt41_mandiant)
|['enterprise-attack']|enterprise-attack|Windows|T1484.001|Group Policy Modification|


[APT41](https://attack.mitre.org/groups/G0096) has encrypted payloads using the Data Protection API (DPAPI), which relies on keys tied to specific user accounts on specific machines. [APT41](https://attack.mitre.org/groups/G0096) has also environmentally keyed second stage malware with an RC5 key derived in part from the infected system's volume serial number.(Citation: Twitter ItsReallyNick APT41 EK)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1480.001|Environmental Keying|


 [APT41](https://attack.mitre.org/groups/G0096) used the <code>net share</code> command as part of network reconnaissance.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1135|Network Share Discovery|


[APT41](https://attack.mitre.org/groups/G0096) used the Acunetix SQL injection vulnerability scanner in target reconnaissance operations, as well as the JexBoss tool to identify vulnerabilities in Java applications.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1595.002|Vulnerability Scanning|


[APT41](https://attack.mitre.org/groups/G0096) compromised an online billing/payment service using VPN access between a third-party service provider and the targeted payment service.(Citation: FireEye APT41 Aug 2019)

|['enterprise-attack']|enterprise-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[APT41](https://attack.mitre.org/groups/G0096) has uploaded files and data from a compromised host.(Citation: Group IB APT 41 June 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[APT41](https://attack.mitre.org/groups/G0096) used built-in <code>net</code> commands to enumerate local administrator groups.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.001|Local Account|


[APT41](https://attack.mitre.org/groups/G0096) deployed Master Boot Record bootkits on Windows systems to hide their malware and maintain persistence on victim systems.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|Linux, Windows|T1542.003|Bootkit|


[APT41](https://attack.mitre.org/groups/G0096) attempted to remove evidence of some of its activity by clearing Windows security and system events.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|Windows|T1070.001|Clear Windows Event Logs|


[APT41](https://attack.mitre.org/groups/G0096) used HTTP to download payloads for CVE-2019-19781 and CVE-2020-10189 exploits.(Citation: FireEye APT41 March 2020) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[APT41](https://attack.mitre.org/groups/G0096) sent spearphishing emails with attachments such as compiled HTML (.chm) files to initially compromise their victims.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[APT41](https://attack.mitre.org/groups/G0096) deleted files from the system.(Citation: FireEye APT41 Aug 2019)(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[APT41](https://attack.mitre.org/groups/G0096) has executed <code>whoami</code> commands, including using the WMIEXEC utility to execute this on remote machines.(Citation: FireEye APT41 Aug 2019)(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[APT41](https://attack.mitre.org/groups/G0096) used a ransomware called Encryptor RaaS to encrypt files on the targeted systems and provide a ransom note to the user.(Citation: FireEye APT41 Aug 2019) [APT41](https://attack.mitre.org/groups/G0096) also used Microsoft Bitlocker to encrypt workstations and Jetico’s BestCrypt to encrypt servers.(Citation: apt41_dcsocytec_dec2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1486|Data Encrypted for Impact|


[APT41](https://attack.mitre.org/groups/G0096) collected MAC addresses from victim machines.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1016|System Network Configuration Discovery|


[APT41](https://attack.mitre.org/groups/G0096) used legitimate executables to perform DLL side-loading of their malware.(Citation: FireEye APT41 Aug 2019) 
|['enterprise-attack']|enterprise-attack|Windows|T1574.002|DLL Side-Loading|


[APT41](https://attack.mitre.org/groups/G0096) has enumerated IP addresses of network resources and used the <code>netstat</code> command as part of network reconnaissance. The group has also used a malware variant, HIGHNOON, to enumerate active RDP sessions.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1049|System Network Connections Discovery|


[APT41](https://attack.mitre.org/groups/G0096) used ntdsutil to obtain a copy of the victim environment <code>ntds.dit</code> file.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1003.003|NTDS|


[APT41](https://attack.mitre.org/groups/G0096) used Linux shell commands for system survey and information gathering prior to exploitation of vulnerabilities such as CVE-2019-19871.(Citation: FireEye APT41 March 2020)
|['enterprise-attack']|enterprise-attack|macOS, Linux, Network|T1059.004|Unix Shell|


[APT41](https://attack.mitre.org/groups/G0096) leveraged the follow exploits in their operations: CVE-2012-0158, CVE-2015-1641, CVE-2017-0199, CVE-2017-11882, and CVE-2019-3396.(Citation: FireEye APT41 Aug 2019) 
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1203|Exploitation for Client Execution|


[APT41](https://attack.mitre.org/groups/G0096) used [certutil](https://attack.mitre.org/software/S0160) to download additional files.(Citation: FireEye APT41 March 2020)(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: Group IB APT 41 June 2021) [APT41](https://attack.mitre.org/groups/G0096) downloaded post-exploitation tools such as [Cobalt Strike](https://attack.mitre.org/software/S0154) via command shell following initial access.(Citation: Rostovcev APT41 2021) [APT41](https://attack.mitre.org/groups/G0096) has uploaded Procdump   and NATBypass to a staging directory and has used these tools in follow-on activities.(Citation: apt41_dcsocytec_dec2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[APT41](https://attack.mitre.org/groups/G0096) used a malware variant called WIDETONE to conduct port scans on specified subnets.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers, Network|T1046|Network Service Discovery|


[APT41](https://attack.mitre.org/groups/G0096) created a RAR archive of targeted files for exfiltration.(Citation: FireEye APT41 Aug 2019) Additionally, [APT41](https://attack.mitre.org/groups/G0096) used the makecab.exe utility to both download tools, such as NATBypass, to the victim network and to archive a file for exfiltration.(Citation: apt41_dcsocytec_dec2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[APT41](https://attack.mitre.org/groups/G0096) used DNS for C2 communications.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.004|DNS|


[APT41](https://attack.mitre.org/groups/G0096) has used rundll32.exe to execute a loader.(Citation: Crowdstrike GTR2020 Mar 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1218.011|Rundll32|


[APT41](https://attack.mitre.org/groups/G0096) deployed a Monero cryptocurrency mining tool in a victim’s environment.(Citation: FireEye APT41 Aug 2019)(Citation: apt41_mandiant)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers|T1496.001|Compute Hijacking|


[APT41](https://attack.mitre.org/groups/G0096) used the Steam community page as a fallback mechanism for C2.(Citation: FireEye APT41 Aug 2019) 
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1008|Fallback Channels|


[APT41](https://attack.mitre.org/groups/G0096) used legitimate websites for C2 through dead drop resolvers (DDR), including GitHub, Pastebin, and Microsoft TechNet.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1102.001|Dead Drop Resolver|


[APT41](https://attack.mitre.org/groups/G0096) has obtained information about accounts, lists of employees, and plaintext and hashed passwords from databases.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1555|Credentials from Password Stores|


[APT41](https://attack.mitre.org/groups/G0096) used the storescyncsvc.dll BEACON backdoor to download a secondary backdoor.(Citation: FireEye APT41 March 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1104|Multi-Stage Channels|


[APT41](https://attack.mitre.org/groups/G0096) used VMProtected binaries in multiple intrusions.(Citation: FireEye APT41 March 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1027|Obfuscated Files or Information|


[APT41](https://attack.mitre.org/groups/G0096) transfers post-exploitation files dividing the payload into fixed-size chunks to evade detection.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1030|Data Transfer Size Limits|


[APT41](https://attack.mitre.org/groups/G0096) uses remote shares to move and remotely execute payloads during lateral movemement.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1570|Lateral Tool Transfer|


[APT41](https://attack.mitre.org/groups/G0096) used RDP for lateral movement.(Citation: FireEye APT41 Aug 2019)(Citation: Crowdstrike GTR2020 Mar 2020) [APT41](https://attack.mitre.org/groups/G0096) used NATBypass to expose local RDP ports on compromised systems to the Internet.(Citation: apt41_dcsocytec_dec2022) 
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[APT41](https://attack.mitre.org/groups/G0096) exploited CVE-2020-10189 against Zoho ManageEngine Desktop Central through unsafe deserialization, and CVE-2019-19781 to compromise Citrix Application Delivery Controllers (ADC) and gateway devices.(Citation: FireEye APT41 March 2020) [APT41](https://attack.mitre.org/groups/G0096) leveraged vulnerabilities such as ProxyLogon exploitation or SQL injection for initial access.(Citation: Rostovcev APT41 2021) [APT41](https://attack.mitre.org/groups/G0096) exploited CVE-2021-26855 against a vulnerable Microsoft Exchange Server to gain initial access to the victim network.(Citation: apt41_dcsocytec_dec2022)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[APT41](https://attack.mitre.org/groups/G0096) has created services to appear as benign system tools.(Citation: Group IB APT 41 June 2021)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1036.004|Masquerade Task or Service|


[APT41](https://attack.mitre.org/groups/G0096) has used search order hijacking to execute malicious payloads, such as [Winnti for Windows](https://attack.mitre.org/software/S0141).(Citation: Crowdstrike GTR2020 Mar 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1574.001|DLL Search Order Hijacking|


[APT41](https://attack.mitre.org/groups/G0096) used WMI in several ways, including for execution of commands via WMIEXEC as well as for persistence via [PowerSploit](https://attack.mitre.org/software/S0194).(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021) [APT41](https://attack.mitre.org/groups/G0096) has executed files through Windows Management Instrumentation (WMI).(Citation: apt41_dcsocytec_dec2022)
|['enterprise-attack']|enterprise-attack|Windows|T1047|Windows Management Instrumentation|


[APT41](https://attack.mitre.org/groups/G0096) used a keylogger called GEARSHIFT on a target system.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Network|T1056.001|Keylogging|


[APT41](https://attack.mitre.org/groups/G0096) attempted to remove evidence of some of its activity by deleting Bash histories.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1070.003|Clear Command History|


[APT41](https://attack.mitre.org/groups/G0096) has used hashdump, [Mimikatz](https://attack.mitre.org/software/S0002), Procdump, and the Windows Credential Editor to dump password hashes from memory and authenticate to other user accounts.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021)(Citation: apt41_dcsocytec_dec2022)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[APT41](https://attack.mitre.org/groups/G0096) used [BITSAdmin](https://attack.mitre.org/software/S0190) to download and install payloads.(Citation: FireEye APT41 March 2020)(Citation: Crowdstrike GTR2020 Mar 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1197|BITS Jobs|


[APT41](https://attack.mitre.org/groups/G0096) cloned victim user Git repositories during intrusions.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|SaaS|T1213.003|Code Repositories|


[APT41](https://attack.mitre.org/groups/G0096) used compiled HTML (.chm) files for targeting.(Citation: FireEye APT41 Aug 2019) 
|['enterprise-attack']|enterprise-attack|Windows|T1218.001|Compiled HTML File|


[APT41](https://attack.mitre.org/groups/G0096) used a tool called CLASSFON to covertly proxy network communications.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090|Proxy|


[APT41](https://attack.mitre.org/groups/G0096) used a malware variant called GOODLUCK to modify the registry in order to steal credentials.(Citation: FireEye APT41 Aug 2019)(Citation: Group IB APT 41 June 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1112|Modify Registry|


[APT41](https://attack.mitre.org/groups/G0096) malware TIDYELF loaded the main WINTERLOVE component by injecting it into the iexplore.exe process.(Citation: FireEye APT41 Aug 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1055|Process Injection|


[APT41](https://attack.mitre.org/groups/G0096) queried registry values to determine items such as configured RDP ports and network configurations.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1012|Query Registry|


[APT41](https://attack.mitre.org/groups/G0096) impersonated an employee at a video game developer company to send phishing emails.(Citation: apt41_mandiant)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Office Suite|T1656|Impersonation|


[APT41](https://attack.mitre.org/groups/G0096) has executed <code>file /bin/pwd</code> on exploited victims, perhaps to return architecture related information.(Citation: FireEye APT41 March 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


To support initial access, [APT41](https://attack.mitre.org/groups/G0096) gained access to databases with information about existing accounts as well as plaintext and hashed passwords.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1589.001|Credentials|


To support initial access, [APT41](https://attack.mitre.org/groups/G0096) gained access to databases with information about existing accounts and lists of employees.(Citation: Rostovcev APT41 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1589.003|Employee Names|

