# Volt Typhoon - G1017

**Created**: 2023-07-27T20:35:46.206Z

**Modified**: 2024-05-21T20:12:20.029Z

**Contributors**: Phyo Paing Htun (ChiLai), I-Secure Co.,Ltd,Ai Kimura, NEC Corporation,Manikantan Srinivasan, NEC Corporation India,Pooja Natarajan, NEC Corporation India

## Aliases

Volt Typhoon,BRONZE SILHOUETTE,Vanguard Panda,DEV-0391,UNC3236,Voltzite,Insidious Taurus

## Description

[Volt Typhoon](https://attack.mitre.org/groups/G1017) is a People's Republic of China (PRC) state-sponsored actor that has been active since at least 2021 primarily targeting critical infrastructure organizations in the US and its territories including Guam. [Volt Typhoon](https://attack.mitre.org/groups/G1017)'s targeting and pattern of behavior have been assessed as pre-positioning to enable lateral movement to operational technology (OT) assets for potential destructive or disruptive attacks. [Volt Typhoon](https://attack.mitre.org/groups/G1017) has emphasized stealth in operations using web shells, living-off-the-land (LOTL) binaries, hands on keyboard activities, and stolen credentials.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)(Citation: Microsoft Volt Typhoon May 2023)(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)

## Techniques Used


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used commercial tools, LOTL utilities, and appliances already present on the system for network service discovery.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers, Network|T1046|Network Service Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used compromised Paessler Router Traffic Grapher (PRTG) servers from other organizations for C2.(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1584.004|Server|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has moved laterally to the Domain Controller via RDP using a compromised account with domain administrator privileges.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used compromised devices and customized versions of open source tools  such as [FRP](https://attack.mitre.org/software/S1144) (Fast Reverse Proxy), Earthworm, and [Impacket](https://attack.mitre.org/software/S0357) to proxy network traffic.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090|Proxy|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has enumerated running processes on targeted systems including through the use of [Tasklist](https://attack.mitre.org/software/S0057).(Citation: Microsoft Volt Typhoon May 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1057|Process Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has queried the Registry on compromised systems for information on installed software.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1518|Software Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has enumerated directories containing vulnerability testing and cyber related content and facilities data such as construction drawings.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has identified key network and IT staff members pre-compromise at targeted organizations.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)

|['enterprise-attack']|enterprise-attack|PRE|T1591.004|Identify Roles|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has gained initial access through exploitation of multiple vulnerabilities in internet-facing software and appliances such as Fortinet, Ivanti (formerly Pulse Secure), NETGEAR, Citrix, and Cisco.(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has attempted to obtain credentials from OpenSSH, realvnc, and PuTTY.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)

|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1555|Credentials from Password Stores|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has selectively cleared Windows Event Logs, system logs, and other technical artifacts to remove evidence of intrusion activity.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1070.001|Clear Windows Event Logs|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has conducted extensive pre-compromise reconnaissance to learn about the target organization’s network.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1590|Gather Victim Network Information|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has staged collected data in password-protected archives.(Citation: Microsoft Volt Typhoon May 2023)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1074|Data Staged|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has compromised small office and home office (SOHO) network edge devices, many of which were located in the same geographic area as the victim, to proxy network traffic.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1584.008|Network Devices|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has created and accessed a file named rult3uil.log on compromised domain controllers to capture keypresses and command execution.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Network|T1056.001|Keylogging|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used legitimate looking filenames for compressed copies of the ntds.dit database and used names including cisco_up.exe, cl64.exe, vm3dservice.exe, watchdogd.exe, Win.exe, WmiPreSV.exe, and WmiPrvSE.exe for the Earthworm and Fast Reverse Proxy tools.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) relies primarily on valid credentials for persistence.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used the Windows command line to perform hands-on-keyboard activities in targeted environments including for discovery.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)

|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has appended copies of the ntds.dit database with a .gif file extension.(Citation: Secureworks BRONZE SILHOUETTE May 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1036.008|Masquerade File Type|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has leveraged WMIC for execution, remote system discovery, and to create and use temporary directories.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1047|Windows Management Instrumentation|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used VPNs to connect to victim environments and enable post-exploitation actions.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has executed multiple commands to enumerate network topology and settings including  `ipconfig`, `netsh interface firewall show all`, and `netsh interface portproxy show all`.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1016|System Network Configuration Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has run `net group` in compromised environments to discover domain groups.(Citation: Secureworks BRONZE SILHOUETTE May 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1069.002|Domain Groups|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used multiple methods, including [Ping](https://attack.mitre.org/software/S0097), to enumerate systems on compromised networks.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has obtained the victim's system timezone.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, Network, Linux, macOS|T1124|System Time Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has archived the ntds.dit database as a multi-volume password-protected archive with 7-Zip.(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has gained initial access by exploiting privilege escalation vulnerabilities in the operating system or network services.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1068|Exploitation for Privilege Escalation|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used `wevtutil.exe` and the PowerShell command `Get-EventLog security` to enumerate Windows logs to search for successful logons.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1654|Log Enumeration|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used PowerShell including for remote system discovery.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)

|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used the built-in [netsh](https://attack.mitre.org/software/S0108) `port proxy` command to create proxies on compromised systems to facilitate access.(Citation: Microsoft Volt Typhoon May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090.001|Internal Proxy|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has obtained a screenshot of the victim's system using the gdi32.dll and gdiplus.dll libraries.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1113|Screen Capture|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has discovered file system types, drive names, size, and free space on compromised systems.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has conducted pre-compromise web searches for victim information.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1593|Search Open Websites/Domains|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has targeted the personal emails of key network and IT staff at victim organizations.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1589.002|Email Addresses|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has copied web shells between servers in targeted environments.(Citation: Secureworks BRONZE SILHOUETTE May 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1570|Lateral Tool Transfer|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) Volt Typhoon has used compromised Cisco and NETGEAR end-of-life SOHO routers implanted with KV Botnet malware to support operations.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)

|['enterprise-attack']|enterprise-attack|PRE|T1584.005|Botnet|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has conducted pre-compromise reconnaissance for victim host information.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1592|Gather Victim Host Information|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has targeted the browsing history of network administrators.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1217|Browser Information Discovery|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used `netstat -ano` on compromised hosts to enumerate network connections.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)                                                   
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1049|System Network Connections Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has executed `net user` and `quser` to enumerate local account information.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.001|Local Account|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used a version of the Awen web shell that employed AES encryption and decryption for C2 communications.(Citation: Secureworks BRONZE SILHOUETTE May 2023)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1573.001|Symmetric Cryptography|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used the Ultimate Packer for Executables (UPX) to obfuscate the FRP client files BrightmetricAgent.exe and SMSvcService.ex) and the port scanning utility ScanLine.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1027.002|Software Packing|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has run system checks to determine if they were operating in a virtualized environment.(Citation: Microsoft Volt Typhoon May 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1497.001|System Checks|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used ntds.util to create domain controller installation media containing usernames and password hashes.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)

|['enterprise-attack']|enterprise-attack|Windows|T1003.003|NTDS|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has attempted to access hashed credentials from the LSASS process memory space.(Citation: Microsoft Volt Typhoon May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)

|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used `net start` to list running services.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1007|System Service Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has compromised Virtual Private Servers (VPS) to proxy C2 traffic.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1584.003|Virtual Private Server|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used commercial tools, LOTL utilities, and appliances already present on the system for group and user discovery.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Office Suite, Identity Provider|T1069|Permission Groups Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used Brightmetricagent.exe which contains a command- line interface (CLI) library that can leverage command shells including Z Shell (zsh).(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|macOS, Linux, Network|T1059.004|Unix Shell|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has collected window title information from compromised systems.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)

|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1010|Application Window Discovery|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has run `net localgroup administrators` in compromised environments to enumerate accounts.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)

|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1069.001|Local Groups|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has obtained victim's screen dimension and display device information.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1120|Peripheral Device Discovery|




[Volt Typhoon](https://attack.mitre.org/groups/G1017) has targeted network administrator browser data including browsing history and stored credentials.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)

|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1555.003|Credentials from Web Browsers|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has conducted extensive reconnaissance pre-compromise to gain information about the targeted organization.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1591|Gather Victim Org Information|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has conducted extensive reconnaissance of victim networks including identifying network topologies.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1590.004|Network Topology|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used public tools and executed the PowerShell command `Get-EventLog security -instanceid 4624` to identify associated user and computer account names.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used multi-hop proxies for command-and-control infrastructure.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090.003|Multi-hop Proxy|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has conducted pre-compromise reconnaissance on victim-owned sites.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1594|Search Victim-Owned Websites|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has exploited zero-day vulnerabilities for initial access.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1587.004|Exploits|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used native tools and processes including living off the land binaries or “LOLBins" to maintain and expand access to the victim networks.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1218|System Binary Proxy Execution|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used webshells, including ones named AuditReport.jspx and iisstart.aspx, in compromised environments.(Citation: Secureworks BRONZE SILHOUETTE May 2023)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used `netsh` to create a PortProxy Registry modification on a compromised server running the Paessler Router Traffic Grapher (PRTG).(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1112|Modify Registry|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has run `net group /dom` and `net group "Domain Admins" /dom` in compromised environments for account discovery.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has inspected server logs to remove their IPs.(Citation: Secureworks BRONZE SILHOUETTE May 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1070.007|Clear Network Connection History and Configurations|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has obtained the victim's system current location.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, IaaS|T1614|System Location Discovery|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has identified target network security measures as part of pre-compromise reconnaissance.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1590.006|Network Security Appliances|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has saved stolen files including the `ntds.dit` database and the `SYSTEM` and `SECURITY` Registry hives locally to the `C:\Windows\Temp\` directory.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1074.001|Local Data Staging|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has employed [Ping](https://attack.mitre.org/software/S0097) to check network connectivity.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1016.001|Internet Connection Discovery|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has accessed a Local State file that contains the AES key used to encrypt passwords stored in the Chrome browser.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1552.004|Private Keys|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has downloaded an outdated version of comsvcs.dll to a compromised domain controller in a non-standard folder.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has obtained credentials insecurely stored on targeted network appliances.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1552|Unsecured Credentials|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has run `rd /S` to delete their working directories and deleted systeminfo.dat from `C:\Users\Public\Documentsfiles`.(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)

|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used publicly available exploit code for initial access.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1588.006|Vulnerabilities|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has queried the Registry on compromised systems, `reg query hklm\software\`, for information on installed software including PuTTY.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1012|Query Registry|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used FOFA, Shodan, and Censys to search for exposed victim infrastructure.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1596.005|Scan Databases|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used legitimate network and forensic tools and customized versions of open-source tools for C2.(Citation: Microsoft Volt Typhoon May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has gathered victim identify information during pre-compromise reconnaissance. (Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1589|Gather Victim Identity Information|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has stolen files from a sensitive file server and the Active Directory database from targeted environments, and used [Wevtutil](https://attack.mitre.org/software/S0645) to extract event log information.(Citation: Joint Cybersecurity Advisory Volt Typhoon June 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[Volt Typhoon](https://attack.mitre.org/groups/G1017) has used compromised domain accounts to authenticate to devices on compromised networks.(Citation: Microsoft Volt Typhoon May 2023)(Citation: Secureworks BRONZE SILHOUETTE May 2023)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1078.002|Domain Accounts|



[Volt Typhoon](https://attack.mitre.org/groups/G1017) has executed the Windows-native `vssadmin` command to create volume shadow copies.(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)
|['enterprise-attack']|enterprise-attack|Windows, Network|T1006|Direct Volume Access|

