# FIN6 - G0037

**Created**: 2017-05-31T21:32:06.015Z

**Modified**: 2024-01-08T22:13:27.588Z

**Contributors**: Center for Threat-Informed Defense (CTID),Drew Church, Splunk

## Aliases

FIN6,Magecart Group 6,ITG08,Skeleton Spider,TAAL,Camouflage Tempest

## Description

[FIN6](https://attack.mitre.org/groups/G0037) is a cyber crime group that has stolen payment card data and sold it for profit on underground marketplaces. This group has aggressively targeted and compromised point of sale (PoS) systems in the hospitality and retail sectors.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)

## Techniques Used


[FIN6](https://attack.mitre.org/groups/G0037) has used Metasploit’s [PsExec](https://attack.mitre.org/software/S0029) NTDSGRAB module to obtain a copy of the victim's Active Directory database.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[FIN6](https://attack.mitre.org/groups/G0037) has encoded data gathered from the victim with a simple substitution cipher and single-byte XOR using the 0xAA key, and Base64 with character permutation.(Citation: FireEye FIN6 April 2016)(Citation: Trend Micro FIN6 October 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1560.003|Archive via Custom Method|


[FIN6](https://attack.mitre.org/groups/G0037) has targeted victims with e-mails containing malicious attachments.(Citation: Visa FIN6 Feb 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[FIN6](https://attack.mitre.org/groups/G0037) has used encoded PowerShell commands.(Citation: Visa FIN6 Feb 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1027.010|Command Obfuscation|


[FIN6](https://attack.mitre.org/groups/G0037) has used malicious JavaScript to steal payment card data from e-commerce sites.(Citation: Trend Micro FIN6 October 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux|T1059.007|JavaScript|


[FIN6](https://attack.mitre.org/groups/G0037) has used scripting to iterate through a list of compromised PoS systems, copy data to a log file, and remove the original data files.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network, IaaS, Office Suite, Identity Provider|T1059|Command and Scripting Interpreter|


[FIN6](https://attack.mitre.org/groups/G0037) used the Plink command-line utility to create SSH tunnels to C2 servers.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1572|Protocol Tunneling|


[FIN6](https://attack.mitre.org/groups/G0037) has collected schemas and user accounts from systems running SQL Server.(Citation: Visa FIN6 Feb 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS, SaaS, IaaS, Office Suite|T1213|Data from Information Repositories|


[FIN6](https://attack.mitre.org/groups/G0037) has used Pastebin and Google Storage to host content for their operations.(Citation: FireEye FIN6 Apr 2019)	

|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1102|Web Service|


[FIN6](https://attack.mitre.org/groups/G0037) has collected and exfiltrated payment card data from compromised systems.(Citation: Trend Micro FIN6 October 2019)(Citation: RiskIQ British Airways September 2018)(Citation: RiskIQ Newegg September 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[FIN6](https://attack.mitre.org/groups/G0037) has deployed a utility script named <code>kill.bat</code> to disable anti-virus.(Citation: FireEye FIN6 Apr 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|


[FIN6](https://attack.mitre.org/groups/G0037) has used tools to exploit Windows vulnerabilities in order to escalate privileges. The tools targeted CVE-2013-3660, CVE-2011-2005, and CVE-2010-4398, all of which could allow local users to access kernel-level privileges.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Containers|T1068|Exploitation for Privilege Escalation|


[FIN6](https://attack.mitre.org/groups/G0037) has used has used Metasploit’s named-pipe impersonation technique to escalate privileges.(Citation: FireEye FIN6 Apr 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1134|Access Token Manipulation|


[FIN6](https://attack.mitre.org/groups/G0037) has used <code>kill.bat</code> script to disable security tools.(Citation: FireEye FIN6 Apr 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1059.003|Windows Command Shell|


[FIN6](https://attack.mitre.org/groups/G0037) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002), [Cobalt Strike](https://attack.mitre.org/software/S0154), and [AdFind](https://attack.mitre.org/software/S0552).(Citation: Security Intelligence More Eggs Aug 2019)(Citation: FireEye FIN6 Apr 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1588.002|Tool|


[FIN6](https://attack.mitre.org/groups/G0037) has removed files from victim machines.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[FIN6](https://attack.mitre.org/groups/G0037) has used Registry Run keys to establish persistence for its downloader tools known as HARDTACK and SHIPBREAD.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[FIN6](https://attack.mitre.org/groups/G0037) has used Metasploit’s [PsExec](https://attack.mitre.org/software/S0029) NTDSGRAB module to obtain a copy of the victim's Active Directory database.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)	
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1003.003|NTDS|


[FIN6](https://attack.mitre.org/groups/G0037) has used scheduled tasks to establish persistence for various malware it uses, including downloaders known as HARDTACK and SHIPBREAD and [FrameworkPOS](https://attack.mitre.org/software/S0503).(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1053.005|Scheduled Task|


[FIN6](https://attack.mitre.org/groups/G0037) has used a script to iterate through a list of compromised PoS systems, copy and remove data to a log file, and to bind to events from the submit payment button.(Citation: FireEye FIN6 April 2016)(Citation: Trend Micro FIN6 October 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, IaaS, SaaS, Office Suite|T1119|Automated Collection|


[FIN6](https://attack.mitre.org/groups/G0037) used publicly available tools (including Microsoft's built-in SQL querying tool, osql.exe) to map the internal network and conduct reconnaissance against Active Directory, Structured Query Language (SQL) servers, and NetBIOS.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[FIN6](https://attack.mitre.org/groups/G0037) used publicly available tools (including Microsoft's built-in SQL querying tool, osql.exe) to map the internal network and conduct reconnaissance against Active Directory, Structured Query Language (SQL) servers, and NetBIOS.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Linux, macOS, Containers, Network|T1046|Network Service Discovery|


[FIN6](https://attack.mitre.org/groups/G0037) has created Windows services to execute encoded PowerShell commands.(Citation: FireEye FIN6 Apr 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1569.002|Service Execution|


[FIN6](https://attack.mitre.org/groups/G0037) has sent stolen payment card data to remote servers via HTTP POSTs.(Citation: Trend Micro FIN6 October 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1048.003|Exfiltration Over Unencrypted Non-C2 Protocol|


[FIN6](https://attack.mitre.org/groups/G0037) has renamed the "psexec" service name to "mstdc" to masquerade as a legitimate Windows service.(Citation: FireEye FIN6 Apr 2019)	
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, macOS|T1036.004|Masquerade Task or Service|


[FIN6](https://attack.mitre.org/groups/G0037) has used malicious documents to lure victims into allowing execution of PowerShell scripts.(Citation: Visa FIN6 Feb 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[FIN6](https://attack.mitre.org/groups/G0037) used RDP to move laterally in victim networks.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1021.001|Remote Desktop Protocol|


[FIN6](https://attack.mitre.org/groups/G0037) has used Comodo code-signing certificates.(Citation: Security Intelligence More Eggs Aug 2019)	
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows|T1553.002|Code Signing|


 [FIN6](https://attack.mitre.org/groups/G0037) has used PowerShell to gain access to merchant's networks, and a Metasploit PowerShell module to download and execute shellcode and to set up a local listener.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)(Citation: Visa FIN6 Feb 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1059.001|PowerShell|


Following data collection, [FIN6](https://attack.mitre.org/groups/G0037) has compressed log files into a ZIP archive prior to staging and exfiltration.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1560|Archive Collected Data|


[FIN6](https://attack.mitre.org/groups/G0037) has used fake job advertisements sent via LinkedIn to spearphish targets.(Citation: Security Intelligence More Eggs Aug 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1566.003|Spearphishing via Service|


[FIN6](https://attack.mitre.org/groups/G0037) has used the Stealer One credential stealer to target web browsers.(Citation: Visa FIN6 Feb 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1555.003|Credentials from Web Browsers|


[FIN6](https://attack.mitre.org/groups/G0037) actors have compressed data from remote systems and moved it to another staging system before exfiltration.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Linux, macOS|T1074.002|Remote Data Staging|


[FIN6](https://attack.mitre.org/groups/G0037) has extracted password hashes from ntds.dit to crack offline.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network, Office Suite, Identity Provider|T1110.002|Password Cracking|


[FIN6](https://attack.mitre.org/groups/G0037) has used the Stealer One credential stealer to target e-mail and file transfer utilities including FTP.(Citation: Visa FIN6 Feb 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, IaaS|T1555|Credentials from Password Stores|


[FIN6](https://attack.mitre.org/groups/G0037) has used WMI to automate the remote execution of PowerShell scripts.(Citation: Security Intelligence More Eggs Aug 2019)	
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1047|Windows Management Instrumentation|


[FIN6](https://attack.mitre.org/groups/G0037) used the Plink command-line utility to create SSH tunnels to C2 servers.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1573.002|Asymmetric Cryptography|


[FIN6](https://attack.mitre.org/groups/G0037) has used [Windows Credential Editor](https://attack.mitre.org/software/S0005) for credential dumping.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)	

|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1003.001|LSASS Memory|


[FIN6](https://attack.mitre.org/groups/G0037) has used Metasploit Bind and Reverse TCP stagers.(Citation: Trend Micro FIN6 October 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, macOS, Network|T1095|Non-Application Layer Protocol|


To move laterally on a victim network, [FIN6](https://attack.mitre.org/groups/G0037) has used credentials stolen from various systems on which it gathered usernames and password hashes.(Citation: FireEye FIN6 April 2016)(Citation: FireEye FIN6 Apr 2019)(Citation: Visa FIN6 Feb 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[FIN6](https://attack.mitre.org/groups/G0037) has used tools like Adfind to query users, groups, organizational units, and trusts.(Citation: FireEye FIN6 Apr 2019)	

|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1069.002|Domain Groups|


TRINITY malware used by [FIN6](https://attack.mitre.org/groups/G0037) identifies payment card track data on the victim and then copies it to a local file in a subdirectory of <code>C:\Windows\</code>.(Citation: FireEye FIN6 April 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1074.001|Local Data Staging|

