# APT39 - G0087

**Created**: 2019-02-19T16:01:38.585Z

**Modified**: 2024-04-11T02:59:52.392Z

**Contributors**: 

## Aliases

APT39,ITG07,Chafer,Remix Kitten

## Description

[APT39](https://attack.mitre.org/groups/G0087) is one of several names for cyber espionage activity conducted by the Iranian Ministry of Intelligence and Security (MOIS) through the front company Rana Intelligence Computing since at least 2014. [APT39](https://attack.mitre.org/groups/G0087) has primarily targeted the travel, hospitality, academic, and telecommunications industries in Iran and across Asia, Africa, Europe, and North America to track individuals and entities considered to be a threat by the MOIS.(Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer Dec 2015)(Citation: FBI FLASH APT39 September 2020)(Citation: Dept. of Treasury Iran Sanctions September 2020)(Citation: DOJ Iran Indictments September 2020)

## Techniques Used


[APT39](https://attack.mitre.org/groups/G0087) has used different versions of Mimikatz to obtain credentials.(Citation: BitDefender Chafer May 2020)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1003|OS Credential Dumping|


[APT39](https://attack.mitre.org/groups/G0087) has used tools capable of stealing contents of the clipboard.(Citation: Symantec Chafer February 2018)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1115|Clipboard Data|


[APT39](https://attack.mitre.org/groups/G0087) has used malware to set <code>LoadAppInit_DLLs</code> in the Registry key <code>SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows</code> in order to establish persistence.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1546.010|AppInit DLLs|


[APT39](https://attack.mitre.org/groups/G0087) has used malware to turn off the <code>RequireSigned</code> feature which ensures only signed DLLs can be run on Windows.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Windows, macOS|T1553.006|Code Signing Policy Modification|


[APT39](https://attack.mitre.org/groups/G0087) has maintained persistence using the startup folder.(Citation: FireEye APT39 Jan 2019)
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[APT39](https://attack.mitre.org/groups/G0087) has used various tools to proxy C2 communications.(Citation: BitDefender Chafer May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090.002|External Proxy|


[APT39](https://attack.mitre.org/groups/G0087) has used [CrackMapExec](https://attack.mitre.org/software/S0488) and a custom port scanner known as BLUETORCH for network scanning.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers, Network|T1046|Network Service Discovery|


[APT39](https://attack.mitre.org/groups/G0087) has used PowerShell to execute malicious code.(Citation: BitDefender Chafer May 2020)(Citation: Symantec Chafer February 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[APT39](https://attack.mitre.org/groups/G0087) has used tools for capturing keystrokes.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Network|T1056.001|Keylogging|


[APT39](https://attack.mitre.org/groups/G0087) has used various tools to steal files from the compromised host.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[APT39](https://attack.mitre.org/groups/G0087) has used malware to decrypt encrypted CAB files.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[APT39](https://attack.mitre.org/groups/G0087) has used the post exploitation tool [CrackMapExec](https://attack.mitre.org/software/S0488) to enumerate network shares.(Citation: BitDefender Chafer May 2020)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1135|Network Share Discovery|


[APT39](https://attack.mitre.org/groups/G0087) has modified LNK shortcuts.(Citation: FireEye APT39 Jan 2019)
|['enterprise-attack']|enterprise-attack|Windows|T1547.009|Shortcut Modification|


[APT39](https://attack.mitre.org/groups/G0087) has modified and used customized versions of publicly-available tools like PLINK and [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: BitDefender Chafer May 2020)(Citation: IBM ITG07 June 2019)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[APT39](https://attack.mitre.org/groups/G0087) has been seen using RDP for lateral movement and persistence, in some cases employing the rdpwinst tool for mangement of multiple sessions.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[APT39](https://attack.mitre.org/groups/G0087) used [Remexi](https://attack.mitre.org/software/S0375) to collect usernames from the system.(Citation: Symantec Chafer Dec 2015)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[APT39](https://attack.mitre.org/groups/G0087) has used malware to drop encrypted CAB files.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.013|Encrypted/Encoded File|


[APT39](https://attack.mitre.org/groups/G0087) has used post-exploitation tools including RemCom and the Non-sucking Service Manager (NSSM) to execute processes.(Citation: BitDefender Chafer May 2020)(Citation: Symantec Chafer February 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1569.002|Service Execution|


[APT39](https://attack.mitre.org/groups/G0087) has utilized AutoIt malware scripts embedded in Microsoft Office documents or malicious links.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1059.010|AutoHotKey & AutoIT|


[APT39](https://attack.mitre.org/groups/G0087) has sent spearphishing emails in an attempt to lure users to click on a malicious link.(Citation: FireEye APT39 Jan 2019)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[APT39](https://attack.mitre.org/groups/G0087) has created scheduled tasks for persistence.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[APT39](https://attack.mitre.org/groups/G0087) has sent spearphishing emails in an attempt to lure users to click on a malicious attachment.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[APT39](https://attack.mitre.org/groups/G0087) has exfiltrated stolen victim data through C2 communications.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1041|Exfiltration Over C2 Channel|


[APT39](https://attack.mitre.org/groups/G0087) has packed tools with UPX, and has repacked a modified version of [Mimikatz](https://attack.mitre.org/software/S0002) to thwart anti-virus detection.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1027.002|Software Packing|


[APT39](https://attack.mitre.org/groups/G0087) has downloaded tools to compromised hosts.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[APT39](https://attack.mitre.org/groups/G0087) has installed ANTAK and ASPXSPY web shells.(Citation: FireEye APT39 Jan 2019)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[APT39](https://attack.mitre.org/groups/G0087) has used malware to delete files after they are deployed on a compromised host.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[APT39](https://attack.mitre.org/groups/G0087) has used WinRAR and 7-Zip to compress an archive stolen data.(Citation: FireEye APT39 Jan 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[APT39](https://attack.mitre.org/groups/G0087) has communicated with C2 through files uploaded to and downloaded from DropBox.(Citation: BitDefender Chafer May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1102.002|Bidirectional Communication|


[APT39](https://attack.mitre.org/groups/G0087) has utilized tools to aggregate data prior to exfiltration.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1074.001|Local Data Staging|


[APT39](https://attack.mitre.org/groups/G0087) has used various strains of malware to query the Registry.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1012|Query Registry|


[APT39](https://attack.mitre.org/groups/G0087) has used tools with the ability to search for files on a compromised host.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[APT39](https://attack.mitre.org/groups/G0087) has used a screen capture utility to take screenshots on a compromised host.(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1113|Screen Capture|


[APT39](https://attack.mitre.org/groups/G0087) has used Mimikatz, Windows Credential Editor and ProcDump to dump credentials.(Citation: FireEye APT39 Jan 2019)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[APT39](https://attack.mitre.org/groups/G0087) has used the Smartftp Password Decryptor tool to decrypt FTP passwords.(Citation: BitDefender Chafer May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1555|Credentials from Password Stores|


[APT39](https://attack.mitre.org/groups/G0087) has utilized custom scripts to perform internal reconnaissance.(Citation: FireEye APT39 Jan 2019)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, IaaS, Office Suite, Identity Provider|T1059|Command and Scripting Interpreter|


[APT39](https://attack.mitre.org/groups/G0087) has used [NBTscan](https://attack.mitre.org/software/S0590) and custom tools to discover remote systems.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)(Citation: Symantec Chafer February 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[APT39](https://attack.mitre.org/groups/G0087) has used remote access tools that leverage DNS in communications with C2.(Citation: BitDefender Chafer May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.004|DNS|


[APT39](https://attack.mitre.org/groups/G0087) has utilized tools to capture mouse movements.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1056|Input Capture|


[APT39](https://attack.mitre.org/groups/G0087) has used stolen credentials to compromise Outlook Web Access (OWA).(Citation: FireEye APT39 Jan 2019)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[APT39](https://attack.mitre.org/groups/G0087) has utilized malicious VBS scripts in malware.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[APT39](https://attack.mitre.org/groups/G0087) used secure shell (SSH) to move laterally among their targets.(Citation: FireEye APT39 Jan 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS|T1021.004|SSH|


[APT39](https://attack.mitre.org/groups/G0087) leveraged spearphishing emails with malicious attachments to initially compromise victims.(Citation: FireEye APT39 Jan 2019)(Citation: Symantec Chafer February 2018)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[APT39](https://attack.mitre.org/groups/G0087) leveraged spearphishing emails with malicious links to initially compromise victims.(Citation: FireEye APT39 Jan 2019)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[APT39](https://attack.mitre.org/groups/G0087) has used SMB for lateral movement.(Citation: Symantec Chafer February 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1021.002|SMB/Windows Admin Shares|


[APT39](https://attack.mitre.org/groups/G0087) has used SQL injection for initial compromise.(Citation: Symantec Chafer February 2018)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[APT39](https://attack.mitre.org/groups/G0087) has used the BITS protocol to exfiltrate stolen data from a compromised host.(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1197|BITS Jobs|


[APT39](https://attack.mitre.org/groups/G0087) has created accounts on multiple compromised hosts to perform actions within the network.(Citation: BitDefender Chafer May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, Containers|T1136.001|Local Account|


[APT39](https://attack.mitre.org/groups/G0087) has used Ncrack to reveal credentials.(Citation: FireEye APT39 Jan 2019)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110|Brute Force|


[APT39](https://attack.mitre.org/groups/G0087) has used a command line utility and a network scanner written in python.(Citation: BitDefender Chafer May 2020)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1059.006|Python|


[APT39](https://attack.mitre.org/groups/G0087) used custom tools to create SOCK5 and custom protocol proxies between infected hosts.(Citation: FireEye APT39 Jan 2019)(Citation: BitDefender Chafer May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090.001|Internal Proxy|


[APT39](https://attack.mitre.org/groups/G0087) has used malware disguised as Mozilla Firefox and a tool named mfevtpse.exe to proxy C2 communications, closely mimicking a legitimate McAfee file mfevtps.exe.(Citation: BitDefender Chafer May 2020)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[APT39](https://attack.mitre.org/groups/G0087) has used HTTP in communications with C2.(Citation: BitDefender Chafer May 2020)(Citation: FBI FLASH APT39 September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|

