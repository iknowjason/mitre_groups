# Sandworm Team - G0034

**Created**: 2017-05-31T21:32:04.588Z

**Modified**: 2024-09-12T17:37:44.040Z

**Contributors**: Dragos Threat Intelligence,Hakan KARABACAK

## Aliases

Sandworm Team,ELECTRUM,Telebots,IRON VIKING,BlackEnergy (Group),Quedagh,Voodoo Bear,IRIDIUM,Seashell Blizzard,FROZENBARENTS,APT44

## Description

[Sandworm Team](https://attack.mitre.org/groups/G0034) is a destructive threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) Main Center for Special Technologies (GTsST) military unit 74455.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) This group has been active since at least 2009.(Citation: iSIGHT Sandworm 2014)(Citation: CrowdStrike VOODOO BEAR)(Citation: USDOJ Sandworm Feb 2020)(Citation: NCSC Sandworm Feb 2020)

In October 2020, the US indicted six GRU Unit 74455 officers associated with [Sandworm Team](https://attack.mitre.org/groups/G0034) for the following cyber operations: the 2015 and 2016 attacks against Ukrainian electrical companies and government organizations, the 2017 worldwide [NotPetya](https://attack.mitre.org/software/S0368) attack, targeting of the 2017 French presidential campaign, the 2018 [Olympic Destroyer](https://attack.mitre.org/software/S0365) attack against the Winter Olympic Games, the 2018 operation against the Organisation for the Prohibition of Chemical Weapons, and attacks against the country of Georgia in 2018 and 2019.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020) Some of these were conducted with the assistance of GRU Unit 26165, which is also referred to as [APT28](https://attack.mitre.org/groups/G0007).(Citation: US District Court Indictment GRU Oct 2018)

## Techniques Used


[Sandworm Team](https://attack.mitre.org/groups/G0034) staged compromised versions of legitimate software installers in forums to enable initial access to executing user.(Citation: mandiant_apt44_unearthing_sandworm)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1608.001|Upload Malware|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has established social media accounts to disseminate victim internal-only documents and other sensitive data.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1585.001|Social Media Accounts|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has scanned network infrastructure for vulnerabilities as part of its operational planning.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1595.002|Vulnerability Scanning|


[Sandworm Team](https://attack.mitre.org/groups/G0034)'s BCS-server tool uses base64 encoding and HTML tags for the communication traffic between the C2 server.(Citation: ESET Telebots Dec 2016)	
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1132.001|Standard Encoding|


[Sandworm Team](https://attack.mitre.org/groups/G0034) creates credential capture webpages to compromise existing, legitimate social media accounts.(Citation: Slowik Sandworm 2021)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1586.001|Social Media Accounts|


In 2017, [Sandworm Team](https://attack.mitre.org/groups/G0034) conducted technical research related to vulnerabilities associated with websites used by the Korean Sport and Olympic Committee, a Korean power company, and a Korean airport.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1588.006|Vulnerabilities|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used ROT13 encoding, AES encryption and compression with the zlib library for their Python-based backdoor.(Citation: ESET Telebots Dec 2016)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1027.010|Command Obfuscation|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used intercepter-NG to sniff passwords in network traffic.(Citation: ESET Telebots Dec 2016)	
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network, IaaS|T1040|Network Sniffing|


[Sandworm Team](https://attack.mitre.org/groups/G0034) leveraged SHARPIVORY, a .NET dropper that writes embedded payload to disk and uses scheduled tasks to persist on victim machines.(Citation: mandiant_apt44_unearthing_sandworm)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows|T1053.005|Scheduled Task|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has sent system information to its C2 server using HTTP.(Citation: ESET Telebots Dec 2016)	
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1041|Exfiltration Over C2 Channel|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used `ntdsutil.exe` to back up the Active Directory database, likely for credential access.(Citation: Microsoft Prestige ransomware October 2022)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows|T1003.003|NTDS|


[Sandworm Team](https://attack.mitre.org/groups/G0034) masqueraded malicious installers as Windows update packages to evade defense and entice users to execute binaries.(Citation: Leonard TAG 2023)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Containers|T1036|Masquerading|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used stolen credentials to access administrative accounts within the domain.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: Microsoft Prestige ransomware October 2022)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1078.002|Domain Accounts|


[Sandworm Team](https://attack.mitre.org/groups/G0034) exploits public-facing applications for initial access and to acquire infrastructure, such as exploitation of the EXIM mail transfer agent in Linux systems.(Citation: NSA Sandworm 2020)(Citation: Leonard TAG 2023)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[Sandworm Team](https://attack.mitre.org/groups/G0034)'s BCS-server tool can create an internal proxy server to redirect traffic from the adversary-controlled C2 to internal servers which may not be connected to the internet, but are interconnected locally.(Citation: ESET Telebots Dec 2016)	
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network|T1090|Proxy|


[Sandworm Team](https://attack.mitre.org/groups/G0034) used information stealer malware to collect browser session cookies.(Citation: Leonard TAG 2023)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, SaaS, Office Suite|T1539|Steal Web Session Cookie|


[Sandworm Team](https://attack.mitre.org/groups/G0034) exfiltrates data of interest from enterprise databases using Adminer.(Citation: Leonard TAG 2023)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, Windows, macOS, SaaS, IaaS, Office Suite|T1213|Data from Information Repositories|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used PowerShell scripts to run a credential harvesting tool in memory to evade defenses.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: Dragos Crashoverride 2018) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows|T1059.001|PowerShell|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has exploited vulnerabilities in Microsoft PowerPoint via OLE objects (CVE-2014-4114) and Microsoft Word via crafted TIFF images (CVE-2013-3906).(Citation: iSight Sandworm Oct 2014)(Citation: TrendMicro Sandworm October 2014)(Citation: McAfee Sandworm November 2013)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, Windows, macOS|T1203|Exploitation for Client Execution|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used a large-scale botnet to target Small Office/Home Office (SOHO) network devices.(Citation: NCSC Cyclops Blink February 2022)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1584.005|Botnet|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has crafted phishing emails containing malicious hyperlinks.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has developed malware for its operations, including malicious mobile applications and destructive malware such as [NotPetya](https://attack.mitre.org/software/S0368) and [Olympic Destroyer](https://attack.mitre.org/software/S0365).(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1587.001|Malware|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used the commercially available tool RemoteExec for agentless remote code execution.(Citation: Microsoft Prestige ransomware October 2022)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network, SaaS|T1072|Software Deployment Tools|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used a tool to query Active Directory using LDAP, discovering information about computers listed in AD.(Citation: ESET Telebots Dec 2016)(Citation: Dragos Crashoverride 2018) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has crafted spearphishing emails with hyperlinks designed to trick unwitting recipients into revealing their account credentials.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1598.003|Spearphishing Link|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used Dropbear SSH with a hardcoded backdoor password to maintain persistence within the target network. [Sandworm Team](https://attack.mitre.org/groups/G0034) has also used VPN tunnels established in legitimate software company infrastructure to gain access to internal networks of that software company's users.(Citation: ESET BlackEnergy Jan 2016)(Citation: ESET Telebots June 2017)(Citation: ANSSI Sandworm January 2021)(Citation: mandiant_apt44_unearthing_sandworm)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used port 6789 to accept connections on the group's SSH server.(Citation: ESET BlackEnergy Jan 2016)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1571|Non-Standard Port|


[Sandworm Team](https://attack.mitre.org/groups/G0034)'s CredRaptor tool can collect saved passwords from various internet browsers.(Citation: ESET Telebots Dec 2016)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1555.003|Credentials from Web Browsers|


[Sandworm Team](https://attack.mitre.org/groups/G0034) attempts to stop the MSSQL Windows service to ensure successful encryption of locked files.(Citation: Microsoft Prestige ransomware October 2022) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, Linux, macOS|T1489|Service Stop|


[Sandworm Team](https://attack.mitre.org/groups/G0034) used malware to enumerate email settings, including usernames and passwords, from the M.E.Doc application.(Citation: ESET Telebots July 2017)	
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, Office Suite|T1087.003|Email Account|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used [Impacket](https://attack.mitre.org/software/S0357)’s WMIexec module for remote code execution and VBScript to run WMI queries.(Citation: Dragos Crashoverride 2018)(Citation: Microsoft Prestige ransomware October 2022)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows|T1047|Windows Management Instrumentation|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has copied payloads to the `ADMIN$` share of remote systems and run <code>net use</code> to connect to network shares.(Citation: Dragos Crashoverride 2018)(Citation: Microsoft Prestige ransomware October 2022)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows|T1021.002|SMB/Windows Admin Shares|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used backdoors that can delete files used in an attack from an infected system.(Citation: ESET Telebots Dec 2016)(Citation: ESET Telebots July 2017)(Citation: Mandiant-Sandworm-Ukraine-2022) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has delivered malicious Microsoft Office and ZIP file attachments via spearphishing emails.(Citation: iSight Sandworm Oct 2014)(Citation: US-CERT Ukraine Feb 2016)(Citation: ESET Telebots Dec 2016)(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: Google_WinRAR_vuln_2023)(Citation: mandiant_apt44_unearthing_sandworm)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Sandworm Team](https://attack.mitre.org/groups/G0034) have used previously acquired legitimate credentials prior to attacks.(Citation: US-CERT Ukraine Feb 2016)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has tricked unwitting recipients into clicking on spearphishing attachments and enabling malicious macros embedded within files.(Citation: ESET Telebots Dec 2016)(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Sandworm Team](https://attack.mitre.org/groups/G0034)'s research of potential victim organizations included the identification and collection of employee information.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1589.003|Employee Names|


[Sandworm Team](https://attack.mitre.org/groups/G0034) conducted technical reconnaissance of the Parliament of Georgia's official internet domain prior to its 2019 attack.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1590.001|Domain Properties|


[Sandworm Team](https://attack.mitre.org/groups/G0034) had gathered user, IP address, and server data related to RDP sessions on a compromised host. It has also accessed network diagram files useful for understanding how a host's network was configured.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: Dragos Crashoverride 2018) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, IaaS, Linux, macOS, Network|T1049|System Network Connections Discovery|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has enumerated files on a compromised host.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: Dragos Crashoverride 2018)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has acquired open-source tools for their operations, including [Invoke-PSImage](https://attack.mitre.org/software/S0231), which was used to establish an encrypted channel from a compromised host to [Sandworm Team](https://attack.mitre.org/groups/G0034)'s C2 server in preparation for the 2018 Winter Olympics attack, as well as [Impacket](https://attack.mitre.org/software/S0357) and RemoteExec, which were used in their 2022 [Prestige](https://attack.mitre.org/software/S1058) operations.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: Microsoft Prestige ransomware October 2022) Additionally, [Sandworm Team](https://attack.mitre.org/groups/G0034) has used [Empire](https://attack.mitre.org/software/S0363), [Cobalt Strike](https://attack.mitre.org/software/S0154) and [PoshC2](https://attack.mitre.org/software/S0378).(Citation: mandiant_apt44_unearthing_sandworm)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1588.002|Tool|


[Sandworm Team](https://attack.mitre.org/groups/G0034) uses [Prestige](https://attack.mitre.org/software/S1058) to disable and restore file system redirection by using the following functions:  `Wow64DisableWow64FsRedirection()` and `Wow64RevertWow64FsRedirection()`.(Citation: Microsoft Prestige ransomware October 2022)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, macOS, Linux|T1106|Native API|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has leased servers from resellers instead of leasing infrastructure directly from hosting companies to enable its operations.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1583.004|Server|


[Sandworm Team](https://attack.mitre.org/groups/G0034) compromised legitimate Linux servers running the EXIM mail transfer agent for use in subsequent campaigns.(Citation: NSA Sandworm 2020)(Citation: Leonard TAG 2023)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1584.004|Server|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used remote administration tools or remote industrial control system client software for execution and to maliciously release electricity breakers.(Citation: US-CERT Ukraine Feb 2016)(Citation: Microsoft Prestige ransomware October 2022)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, Windows, macOS|T1219|Remote Access Software|


[Sandworm Team](https://attack.mitre.org/groups/G0034) used various third-party email campaign management services to deliver phishing emails.(Citation: Leonard TAG 2023)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1583|Acquire Infrastructure|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has conducted research against potential victim websites as part of its operational planning.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1594|Search Victim-Owned Websites|


In preparation for its attack against the 2018 Winter Olympics, [Sandworm Team](https://attack.mitre.org/groups/G0034) conducted online research of partner organizations listed on an official PyeongChang Olympics partnership site.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1591.002|Business Relationships|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used Base64 encoding within malware variants.(Citation: iSight Sandworm Oct 2014)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network|T1027|Obfuscated Files or Information|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used `move` to transfer files to a network share and has copied payloads--such as [Prestige](https://attack.mitre.org/software/S1058) ransomware--to an Active Directory Domain Controller and distributed via the Default Domain Group Policy Object.(Citation: Dragos Crashoverride 2018)(Citation: Microsoft Prestige ransomware October 2022) Additionally, [Sandworm Team](https://attack.mitre.org/groups/G0034) has transferred an ISO file into the OT network to gain initial access.(Citation: Mandiant-Sandworm-Ukraine-2022)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1570|Lateral Tool Transfer|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used its plainpwd tool, a modified version of [Mimikatz](https://attack.mitre.org/software/S0002), and comsvcs.dll to dump Windows credentials from system memory.(Citation: ESET Telebots Dec 2016)(Citation: ESET Telebots June 2017)(Citation: Microsoft Prestige ransomware October 2022)	
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows|T1003.001|LSASS Memory|


[Sandworm Team](https://attack.mitre.org/groups/G0034) used a backdoor which could execute a supplied DLL using rundll32.exe.(Citation: ESET Telebots July 2017)	
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows|T1218.011|Rundll32|


[Sandworm Team](https://attack.mitre.org/groups/G0034) temporarily disrupted service to Georgian government, non-government, and private sector websites after compromising a Georgian web hosting provider in 2019.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, Linux, macOS, Containers, IaaS|T1499|Endpoint Denial of Service|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has distributed [NotPetya](https://attack.mitre.org/software/S0368) by compromising the legitimate Ukrainian accounting software M.E.Doc and replacing a legitimate software update with a malicious one.(Citation: Secureworks NotPetya June 2017)(Citation: ESET Telebots June 2017)(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1195.002|Compromise Software Supply Chain|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has tricked unwitting recipients into clicking on malicious hyperlinks within emails crafted to resemble trustworthy senders.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used webshells including [P.A.S. Webshell](https://attack.mitre.org/software/S0598) to maintain access to victim networks.(Citation: ANSSI Sandworm January 2021)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has researched software code to enable supply-chain operations, most notably for the 2017 [NotPetya](https://attack.mitre.org/software/S0368) attack. [Sandworm Team](https://attack.mitre.org/groups/G0034) also collected a list of computers using specific software as part of its targeting efforts.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1592.002|Software|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used [Prestige](https://attack.mitre.org/software/S1058) ransomware to encrypt data at targeted organizations in transportation and related logistics industries in Ukraine and Poland.(Citation: Microsoft Prestige ransomware October 2022)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, IaaS|T1486|Data Encrypted for Impact|


[Sandworm Team](https://attack.mitre.org/groups/G0034) defaced approximately 15,000 websites belonging to Georgian government, non-government, and private sector organizations in 2019.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: UK NCSC Olympic Attacks October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, IaaS, Linux, macOS|T1491.002|External Defacement|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used dedicated network connections from one victim organization to gain unauthorized access to a separate organization.(Citation: US District Court Indictment GRU Unit 74455 October 2020) Additionally, [Sandworm Team](https://attack.mitre.org/groups/G0034) has accessed Internet service providers and telecommunication entities that provide mobile connectivity.(Citation: mandiant_apt44_unearthing_sandworm) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, SaaS, IaaS, Linux, macOS, Identity Provider, Office Suite|T1199|Trusted Relationship|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used a keylogger to capture keystrokes by using the SetWindowsHookEx function.(Citation: ESET Telebots Dec 2016)	
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, macOS, Linux, Network|T1056.001|Keylogging|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used the [BlackEnergy](https://attack.mitre.org/software/S0089) KillDisk component to corrupt the infected system's master boot record.(Citation: US-CERT Ukraine Feb 2016)(Citation: ESET Telebots June 2017)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network|T1561.002|Disk Structure Wipe|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has collected the username from a compromised host.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has created VBScripts to run an SSH server.(Citation: ESET BlackEnergy Jan 2016)(Citation: ESET Telebots Dec 2016)(Citation: ESET Telebots June 2017)(Citation: Dragos Crashoverride 2018) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has pushed additional malicious tools onto an infected system to steal user credentials, move laterally, and destroy data.(Citation: ESET Telebots Dec 2016)(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used [CaddyWiper](https://attack.mitre.org/software/S0693), [SDelete](https://attack.mitre.org/software/S0195), and the [BlackEnergy](https://attack.mitre.org/software/S0089) KillDisk component to overwrite files on victim systems. (Citation: US-CERT Ukraine Feb 2016)(Citation: ESET Telebots June 2017)(Citation: Mandiant-Sandworm-Ukraine-2022) Additionally, [Sandworm Team](https://attack.mitre.org/groups/G0034) has used the JUNKMAIL tool to overwrite files with null bytes.(Citation: mandiant_apt44_unearthing_sandworm)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, IaaS, Linux, macOS, Containers|T1485|Data Destruction|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has avoided detection by naming a malicious binary explorer.exe.(Citation: ESET Telebots Dec 2016)(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[Sandworm Team](https://attack.mitre.org/groups/G0034)'s BCS-server tool connects to the designated C2 server via HTTP.(Citation: ESET Telebots Dec 2016)	
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used a tool to query Active Directory using LDAP, discovering information about usernames listed in AD.(Citation: ESET Telebots Dec 2016)	
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has obtained valid emails addresses while conducting research against target organizations that were subsequently used in spearphishing campaigns.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1589.002|Email Addresses|


[Sandworm Team](https://attack.mitre.org/groups/G0034) staged compromised versions of legitimate software installers on forums to achieve initial, untargetetd access in victim environments.(Citation: mandiant_apt44_unearthing_sandworm) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, Windows, macOS|T1195|Supply Chain Compromise|


[Sandworm Team](https://attack.mitre.org/groups/G0034) researched Ukraine's unique legal entity identifier (called an "EDRPOU" number), including running queries on the EDRPOU website, in preparation for the [NotPetya](https://attack.mitre.org/software/S0368) attack. [Sandworm Team](https://attack.mitre.org/groups/G0034) has also researched third-party websites to help it craft credible spearphishing emails.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1593|Search Open Websites/Domains|


[Sandworm Team](https://attack.mitre.org/groups/G0034) used a backdoor to enumerate information about the infected system's operating system.(Citation: ESET Telebots July 2017)(Citation: US District Court Indictment GRU Unit 74455 October 2020)	
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has exfiltrated internal documents, files, and other data from compromised hosts.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[Sandworm Team](https://attack.mitre.org/groups/G0034)'s VBS backdoor can decode Base64-encoded data and save it to the %TEMP% folder. The group also decrypted received information using the Triple DES algorithm and decompresses it using GZip.(Citation: ESET Telebots Dec 2016)(Citation: ESET Telebots July 2017)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used the Telegram Bot API from Telegram Messenger to send and receive commands to its Python backdoor. [Sandworm Team](https://attack.mitre.org/groups/G0034) also used legitimate M.E.Doc software update check requests for sending and receiving commands and hosted malicious payloads on putdrive.com.(Citation: ESET Telebots Dec 2016)(Citation: ESET Telebots June 2017)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows|T1102.002|Bidirectional Communication|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has created email accounts that mimic legitimate organizations for its spearphishing operations.(Citation: US District Court Indictment GRU Unit 74455 October 2020)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1585.002|Email Accounts|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has registered domain names and created URLs that are often designed to mimic or spoof legitimate websites, such as email login pages, online file sharing and storage websites, and password reset pages, while also hosting these items on legitimate, compromised network infrastructure.(Citation: US District Court Indictment GRU Unit 74455 October 2020)(Citation: Slowik Sandworm 2021)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|PRE|T1583.001|Domains|


[Sandworm Team](https://attack.mitre.org/groups/G0034) uses [Prestige](https://attack.mitre.org/software/S1058) to delete the backup catalog from the target system using: `C:\Windows\System32\wbadmin.exe delete catalog -quiet` and to delete volume shadow copies using: `C:\Windows\System32\vssadmin.exe delete shadows /all /quiet`. (Citation: Microsoft Prestige ransomware October 2022) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, macOS, Linux, Network, IaaS, Containers|T1490|Inhibit System Recovery|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used various MS-SQL stored procedures.(Citation: Dragos Crashoverride 2018) 

|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, Linux|T1505.001|SQL Stored Procedures|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has run the  <code>xp_cmdshell</code> command in MS-SQL.(Citation: Dragos Crashoverride 2018) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows|T1059.003|Windows Command Shell|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has used a script to attempt RPC authentication against a number of hosts.(Citation: Dragos Crashoverride 2018) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110.003|Password Spraying|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has created new domain accounts on an ICS access server.(Citation: Dragos Crashoverride 2018)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, macOS, Linux|T1136.002|Domain Account|


[Sandworm Team](https://attack.mitre.org/groups/G0034) added a login to a SQL Server with <code>sp_addlinkedsrvlogin</code>.(Citation: Dragos Crashoverride 2018)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, IaaS, Linux, macOS, Network, Containers, SaaS, Office Suite, Identity Provider|T1136|Create Account|


[Sandworm Team](https://attack.mitre.org/groups/G0034) checks for connectivity to other resources in the network.(Citation: Dragos Crashoverride 2018) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Linux, macOS, Windows, Network|T1016|System Network Configuration Discovery|


[Sandworm Team](https://attack.mitre.org/groups/G0034) has disabled event logging on compromised systems.(Citation: Dragos Crashoverride 2018)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows|T1562.002|Disable Windows Event Logging|


[Sandworm Team](https://attack.mitre.org/groups/G0034) used UPX to pack a copy of [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Dragos Crashoverride 2018) 
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|macOS, Windows, Linux|T1027.002|Software Packing|


[Sandworm Team](https://attack.mitre.org/groups/G0034) used the <code>sp_addlinkedsrvlogin</code> command in MS-SQL to create a link between a created account and other servers in the network.(Citation: Dragos Crashoverride 2018)
|['enterprise-attack']|enterprise-attack, ics-attack, mobile-attack|Windows, IaaS, Linux, macOS, SaaS, Network, Containers, Office Suite, Identity Provider|T1098|Account Manipulation|


[Sandworm Team](https://attack.mitre.org/groups/G0034) used SMS-based phishing to target victims with malicious links.(Citation: Leonard TAG 2023)
|['mobile-attack']|enterprise-attack, ics-attack, mobile-attack|Android, iOS|T1660|Phishing|


[Sandworm Team](https://attack.mitre.org/groups/G0034) can collect encrypted Telegram and Signal communications.(Citation: mandiant_apt44_unearthing_sandworm)
|['mobile-attack']|enterprise-attack, ics-attack, mobile-attack|Android, iOS|T1409|Stored Application Data|


[Sandworm Team](https://attack.mitre.org/groups/G0034) actors exploited vulnerabilities in GE's Cimplicity HMI and Advantech/Broadwin WebAccess HMI software which had been directly exposed to the internet. (Citation: ICS-CERT December 2014) (Citation: ICS CERT September 2018)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0819|Exploit Public-Facing Application|


In the Ukraine 2015 Incident, [Sandworm Team](https://attack.mitre.org/groups/G0034) blocked command messages by using malicious firmware to render communication devices inoperable. (Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0803|Block Command Message|


In the Ukraine 2015 Incident, [Sandworm Team](https://attack.mitre.org/groups/G0034) developed and used malicious firmware to render communication devices inoperable. (Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0857|System Firmware|


In the Ukraine 2015 Incident, [Sandworm Team](https://attack.mitre.org/groups/G0034) used the credentials of valid accounts to interact with client applications and access employee workstations hosting HMI applications. (Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016)(Citation: Dragos)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0859|Valid Accounts|


In the Ukraine 2015 Incident, [Sandworm Team](https://attack.mitre.org/groups/G0034) utilized HMI GUIs in the SCADA environment to open breakers. (Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0823|Graphical User Interface|


In the Ukraine 2015 Incident, [Sandworm Team](https://attack.mitre.org/groups/G0034) issued unauthorized commands to substation breakers after gaining control of operator workstations and accessing a distribution management system (DMS) client application. (Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0855|Unauthorized Command Message|


In the Ukraine 2015 Incident, [Sandworm Team](https://attack.mitre.org/groups/G0034) blocked reporting messages by using malicious firmware to render communication devices inoperable. (Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0804|Block Reporting Message|


In the Ukraine 2015 Incident, [Sandworm Team](https://attack.mitre.org/groups/G0034) harvested VPN worker credentials and used them to remotely log into control system networks. (Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016) (Citation: Zetter, Kim March 2016) (Citation: ICS-CERT February 2016) (Citation: John Hultquist January 2016)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0822|External Remote Services|


In the 2015 attack on the Ukrainian power grid, the [Sandworm Team](https://attack.mitre.org/groups/G0034) scheduled disconnects of uninterruptable power supply (UPS) systems so that when power was disconnected from the substations, the devices would shut down and service could not be recovered. (Citation: Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems March 2016)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0816|Device Restart/Shutdown|


In the Ukraine 2015 incident, [Sandworm Team](https://attack.mitre.org/groups/G0034) sent spearphishing attachments to three energy distribution companies containing malware to gain access to victim systems. (Citation: UNITED STATES DISTRICT COURT WESTERN DISTRICT OF PENNSYLVANIA October 2020)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0865|Spearphishing Attachment|


[Sandworm Team](https://attack.mitre.org/groups/G0034) appears to use MS-SQL access to a pivot machine, allowing code execution throughout the ICS network. (Citation: Dragos October 2018)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0886|Remote Services|


[Sandworm Team](https://attack.mitre.org/groups/G0034) utilized VBS and batch scripts for file movement and as wrappers for PowerShell execution. (Citation: Dragos October 2018)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0853|Scripting|


[Sandworm Team](https://attack.mitre.org/groups/G0034) transfers executable files as .txt. and then renames them to .exe, likely to avoid detection through extension tracking. (Citation: Dragos October 2018)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0849|Masquerading|


[Sandworm Team](https://attack.mitre.org/groups/G0034) used a VBS script to facilitate lateral tool transfer. The VBS script was used to copy ICS-specific payloads with the following command: cscript C:\\Backinfo\\ufn.vbs  C:\\Backinfo\\101.dll C:\\Delta\\101.dll (Citation: Dragos October 2018)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0867|Lateral Tool Transfer|


[Sandworm Team](https://attack.mitre.org/groups/G0034) establishes an internal proxy prior to the installation of backdoors within the network. (Citation: Dragos Inc. June 2017)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0884|Connection Proxy|


[Sandworm Team](https://attack.mitre.org/groups/G0034) uses the MS-SQL server xp_cmdshell command, and PowerShell to execute commands. (Citation: Dragos October 2018)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0807|Command-Line Interface|


[Sandworm](https://collaborate.mitre.org/attackics/index.php/Group/G0007) actors exploited vulnerabilities in GE's Cimplicity HMI and Advantech/Broadwin WebAccess HMI software which had been directly exposed to the internet.(Citation: CISA ICS Alert (ICS-ALERT-14-281-01E))(Citation: CISA ICS Advisory (ICSA-11-094-02B))
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0883|Internet Accessible Device|


[Sandworm Team](https://collaborate.mitre.org/attackics/index.php/Group/G0007) appears to use MS-SQL access to a pivot machine, allowing code execution throughout the ICS network. (Citation: Dragos CRASHOVERRIDE Oct 2018)
|['ics-attack']|enterprise-attack, ics-attack, mobile-attack|None|T0886|Remote Services|

