# Dragonfly - G0035

**Created**: 2017-05-31T21:32:05.217Z

**Modified**: 2024-01-08T20:40:31.822Z

**Contributors**: Dragos Threat Intelligence

## Aliases

Dragonfly,TEMP.Isotope,DYMALLOY,Berserk Bear,TG-4192,Crouching Yeti,IRON LIBERTY,Energetic Bear,Ghost Blizzard,BROMINE

## Description

[Dragonfly](https://attack.mitre.org/groups/G0035) is a cyber espionage group that has been attributed to Russia's Federal Security Service (FSB) Center 16.(Citation: DOJ Russia Targeting Critical Infrastructure March 2022)(Citation: UK GOV FSB Factsheet April 2022) Active since at least 2010, [Dragonfly](https://attack.mitre.org/groups/G0035) has targeted defense and aviation companies, government entities, companies related to industrial control systems, and critical infrastructure sectors worldwide through supply chain, spearphishing, and drive-by compromise attacks.(Citation: Symantec Dragonfly)(Citation: Secureworks IRON LIBERTY July 2019)(Citation: Symantec Dragonfly Sept 2017)(Citation: Fortune Dragonfly 2.0 Sept 2017)(Citation: Gigamon Berserk Bear October 2021)(Citation: CISA AA20-296A Berserk Bear December 2020)(Citation: Symantec Dragonfly 2.0 October 2017)

## Techniques Used


[Dragonfly](https://attack.mitre.org/groups/G0035) has compressed data into .zip files prior to exfiltration.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1560|Archive Collected Data|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used various forms of spearphishing in attempts to get users to open malicious attachments.(Citation: Gigamon Berserk Bear October 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Dragonfly](https://attack.mitre.org/groups/G0035) has commonly created Web shells on victims' publicly accessible email and web servers, which they used to maintain access to a victim network and download additional malicious files.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[Dragonfly](https://attack.mitre.org/groups/G0035) has compromised user credentials and used valid accounts for operations.(Citation: US-CERT TA18-074A)(Citation: Gigamon Berserk Bear October 2021)(Citation: CISA AA20-296A Berserk Bear December 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used batch scripts to enumerate network information, including information about trusts, zones, and the domain.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1016|System Network Configuration Discovery|


[Dragonfly](https://attack.mitre.org/groups/G0035) has collected open source information to identify relationships between organizations for targeting purposes.(Citation: Gigamon Berserk Bear October 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1591.002|Business Relationships|


[Dragonfly](https://attack.mitre.org/groups/G0035) has modified the Registry to hide created user accounts.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows, Linux|T1564.002|Hidden Users|


[Dragonfly](https://attack.mitre.org/groups/G0035) has performed screen captures of victims, including by using a tool, scr.exe (which matched the hash of ScreenUtil).(Citation: US-CERT TA18-074A)(Citation: Symantec Dragonfly Sept 2017)(Citation: Gigamon Berserk Bear October 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1113|Screen Capture|


[Dragonfly](https://attack.mitre.org/groups/G0035) has exploited CVE-2011-0611 in Adobe Flash Player to gain execution on a targeted system.(Citation: Gigamon Berserk Bear October 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS|T1203|Exploitation for Client Execution|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used a batch script to gather folder and file names from victim hosts.(Citation: US-CERT TA18-074A)(Citation: Gigamon Berserk Bear October 2021)(Citation: CISA AA20-296A Berserk Bear December 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[Dragonfly](https://attack.mitre.org/groups/G0035) has compromised legitimate websites to host C2 and malware modules.(Citation: Gigamon Berserk Bear October 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1584.004|Server|


[Dragonfly](https://attack.mitre.org/groups/G0035) has injected SMB URLs into malicious Word spearphishing attachments to initiate [Forced Authentication](https://attack.mitre.org/techniques/T1187).(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1221|Template Injection|


[Dragonfly](https://attack.mitre.org/groups/G0035) has created accounts on victims, including administrator accounts, some of which appeared to be tailored to each individual staging target.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network, Containers|T1136.001|Local Account|


[Dragonfly](https://attack.mitre.org/groups/G0035) has dropped and executed tools used for password cracking, including Hydra and [CrackMapExec](https://attack.mitre.org/software/S0488).(Citation: US-CERT TA18-074A)(Citation: Kali Hydra)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network, Office Suite, Identity Provider|T1110.002|Password Cracking|


[Dragonfly](https://attack.mitre.org/groups/G0035) has compromised websites to redirect traffic and to host exploit kits.(Citation: Gigamon Berserk Bear October 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1608.004|Drive-by Target|


[Dragonfly](https://attack.mitre.org/groups/G0035) has deleted many of its files used during operations as part of cleanup, including removing applications and deleting screenshots.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[Dragonfly](https://attack.mitre.org/groups/G0035) has collected data from local victim systems.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[Dragonfly](https://attack.mitre.org/groups/G0035) has cleared Windows event logs and other logs produced by tools they used, including system, security, terminal services, remote services, and audit logs. The actors also deleted specific Registry keys.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1070.001|Clear Windows Event Logs|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used the command line for execution.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network, IaaS, Office Suite, Identity Provider|T1059|Command and Scripting Interpreter|


[Dragonfly](https://attack.mitre.org/groups/G0035) has sent emails with malicious attachments to gain initial access.(Citation: Gigamon Berserk Bear October 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Dragonfly](https://attack.mitre.org/groups/G0035) has compromised targets via strategic web compromise (SWC) utilizing a custom exploit kit.(Citation: Secureworks IRON LIBERTY July 2019)(Citation: US-CERT TA18-074A)(Citation: Gigamon Berserk Bear October 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, macOS, Identity Provider|T1189|Drive-by Compromise|


[Dragonfly](https://attack.mitre.org/groups/G0035) has disabled host-based firewalls. The group has also globally opened port 3389.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1562.004|Disable or Modify System Firewall|


[Dragonfly](https://attack.mitre.org/groups/G0035) has queried the Registry to identify victim information.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1012|Query Registry|


[Dragonfly](https://attack.mitre.org/groups/G0035) has registered domains for targeting intended victims.(Citation: CISA AA20-296A Berserk Bear December 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1583.001|Domains|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used spearphishing with Microsoft Office attachments to enable harvesting of user credentials.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1598.002|Spearphishing Attachment|


[Dragonfly](https://attack.mitre.org/groups/G0035) has dropped and executed SecretsDump to dump password hashes.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1003.002|Security Account Manager|


[Dragonfly](https://attack.mitre.org/groups/G0035) has acquired VPS infrastructure for use in malicious campaigns.(Citation: Gigamon Berserk Bear October 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1583.003|Virtual Private Server|


[Dragonfly](https://attack.mitre.org/groups/G0035) has added newly created accounts to the administrators group to maintain elevated access.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux|T1098.007|Additional Local or Domain Groups|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used scheduled tasks to automatically log out of created accounts every 8 hours as well as to execute malicious files.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1053.005|Scheduled Task|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used spearphishing with PDF attachments containing malicious links that redirected to credential harvesting websites.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1598.003|Spearphishing Link|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used batch scripts to enumerate administrators and users in the domain.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1069.002|Domain Groups|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used SMB for C2.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1071.002|File Transfer Protocols|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used various types of scripting to perform operations, including batch scripts.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1059.003|Windows Command Shell|


[Dragonfly](https://attack.mitre.org/groups/G0035) has dropped and executed SecretsDump to dump password hashes. They also obtained ntds.dit from domain controllers.(Citation: US-CERT TA18-074A)(Citation: Core Security Impacket)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1003.003|NTDS|


[Dragonfly](https://attack.mitre.org/groups/G0035) has created accounts disguised as legitimate backup and service accounts as well as an email administration account.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, SaaS, IaaS, Containers, Office Suite, Identity Provider|T1036.010|Masquerade Account Name|


[Dragonfly](https://attack.mitre.org/groups/G0035) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002), [CrackMapExec](https://attack.mitre.org/software/S0488), and [PsExec](https://attack.mitre.org/software/S0029).(Citation: Secureworks IRON LIBERTY July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1588.002|Tool|


[Dragonfly](https://attack.mitre.org/groups/G0035) has placed trojanized installers for control system software on legitimate vendor app stores.(Citation: Secureworks IRON LIBERTY July 2019)(Citation: Gigamon Berserk Bear October 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1195.002|Compromise Software Supply Chain|


[Dragonfly](https://attack.mitre.org/groups/G0035) has modified the Registry to perform multiple techniques through the use of [Reg](https://attack.mitre.org/software/S0075).(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1112|Modify Registry|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used PowerShell scripts for execution.(Citation: US-CERT TA18-074A)(Citation: Symantec Dragonfly Sept 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1059.001|PowerShell|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used various types of scripting to perform operations, including Python scripts. The group was observed installing Python 2.7 on a victim.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS|T1059.006|Python|


[Dragonfly](https://attack.mitre.org/groups/G0035) has exploited a Windows Netlogon vulnerability (CVE-2020-1472) to obtain access to Windows Active Directory servers.(Citation: CISA AA20-296A Berserk Bear December 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS|T1210|Exploitation of Remote Services|


[Dragonfly](https://attack.mitre.org/groups/G0035) has likely obtained a list of hosts in the victim environment.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used batch scripts to enumerate users on a victim domain controller.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used VPNs and Outlook Web Access (OWA) to maintain access to victim networks.(Citation: US-CERT TA18-074A)(Citation: CISA AA20-296A Berserk Bear December 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[Dragonfly](https://attack.mitre.org/groups/G0035) has dropped and executed SecretsDump to dump password hashes.(Citation: US-CERT TA18-074A)(Citation: Core Security Impacket)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1003.004|LSA Secrets|


[Dragonfly](https://attack.mitre.org/groups/G0035) has identified and browsed file servers in the victim network, sometimes , viewing files pertaining to ICS or Supervisory Control and Data Acquisition (SCADA) systems.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows, Linux|T1135|Network Share Discovery|


[Dragonfly](https://attack.mitre.org/groups/G0035) has conducted SQL injection attacks, exploited vulnerabilities CVE-2019-19781 and CVE-2020-0688 for Citrix and MS Exchange, and CVE-2018-13379 for Fortinet VPNs.(Citation: CISA AA20-296A Berserk Bear December 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[Dragonfly](https://attack.mitre.org/groups/G0035) has added the registry value ntdll to the Registry Run key to establish persistence.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[Dragonfly](https://attack.mitre.org/groups/G0035) has scanned targeted systems for vulnerable Citrix and Microsoft Exchange services.(Citation: CISA AA20-296A Berserk Bear December 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1595.002|Vulnerability Scanning|


[Dragonfly](https://attack.mitre.org/groups/G0035) has accessed email accounts using Outlook Web Access.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Office Suite|T1114.002|Remote Email Collection|


[Dragonfly](https://attack.mitre.org/groups/G0035) has copied and installed tools for operations once in the victim environment.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Dragonfly](https://attack.mitre.org/groups/G0035) used the command <code>query user</code> on victim hosts.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[Dragonfly](https://attack.mitre.org/groups/G0035) has created a directory named "out" in the user's %AppData% folder and copied files to it.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1074.001|Local Data Staging|


[Dragonfly](https://attack.mitre.org/groups/G0035) has attempted to brute force credentials to gain access.(Citation: CISA AA20-296A Berserk Bear December 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110|Brute Force|


[Dragonfly](https://attack.mitre.org/groups/G0035) has gathered hashed user credentials over SMB using spearphishing attachments with external resource links and by modifying .LNK file icon resources to collect credentials from virtualized systems.(Citation: US-CERT TA18-074A)(Citation: Gigamon Berserk Bear October 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1187|Forced Authentication|


[Dragonfly](https://attack.mitre.org/groups/G0035) has moved laterally via RDP.(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1021.001|Remote Desktop Protocol|


[Dragonfly](https://attack.mitre.org/groups/G0035) has used spearphising campaigns to gain access to victims.(Citation: Secureworks IRON LIBERTY July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566|Phishing|


[Dragonfly](https://attack.mitre.org/groups/G0035) has manipulated .lnk files to gather user credentials in conjunction with [Forced Authentication](https://attack.mitre.org/techniques/T1187).(Citation: US-CERT TA18-074A)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1547.009|Shortcut Modification|


Dragonfly dropped and executed SecretsDump, a tool that dumps password hashes.
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, macOS|T1003|OS Credential Dumping|


Dragonfly has performed screen captures of victims.
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1113|Screen Capture|


Dragonfly has performed forced authentication to gather hashed user credentials over SMB using spearphishing attachments with external resource links and by modifying .LNK file icon resources to collect credentials from virtualized systems.
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1187|Forced Authentication|


Accounts created by Dragonfly masqueraded as legitimate service accounts.
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Containers|T1036|Masquerading|


Dragonfly used remote access services, including VPN and Outlook Web Access (OWA).
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


Dragonfly downloaded tools from a remote server after they were inside the victim network.
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


Dragonfly dropped and executed Hydra, a password cracker.
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110|Brute Force|


Dragonfly has used a scheduled task to execute a malicious file.
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, macOS, Containers|T1053|Scheduled Task/Job|


Dragonfly identified and browsed file servers on the victim network, viewing files pertaining to ICS or Supervisory Control and Data Acquisition (SCADA) systems.
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows, Linux|T1135|Network Share Discovery|


Dragonfly leveraged Outlook Web Access.
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux, Office Suite|T1114|Email Collection|


Dragonfly deleted system, security, terminal services, remote services, and audit logs from a victim.
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Containers, Network, Office Suite|T1070|Indicator Removal|


Dragonfly created accounts that appeared to be tailored to each individual staging target.
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Linux, macOS, Network, Containers, SaaS, Office Suite, Identity Provider|T1136|Create Account|


[Dragonfly](https://attack.mitre.org/groups/G0035) trojanized legitimate ICS equipment providers software packages available for download on their websites.(Citation: Symantec Security Response July 2014)
|['ics-attack']|enterprise-attack, ics-attack|None|T0862|Supply Chain Compromise|


[Dragonfly](https://attack.mitre.org/groups/G0035) utilized watering hole attacks on energy sector websites by injecting a redirect iframe to deliver [Backdoor.Oldrea](https://attack.mitre.org/software/S0093) or [Trojan.Karagany](https://attack.mitre.org/software/S0094). (Citation: Symantec Security Response July 2014)
|['ics-attack']|enterprise-attack, ics-attack|None|T0817|Drive-by Compromise|


[Dragonfly](https://collaborate.mitre.org/attackics/index.php/Group/G0002) has been reported to take screenshots of the GUI for ICS equipment, such as HMIs.(Citation: CISA Alert (TA17-293A)
|['ics-attack']|enterprise-attack, ics-attack|None|T0852|Screen Capture|


[Dragonfly](https://collaborate.mitre.org/attackics/index.php/Group/G0002) communicated with command and control over TCP ports 445 and 139 or UDP 137 or 138.(Citation: CISA Alert (TA17-293A)
|['ics-attack']|enterprise-attack, ics-attack|None|T0885|Commonly Used Port|


[Dragonfly](https://collaborate.mitre.org/attackics/index.php/Group/G0002) leveraged compromised user credentials to access the targets networks and download tools from a remote server.(Citation: CISA Alert (TA17-293A)
|['ics-attack']|enterprise-attack, ics-attack|None|T0859|Valid Accounts|

