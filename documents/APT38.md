# APT38 - G0082

**Created**: 2019-01-29T21:27:24.793Z

**Modified**: 2024-08-26T16:33:33.984Z

**Contributors**: 

## Aliases

APT38,NICKEL GLADSTONE,BeagleBoyz,Bluenoroff,Stardust Chollima,Sapphire Sleet,COPERNICIUM

## Description

[APT38](https://attack.mitre.org/groups/G0082) is a North Korean state-sponsored threat group that specializes in financial cyber operations; it has been attributed to the Reconnaissance General Bureau.(Citation: CISA AA20-239A BeagleBoyz August 2020) Active since at least 2014, [APT38](https://attack.mitre.org/groups/G0082) has targeted banks, financial institutions, casinos, cryptocurrency exchanges, SWIFT system endpoints, and ATMs in at least 38 countries worldwide. Significant operations include the 2016 Bank of Bangladesh heist, during which [APT38](https://attack.mitre.org/groups/G0082) stole $81 million, as well as attacks against Bancomext (Citation: FireEye APT38 Oct 2018) and Banco de Chile (Citation: FireEye APT38 Oct 2018); some of their attacks have been destructive.(Citation: CISA AA20-239A BeagleBoyz August 2020)(Citation: FireEye APT38 Oct 2018)(Citation: DOJ North Korea Indictment Feb 2021)(Citation: Kaspersky Lazarus Under The Hood Blog 2017)

North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups.

## Techniques Used


[APT38](https://attack.mitre.org/groups/G0082) installed a port monitoring tool, MAPMAKER, to print the active TCP connections on the local system.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Linux, macOS, Network|T1049|System Network Connections Discovery|


[APT38](https://attack.mitre.org/groups/G0082) used a Trojan called KEYLIME to capture keystrokes from the victim’s machine.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux, Network|T1056.001|Keylogging|


[APT38](https://attack.mitre.org/groups/G0082) has used a utility called CLOSESHAVE that can securely delete a file from the system. They have also removed malware, tools, or other non-native files used during the intrusion to reduce their footprint or as part of the post-intrusion cleanup process.(Citation: FireEye APT38 Oct 2018)(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[APT38](https://attack.mitre.org/groups/G0082) has identified primary users, currently logged in users, sets of users that commonly use a system, or inactive users.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[APT38](https://attack.mitre.org/groups/G0082) has used Hermes ransomware to encrypt files with AES256.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, IaaS|T1486|Data Encrypted for Impact|


[APT38](https://attack.mitre.org/groups/G0082) uses a tool called CLEANTOAD that has the capability to modify Registry keys.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1112|Modify Registry|


[APT38](https://attack.mitre.org/groups/G0082) has conducted watering holes schemes to gain initial access to victims.(Citation: FireEye APT38 Oct 2018)(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, macOS, Identity Provider|T1189|Drive-by Compromise|


[APT38](https://attack.mitre.org/groups/G0082) have enumerated files and directories, or searched in specific locations within a compromised host.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[APT38](https://attack.mitre.org/groups/G0082) has installed a new Windows service to establish persistence.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1543.003|Windows Service|


[APT38](https://attack.mitre.org/groups/G0082) has identified security software, configurations, defensive tools, and sensors installed on a compromised system.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Linux, macOS|T1518.001|Security Software Discovery|


[APT38](https://attack.mitre.org/groups/G0082) has used VBScript to execute commands and other operational tasks.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[APT38](https://attack.mitre.org/groups/G0082) has used a command-line tunneler, NACHOCHEESE, to give them shell access to a victim’s machine.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1059.003|Windows Command Shell|


[APT38](https://attack.mitre.org/groups/G0082) has modified data timestamps to mimic files that are in the same folder on a compromised host.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1070.006|Timestomp|


[APT38](https://attack.mitre.org/groups/G0082) clears Window Event logs and Sysmon logs from the system.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1070.001|Clear Windows Event Logs|


[APT38](https://attack.mitre.org/groups/G0082) has used brute force techniques to attempt account access when passwords are unknown or when password hashes are unavailable.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110|Brute Force|


[APT38](https://attack.mitre.org/groups/G0082) has enumerated network shares on a compromised host.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows, Linux|T1135|Network Share Discovery|


[APT38](https://attack.mitre.org/groups/G0082) has used a custom secure delete function to make deleted files unrecoverable.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Linux, macOS, Containers|T1485|Data Destruction|


[APT38](https://attack.mitre.org/groups/G0082) used a backdoor, NESTEGG, that has the capability to download and upload files to and from a victim’s machine.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[APT38](https://attack.mitre.org/groups/G0082) used a backdoor, QUICKRIDE, to communicate to the C2 server over HTTP and HTTPS.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[APT38](https://attack.mitre.org/groups/G0082) has used a custom MBR wiper named BOOTWRECK, which will initiate a system reboot after wiping the victim's MBR.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1529|System Shutdown/Reboot|


[APT38](https://attack.mitre.org/groups/G0082) has used several code packing methods such as Themida, Enigma, VMProtect, and Obsidium, to pack their implants.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows, Linux|T1027.002|Software Packing|


[APT38](https://attack.mitre.org/groups/G0082) has collected browser bookmark information to learn more about compromised hosts, obtain personal information about users, and acquire details about internal network resources.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS|T1217|Browser Information Discovery|


[APT38](https://attack.mitre.org/groups/G0082) has prepended a space to all of their terminal commands to operate without leaving traces in the HISTCONTROL environment.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1562.003|Impair Command History Logging|


[APT38](https://attack.mitre.org/groups/G0082) has used web shells for persistence or to ensure redundant access.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[APT38](https://attack.mitre.org/groups/G0082) used a Trojan called KEYLIME to collect data from the clipboard.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS|T1115|Clipboard Data|


[APT38](https://attack.mitre.org/groups/G0082) has obtained and used open-source tools such as [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: ESET Lazarus KillDisk April 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1588.002|Tool|


[APT38](https://attack.mitre.org/groups/G0082) has used rundll32.exe to execute binaries, scripts, and Control Panel Item files and to execute code via proxy to avoid triggering security tools.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1218.011|Rundll32|


[APT38](https://attack.mitre.org/groups/G0082) have created firewall exemptions on specific ports, including ports 443, 6443, 8443, and 9443.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1562.004|Disable or Modify System Firewall|


[APT38](https://attack.mitre.org/groups/G0082) has used DYEPACK to manipulate SWIFT messages en route to a printer.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1565.002|Transmitted Data Manipulation|


[APT38](https://attack.mitre.org/groups/G0082) has attempted to get detailed information about a compromised host, including the operating system, version, patches, hotfixes, and service packs.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[APT38](https://attack.mitre.org/groups/G0082) has used Task Scheduler to run programs at system startup or on a scheduled basis for persistence.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1053.005|Scheduled Task|


[APT38](https://attack.mitre.org/groups/G0082) has used a custom MBR wiper named BOOTWRECK to render systems inoperable.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1561.002|Disk Structure Wipe|


[APT38](https://attack.mitre.org/groups/G0082) has created new services or modified existing ones to run executables, commands, or scripts.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1569.002|Service Execution|


[APT38](https://attack.mitre.org/groups/G0082) leveraged Sysmon to understand the processes, services in the organization.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1057|Process Discovery|


[APT38](https://attack.mitre.org/groups/G0082) has used CHM files to move concealed payloads.(Citation: Kaspersky Lazarus Under The Hood APR 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1218.001|Compiled HTML File|


[APT38](https://attack.mitre.org/groups/G0082)  has attempted to lure victims into enabling malicious macros within email attachments.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[APT38](https://attack.mitre.org/groups/G0082) has collected data from a compromised host.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[APT38](https://attack.mitre.org/groups/G0082) has used DYEPACK to create, delete, and alter records in databases used for SWIFT transactions.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1565.001|Stored Data Manipulation|


[APT38](https://attack.mitre.org/groups/G0082) has used DYEPACK.FOX to manipulate PDF data as it is accessed to remove traces of fraudulent SWIFT transactions from the data displayed to the end user.(Citation: FireEye APT38 Oct 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1565.003|Runtime Data Manipulation|


[APT38](https://attack.mitre.org/groups/G0082) has used the Windows API to execute code within a victim's system.(Citation: CISA AA20-239A BeagleBoyz August 2020) 
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux|T1106|Native API|


[APT38](https://attack.mitre.org/groups/G0082) has used cron to create pre-scheduled and periodic background jobs on a Linux system.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS|T1053.003|Cron|


[APT38](https://attack.mitre.org/groups/G0082) has conducted spearphishing campaigns using malicious email attachments.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[APT38](https://attack.mitre.org/groups/G0082) has used PowerShell to execute commands and other operational tasks.(Citation: CISA AA20-239A BeagleBoyz August 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1059.001|PowerShell|

