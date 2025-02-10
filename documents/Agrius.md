# Agrius - G1030

**Created**: 2024-05-21T19:13:23.526Z

**Modified**: 2024-08-29T15:18:44.308Z

**Contributors**: Asritha Narina

## Aliases

Agrius,Pink Sandstorm,AMERICIUM,Agonizing Serpens,BlackShadow

## Description

[Agrius](https://attack.mitre.org/groups/G1030) is an Iranian threat actor active since 2020 notable for a series of ransomware and wiper operations in the Middle East, with an emphasis on Israeli targets.(Citation: SentinelOne Agrius 2021)(Citation: CheckPoint Agrius 2023) Public reporting has linked [Agrius](https://attack.mitre.org/groups/G1030) to Iran's Ministry of Intelligence and Security (MOIS).(Citation: Microsoft Iran Cyber 2023)

## Techniques Used


[Agrius](https://attack.mitre.org/groups/G1030) used the open-source port scanner <code>WinEggDrop</code> to perform detailed scans of hosts of interest in victim networks.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers, Network|T1046|Network Service Discovery|


[Agrius](https://attack.mitre.org/groups/G1030) attempted to acquire valid credentials for victim environments through various means to enable follow-on lateral movement.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1078.002|Domain Accounts|


[Agrius](https://attack.mitre.org/groups/G1030) used several mechanisms to try to disable security tools. [Agrius](https://attack.mitre.org/groups/G1030) attempted to modify EDR-related services to disable auto-start on system reboot. [Agrius](https://attack.mitre.org/groups/G1030) used a publicly available driver, <code>GMER64.sys</code> typically used for anti-rootkit functionality, to selectively stop and remove security software processes.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|


[Agrius](https://attack.mitre.org/groups/G1030) has deployed base64-encoded variants of [ASPXSpy](https://attack.mitre.org/software/S0073) to evade detection.(Citation: SentinelOne Agrius 2021)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[Agrius](https://attack.mitre.org/groups/G1030) used the tool [NBTscan](https://attack.mitre.org/software/S0590) to scan for remote, accessible hosts in victim environments.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[Agrius](https://attack.mitre.org/groups/G1030) typically deploys a variant of the [ASPXSpy](https://attack.mitre.org/software/S0073) web shell following initial access via exploitation.(Citation: SentinelOne Agrius 2021)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[Agrius](https://attack.mitre.org/groups/G1030) gathered data from database and other critical servers in victim environments, then used wiping mechanisms as an anti-analysis and anti-forensics mechanism.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[Agrius](https://attack.mitre.org/groups/G1030) used 7zip to archive extracted data in preparation for exfiltration.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[Agrius](https://attack.mitre.org/groups/G1030) used the Plink tool for tunneling and connections to remote machines, renaming it <code>systems.exe</code> in some instances.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036|Masquerading|


[Agrius](https://attack.mitre.org/groups/G1030) dumped the SAM file on victim machines to capture credentials.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1003.002|Security Account Manager|


[Agrius](https://attack.mitre.org/groups/G1030) used a custom tool, <code>sql.net4.exe</code>, to query SQL databases and then identify and extract personally identifiable information.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS, SaaS, Office Suite|T1119|Automated Collection|


[Agrius](https://attack.mitre.org/groups/G1030) tunnels RDP traffic through deployed web shells to access victim environments via compromised accounts.(Citation: SentinelOne Agrius 2021) [Agrius](https://attack.mitre.org/groups/G1030) used the Plink tool to tunnel RDP connections for remote access and lateral movement in victim environments.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[Agrius](https://attack.mitre.org/groups/G1030) exploits public-facing applications for initial access to victim environments. Examples include widespread attempts to exploit CVE-2018-13379 in FortiOS devices and SQL injection activity.(Citation: SentinelOne Agrius 2021) 
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[Agrius](https://attack.mitre.org/groups/G1030) used tools such as [Mimikatz](https://attack.mitre.org/software/S0002) to dump LSASS memory to capture credentials in victim environments.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[Agrius](https://attack.mitre.org/groups/G1030) typically uses commercial VPN services for anonymizing last-hop traffic to victim networks, such as ProtonVPN.(Citation: SentinelOne Agrius 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1583|Acquire Infrastructure|


[Agrius](https://attack.mitre.org/groups/G1030) engaged in password spraying via SMB in victim environments.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110.003|Password Spraying|


[Agrius](https://attack.mitre.org/groups/G1030) has used the folder, <code>C:\\windows\\temp\\s\\</code>, to stage data for exfiltration.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1074.001|Local Data Staging|


[Agrius](https://attack.mitre.org/groups/G1030) has deployed [IPsec Helper](https://attack.mitre.org/software/S1132) malware post-exploitation and registered it as a service for persistence.(Citation: SentinelOne Agrius 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1543.003|Windows Service|


[Agrius](https://attack.mitre.org/groups/G1030) engaged in various brute forcing activities via SMB in victim environments.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110|Brute Force|


[Agrius](https://attack.mitre.org/groups/G1030) uses [ASPXSpy](https://attack.mitre.org/software/S0073) web shells to enable follow-on command execution via <code>cmd.exe</code>.(Citation: SentinelOne Agrius 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Agrius](https://attack.mitre.org/groups/G1030) downloaded some payloads for follow-on execution from legitimate filesharing services such as <code>ufile.io</code> and <code>easyupload.io</code>.(Citation: CheckPoint Agrius 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1570|Lateral Tool Transfer|


[Agrius](https://attack.mitre.org/groups/G1030) exfiltrated staged data using tools such as Putty and WinSCP, communicating with command and control servers.(Citation: Unit42 Agrius 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1041|Exfiltration Over C2 Channel|

