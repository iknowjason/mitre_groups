# Cinnamon Tempest - G1021

**Created**: 2023-12-06T19:53:04.988Z

**Modified**: 2024-04-04T23:27:22.311Z

**Contributors**: 

## Aliases

Cinnamon Tempest,DEV-0401,Emperor Dragonfly,BRONZE STARLIGHT

## Description

[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) is a China-based threat group that has been active since at least 2021 deploying multiple strains of ransomware based on the leaked [Babuk](https://attack.mitre.org/software/S0638) source code. [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) does not operate their ransomware on an affiliate model or purchase access but appears to act independently in all stages of the attack lifecycle. Based on victimology, the short lifespan of each ransomware variant, and use of malware attributed to government-sponsored threat groups, [Cinnamon Tempest](https://attack.mitre.org/groups/G1021) may be motivated by intellectual property theft or cyberespionage rather than financial gain.(Citation: Microsoft Ransomware as a Service)(Citation: Microsoft Threat Actor Naming July 2023)(Citation: Trend Micro Cheerscrypt May 2022)(Citation: SecureWorks BRONZE STARLIGHT Ransomware Operations June 2022)

## Techniques Used


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used [Impacket](https://attack.mitre.org/software/S0357) for lateral movement via WMI.(Citation: Microsoft Ransomware as a Service)(Citation: Sygnia Emperor Dragonfly October 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1047|Windows Management Instrumentation|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used search order hijacking to launch [Cobalt Strike](https://attack.mitre.org/software/S0154) Beacons.(Citation: Microsoft Ransomware as a Service)(Citation: SecureWorks BRONZE STARLIGHT Ransomware Operations June 2022)

|['enterprise-attack']|enterprise-attack|Windows|T1574.001|DLL Search Order Hijacking|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has downloaded files, including [Cobalt Strike](https://attack.mitre.org/software/S0154), to compromised hosts.(Citation: Sygnia Emperor Dragonfly October 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used Group Policy to deploy batch scripts for ransomware deployment.(Citation: Microsoft Ransomware as a Service)
|['enterprise-attack']|enterprise-attack|Windows|T1484.001|Group Policy Modification|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has uploaded captured keystroke logs to the Alibaba Cloud Object Storage Service, Aliyun OSS.(Citation: Sygnia Emperor Dragonfly October 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1567.002|Exfiltration to Cloud Storage|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has obtained highly privileged credentials such as domain administrator in order to deploy malware.(Citation: Microsoft Ransomware as a Service)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1078.002|Domain Accounts|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has exploited multiple unpatched vulnerabilities for initial access including vulnerabilities in Microsoft Exchange, Manage Engine AdSelfService Plus, Confluence, and Log4j.(Citation: Microsoft Ransomware as a Service)(Citation: Microsoft Log4j Vulnerability Exploitation December 2021)(Citation: Sygnia Emperor Dragonfly October 2022)(Citation: SecureWorks BRONZE STARLIGHT Ransomware Operations June 2022)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used compromised user accounts to deploy payloads and create system services.(Citation: Sygnia Emperor Dragonfly October 2022)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used open-source tools including customized versions of the Iox proxy tool, NPS tunneling tool, Meterpreter, and a keylogger that uploads data to Alibaba cloud storage.(Citation: Sygnia Emperor Dragonfly October 2022)(Citation: SecureWorks BRONZE STARLIGHT Ransomware Operations June 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used a customized version of the Iox port-forwarding and proxy tool.(Citation: Sygnia Emperor Dragonfly October 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090|Proxy|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has maintained leak sites for exfiltrated data in attempt to extort victims into paying a ransom.(Citation: Microsoft Ransomware as a Service)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Office Suite|T1657|Financial Theft|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used weaponized DLLs to load and decrypt payloads.(Citation: Sygnia Emperor Dragonfly October 2022)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used a customized version of the [Impacket](https://attack.mitre.org/software/S0357) wmiexec.py module to create renamed output files.(Citation: Microsoft Ransomware as a Service)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1059.006|Python|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used PowerShell to communicate with C2, download files, and execute reconnaissance commands.(Citation: Sygnia Emperor Dragonfly October 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has abused legitimate executables to side-load weaponized DLLs.(Citation: Sygnia Emperor Dragonfly October 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1574.002|DLL Side-Loading|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has created system services to establish persistence for deployed tooling.(Citation: Sygnia Emperor Dragonfly October 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1543.003|Windows Service|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has executed ransomware using batch scripts deployed via GPO.(Citation: Microsoft Ransomware as a Service)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has deployed ransomware from a batch file in a network share.(Citation: Microsoft Ransomware as a Service)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, Linux, macOS, Office Suite|T1080|Taint Shared Content|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used SMBexec for lateral movement.(Citation: Sygnia Emperor Dragonfly October 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1021.002|SMB/Windows Admin Shares|


[Cinnamon Tempest](https://attack.mitre.org/groups/G1021) has used the Iox and NPS proxy and tunneling tools in combination  create multiple connections through a single tunnel.(Citation: Sygnia Emperor Dragonfly October 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1572|Protocol Tunneling|

