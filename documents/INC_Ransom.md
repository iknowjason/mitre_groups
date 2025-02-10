# INC Ransom - G1032

**Created**: 2024-06-06T17:16:38.704Z

**Modified**: 2024-10-28T19:03:08.838Z

**Contributors**: Matt Anderson, @‌nosecurething, Huntress

## Aliases

INC Ransom,GOLD IONIC

## Description

[INC Ransom](https://attack.mitre.org/groups/G1032) is a ransomware and data extortion threat group associated with the deployment of [INC Ransomware](https://attack.mitre.org/software/S1139) that has been active since at least July 2023. [INC Ransom](https://attack.mitre.org/groups/G1032)  has targeted organizations worldwide most commonly in the industrial, healthcare, and education sectors in the US and Europe.(Citation: Bleeping Computer INC Ransomware March 2024)(Citation: Cybereason INC Ransomware November 2023)(Citation: Secureworks GOLD IONIC April 2024)(Citation: SentinelOne INC Ransomware)

## Techniques Used


[INC Ransom](https://attack.mitre.org/groups/G1032) has used [INC Ransomware](https://attack.mitre.org/software/S1139) to encrypt victim's data.(Citation: SentinelOne INC Ransomware)(Citation: Huntress INC Ransom Group August 2023)(Citation: Bleeping Computer INC Ransomware March 2024)(Citation: Secureworks GOLD IONIC April 2024)(Citation: Cybereason INC Ransomware November 2023)(Citation: SOCRadar INC Ransom January 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1486|Data Encrypted for Impact|


[INC Ransom](https://attack.mitre.org/groups/G1032) can use SystemSettingsAdminFlows.exe, a native Windows utility, to disable Windows Defender.(Citation: Huntress INC Ransomware May 2024)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|



[INC Ransom](https://attack.mitre.org/groups/G1032) has used RDP to move laterally.(Citation: Cybereason INC Ransomware November 2023)(Citation: Huntress INC Ransom Group August 2023)(Citation: SOCRadar INC Ransom January 2024)(Citation: Huntress INC Ransomware May 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[INC Ransom](https://attack.mitre.org/groups/G1032) has stolen and encrypted victim's data in order to extort payment for keeping it private or decrypting it.(Citation: Cybereason INC Ransomware November 2023)(Citation: Bleeping Computer INC Ransomware March 2024)(Citation: Secureworks GOLD IONIC April 2024)(Citation: SOCRadar INC Ransom January 2024)(Citation: SentinelOne INC Ransomware)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Office Suite|T1657|Financial Theft|


[INC Ransom](https://attack.mitre.org/groups/G1032) has used WMIC to deploy ransomware.(Citation: Cybereason INC Ransomware November 2023)(Citation: Huntress INC Ransom Group August 2023)(Citation: SOCRadar INC Ransom January 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1047|Windows Management Instrumentation|


[INC Ransom](https://attack.mitre.org/groups/G1032) has used phishing to gain initial access.(Citation: SOCRadar INC Ransom January 2024)(Citation: SentinelOne INC Ransomware)

|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566|Phishing|


[INC Ransom](https://attack.mitre.org/groups/G1032) has used Megasync to exfiltrate data to the cloud.(Citation: Secureworks GOLD IONIC April 2024)
|['enterprise-attack']|enterprise-attack|IaaS, SaaS, Office Suite|T1537|Transfer Data to Cloud Account|


[INC Ransom](https://attack.mitre.org/groups/G1032) has used `cmd.exe` to launch malicious payloads.(Citation: Huntress INC Ransom Group August 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[INC Ransom](https://attack.mitre.org/groups/G1032) has run a file encryption executable via `Service Control Manager/7045;winupd,%SystemRoot%\winupd.exe,user mode service,demand start,LocalSystem`.(Citation: Huntress INC Ransom Group August 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1569.002|Service Execution|



[INC Ransom](https://attack.mitre.org/groups/G1032) has used AnyDesk and PuTTY on compromised systems.(Citation: Huntress INC Ransom Group August 2023)(Citation: SOCRadar INC Ransom January 2024)(Citation: Huntress INC Ransomware May 2024)(Citation: SentinelOne INC Ransomware)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1219|Remote Access Software|


[INC Ransom](https://attack.mitre.org/groups/G1032) has staged data on compromised hosts prior to exfiltration.(Citation: Huntress INC Ransom Group August 2023)(Citation: SOCRadar INC Ransom January 2024)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1074|Data Staged|


[INC Ransom](https://attack.mitre.org/groups/G1032) has scanned for domain admin accounts in compromised environments.(Citation: SOCRadar INC Ransom January 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[INC Ransom](https://attack.mitre.org/groups/G1032) has used valid accounts over RDP to connect to targeted systems.(Citation: Huntress INC Ransom Group August 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071|Application Layer Protocol|


[INC Ransom](https://attack.mitre.org/groups/G1032) has used NETSCAN.EXE for internal reconnaissance.(Citation: SOCRadar INC Ransom January 2024)(Citation: SentinelOne INC Ransomware)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers, Network|T1046|Network Service Discovery|


[INC Ransom](https://attack.mitre.org/groups/G1032) has enumerated domain groups on targeted hosts.(Citation: Huntress INC Ransom Group August 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1069.002|Domain Groups|



[INC Ransom](https://attack.mitre.org/groups/G1032) has used a rapid succession of copy commands to install a file encryption executable across multiple endpoints within compromised infrastructure.(Citation: Huntress INC Ransom Group August 2023)(Citation: Secureworks GOLD IONIC April 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1570|Lateral Tool Transfer|


[INC Ransom](https://attack.mitre.org/groups/G1032) has named a [PsExec](https://attack.mitre.org/software/S0029) executable winupd to mimic a legitimate Windows update file.(Citation: Huntress INC Ransom Group August 2023)(Citation: SOCRadar INC Ransom January 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[INC Ransom](https://attack.mitre.org/groups/G1032) has acquired and used several tools including MegaSync, AnyDesk,  [esentutl](https://attack.mitre.org/software/S0404) and [PsExec](https://attack.mitre.org/software/S0029).(Citation: Cybereason INC Ransomware November 2023)(Citation: Huntress INC Ransom Group August 2023)(Citation: SOCRadar INC Ransom January 2024)(Citation: Huntress INC Ransomware May 2024)(Citation: SentinelOne INC Ransomware)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[INC Ransom](https://attack.mitre.org/groups/G1032) has used 7-Zip and WinRAR to archive collected data prior to exfiltration.(Citation: Huntress INC Ransom Group August 2023)(Citation: Secureworks GOLD IONIC April 2024)(Citation: SOCRadar INC Ransom January 2024)(Citation: Huntress INC Ransomware May 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[INC Ransom](https://attack.mitre.org/groups/G1032) has used RDP to test network connections.(Citation: SOCRadar INC Ransom January 2024)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1049|System Network Connections Discovery|


[INC Ransom](https://attack.mitre.org/groups/G1032) has used Internet Explorer to view folders on other systems.(Citation: Huntress INC Ransom Group August 2023)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1135|Network Share Discovery|



[INC Ransom](https://attack.mitre.org/groups/G1032) has uninstalled tools from compromised endpoints after use.(Citation: Huntress INC Ransomware May 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[INC Ransom](https://attack.mitre.org/groups/G1032) has exploited known vulnerabilities including CVE-2023-3519 in Citrix NetScaler for initial access.(Citation: SOCRadar INC Ransom January 2024)(Citation: SentinelOne INC Ransomware)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[INC Ransom](https://attack.mitre.org/groups/G1032) has downloaded tools to compromised servers including Advanced IP Scanner. (Citation: Huntress INC Ransom Group August 2023)(Citation: Huntress INC Ransomware May 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|



[INC Ransom](https://attack.mitre.org/groups/G1032) has used compromised valid accounts for access to victim environments.(Citation: Cybereason INC Ransomware November 2023)(Citation: Huntress INC Ransom Group August 2023)(Citation: SOCRadar INC Ransom January 2024)(Citation: Huntress INC Ransomware May 2024)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|

