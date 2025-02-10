# Play - G1040

**Created**: 2024-09-24T19:48:18.278Z

**Modified**: 2024-10-02T05:37:34.149Z

**Contributors**: Marco Pedrinazzi, @pedrinazziM

## Aliases

Play

## Description

[Play](https://attack.mitre.org/groups/G1040) is a ransomware group that has been active since at least 2022 deploying  [Playcrypt](https://attack.mitre.org/software/S1162) ransomware against the business, government, critical infrastructure, healthcare, and media sectors in North America, South America, and Europe. [Play](https://attack.mitre.org/groups/G1040) actors employ a double-extortion model, encrypting systems after exfiltrating data, and are presumed by security researchers to operate as a closed group.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)

## Techniques Used


[Play](https://attack.mitre.org/groups/G1040) has split victims' files into chunks for exfiltration.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1030|Data Transfer Size Limits|



[Play](https://attack.mitre.org/groups/G1040) has used the information-stealing tool Grixba to enumerate network information.(Citation: CISA Play Ransomware Advisory December 2023)

|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1016|System Network Configuration Discovery|



[Play](https://attack.mitre.org/groups/G1040) has used a batch script to remove indicators of its presence on compromised hosts.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Play](https://attack.mitre.org/groups/G1040) has used tools including [Wevtutil](https://attack.mitre.org/software/S0645) to remove malicious files from compromised hosts.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[Play](https://attack.mitre.org/groups/G1040) has used WinSCP to exfiltrate data to actor-controlled accounts.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, IaaS, Network, Office Suite|T1048|Exfiltration Over Alternative Protocol|


[Play](https://attack.mitre.org/groups/G1040) has used Base64-encoded PowerShell scripts to disable Microsoft Defender.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Play](https://attack.mitre.org/groups/G1040) has used [Cobalt Strike](https://attack.mitre.org/software/S0154) to move laterally via SMB.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1021.002|SMB/Windows Admin Shares|


[Play](https://attack.mitre.org/groups/G1040) has used valid VPN accounts to achieve initial access.(Citation: CISA Play Ransomware Advisory December 2023)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[Play](https://attack.mitre.org/groups/G1040) has used Base64-encoded PowerShell scripts for post exploit activities on compromised hosts.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.010|Command Obfuscation|


[Play](https://attack.mitre.org/groups/G1040) developed and employ [Playcrypt](https://attack.mitre.org/software/S1162) ransomware.(Citation: Trend Micro Ransomware Spotlight Play July 2023)(Citation: CISA Play Ransomware Advisory December 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1587.001|Malware|



[Play](https://attack.mitre.org/groups/G1040) has used WinRAR to compress files prior to exfiltration.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[Play](https://attack.mitre.org/groups/G1040) has used tools such as [AdFind](https://attack.mitre.org/software/S0552), [Nltest](https://attack.mitre.org/software/S0359), and [BloodHound](https://attack.mitre.org/software/S0521) to enumerate shares and hostnames on compromised networks.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|



[Play](https://attack.mitre.org/groups/G1040) has used the information stealer Grixba to check for a list of security processes.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1057|Process Discovery|


[Play](https://attack.mitre.org/groups/G1040) has used valid  local accounts to gain initial access.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers, Network|T1078.003|Local Accounts|



[Play](https://attack.mitre.org/groups/G1040) has used tools including GMER, IOBit, and PowerTool to disable antivirus software.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)

|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|


[Play](https://attack.mitre.org/groups/G1040) has used valid domain accounts for access.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1078.002|Domain Accounts|


[Play](https://attack.mitre.org/groups/G1040) has used the Grixba information stealer to list security files and processes.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|



[Play](https://attack.mitre.org/groups/G1040) has leveraged tools to enumerate system information.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Play](https://attack.mitre.org/groups/G1040) has used [Cobalt Strike](https://attack.mitre.org/software/S0154) to download files to compromised machines.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Play](https://attack.mitre.org/groups/G1040) demands ransom payments from victims to unencrypt filesystems and to not publish sensitive data exfiltrated from victim networks.(Citation: CISA Play Ransomware Advisory December 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Office Suite|T1657|Financial Theft|


[Play](https://attack.mitre.org/groups/G1040) has used [Mimikatz](https://attack.mitre.org/software/S0002) and the Windows Task Manager to dump LSASS process memory.(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[Play](https://attack.mitre.org/groups/G1040) has exploited known vulnerabilities for initial access including CVE-2018-13379 and CVE-2020-12812 in FortiOS and CVE-2022-41082 and CVE-2022-41040 ("ProxyNotShell") in Microsoft Exchange.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[Play](https://attack.mitre.org/groups/G1040) has used tools to remove log files on targeted systems.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1070.001|Clear Windows Event Logs|



[Play](https://attack.mitre.org/groups/G1040) has used the information-stealing tool Grixba to scan for anti-virus software.(Citation: CISA Play Ransomware Advisory December 2023)

|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1518.001|Security Software Discovery|


[Play](https://attack.mitre.org/groups/G1040) has used multiple tools for discovery and defense evasion purposes on compromised hosts.(Citation: CISA Play Ransomware Advisory December 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|



[Play](https://attack.mitre.org/groups/G1040) has used Remote Desktop Protocol (RDP) and Virtual Private Networks (VPN) for initial access.(Citation: CISA Play Ransomware Advisory December 2023)(Citation: Trend Micro Ransomware Spotlight Play July 2023)
|['enterprise-attack']|enterprise-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|

