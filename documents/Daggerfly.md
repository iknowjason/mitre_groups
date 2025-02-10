# Daggerfly - G1034

**Created**: 2024-07-25T17:13:06.098Z

**Modified**: 2024-10-31T18:33:10.434Z

**Contributors**: Furkan Celik, PURE7

## Aliases

Daggerfly,Evasive Panda,BRONZE HIGHLAND

## Description

[Daggerfly](https://attack.mitre.org/groups/G1034) is a People's Republic of China-linked APT entity active since at least 2012. [Daggerfly](https://attack.mitre.org/groups/G1034) has targeted individuals, government and NGO entities, and telecommunication companies in Asia and Africa. [Daggerfly](https://attack.mitre.org/groups/G1034) is associated with exclusive use of [MgBot](https://attack.mitre.org/software/S1146) malware and is noted for several potential supply chain infection campaigns.(Citation: Symantec Daggerfly 2023)(Citation: ESET EvasivePanda 2023)(Citation: Symantec Daggerfly 2024)(Citation: ESET EvasivePanda 2024)

## Techniques Used


[Daggerfly](https://attack.mitre.org/groups/G1034) used [Reg](https://attack.mitre.org/software/S0075) to dump the Security Account Manager (SAM) hive from victim machines for follow-on credential extraction.(Citation: Symantec Daggerfly 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1003.002|Security Account Manager|


[Daggerfly](https://attack.mitre.org/groups/G1034) has attempted to use scheduled tasks for persistence in victim environments.(Citation: ESET EvasivePanda 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[Daggerfly](https://attack.mitre.org/groups/G1034) created code signing certificates to sign malicious macOS files.(Citation: ESET EvasivePanda 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1587.002|Code Signing Certificates|


[Daggerfly](https://attack.mitre.org/groups/G1034) uses HTTP for command and control communication.(Citation: ESET EvasivePanda 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[Daggerfly](https://attack.mitre.org/groups/G1034) proxied execution of malicious DLLs through a renamed rundll32.exe binary.(Citation: Symantec Daggerfly 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1218.011|Rundll32|


[Daggerfly](https://attack.mitre.org/groups/G1034) is associated with several supply chain compromises using malicious updates to compromise victims.(Citation: ESET EvasivePanda 2023)(Citation: ESET EvasivePanda 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1195.002|Compromise Software Supply Chain|


[Daggerfly](https://attack.mitre.org/groups/G1034) has used legitimate software to side-load [PlugX](https://attack.mitre.org/software/S0013) loaders onto victim systems.(Citation: Symantec Daggerfly 2023) [Daggerfly](https://attack.mitre.org/groups/G1034) is also linked to multiple other instances of side-loading for initial loading activity.(Citation: ESET EvasivePanda 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1574.002|DLL Side-Loading|


[Daggerfly](https://attack.mitre.org/groups/G1034) utilizes victim machine operating system information to create custom User Agent strings for subsequent command and control communication.(Citation: ESET EvasivePanda 2024)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Daggerfly](https://attack.mitre.org/groups/G1034) has used strategic website compromise to deliver a malicious link requiring user interaction.(Citation: ESET EvasivePanda 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[Daggerfly](https://attack.mitre.org/groups/G1034) has used PowerShell and [BITSAdmin](https://attack.mitre.org/software/S0190) to retrieve follow-on payloads from external locations for execution on victim machines.(Citation: Symantec Daggerfly 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Daggerfly](https://attack.mitre.org/groups/G1034) used PowerShell to download and execute remote-hosted files on victim systems.(Citation: Symantec Daggerfly 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Daggerfly](https://attack.mitre.org/groups/G1034) used a renamed version of rundll32.exe, such as "dbengin.exe" located in the `ProgramData\Microsoft\PlayReady` directory, to proxy malicious DLL execution.(Citation: Symantec Daggerfly 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1036.003|Rename System Utilities|


[Daggerfly](https://attack.mitre.org/groups/G1034) created a local account on victim machines to maintain access.(Citation: Symantec Daggerfly 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, Containers|T1136.001|Local Account|


[Daggerfly](https://attack.mitre.org/groups/G1034) compromised web servers hosting updates for software as part of a supply chain intrusion.(Citation: ESET EvasivePanda 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1584.004|Server|


[Daggerfly](https://attack.mitre.org/groups/G1034) has used strategic website compromise for initial access against victims.(Citation: ESET EvasivePanda 2024)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, Identity Provider|T1189|Drive-by Compromise|


[Daggerfly](https://attack.mitre.org/groups/G1034) has used signed, but not notarized, malicious files for execution in macOS environments.(Citation: ESET EvasivePanda 2024)
|['enterprise-attack']|enterprise-attack|macOS, Windows|T1553.002|Code Signing|


[Daggerfly](https://attack.mitre.org/groups/G1034) used [Reg](https://attack.mitre.org/software/S0075) to dump the Security Account Manager (SAM), System, and Security Windows registry hives from victim machines.(Citation: Symantec Daggerfly 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1012|Query Registry|

