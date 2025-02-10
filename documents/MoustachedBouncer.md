# MoustachedBouncer - G1019

**Created**: 2023-09-25T18:11:05.672Z

**Modified**: 2023-09-26T14:34:08.342Z

**Contributors**: 

## Aliases

MoustachedBouncer

## Description

[MoustachedBouncer](https://attack.mitre.org/groups/G1019) is a cyberespionage group that has been active since at least 2014 targeting foreign embassies in Belarus.(Citation: MoustachedBouncer ESET August 2023)

## Techniques Used


[MoustachedBouncer](https://attack.mitre.org/groups/G1019) has used plugins to execute PowerShell scripts.(Citation: MoustachedBouncer ESET August 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows|T1059.001|PowerShell|


[MoustachedBouncer](https://attack.mitre.org/groups/G1019) has used malware plugins packed with Themida.(Citation: MoustachedBouncer ESET August 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|macOS, Windows, Linux|T1027.002|Software Packing|


[MoustachedBouncer](https://attack.mitre.org/groups/G1019) has used JavaScript to deliver malware hosted on HTML pages.(Citation: MoustachedBouncer ESET August 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, macOS, Linux|T1059.007|JavaScript|


[MoustachedBouncer](https://attack.mitre.org/groups/G1019) has exploited CVE-2021-1732 to execute malware components with elevated rights.(Citation: MoustachedBouncer ESET August 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows, Containers|T1068|Exploitation for Privilege Escalation|


[MoustachedBouncer](https://attack.mitre.org/groups/G1019) has used a reverse proxy tool similar to the GitHub repository revsocks.(Citation: MoustachedBouncer ESET August 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows, Network|T1090|Proxy|


[MoustachedBouncer](https://attack.mitre.org/groups/G1019) has used plugins to take screenshots on targeted systems.(Citation: MoustachedBouncer ESET August 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows|T1113|Screen Capture|


[MoustachedBouncer](https://attack.mitre.org/groups/G1019) has injected content into DNS, HTTP, and SMB replies to redirect specifically-targeted victims to a fake Windows Update page to download malware.(Citation: MoustachedBouncer ESET August 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows|T1659|Content Injection|


[MoustachedBouncer](https://attack.mitre.org/groups/G1019) has used plugins to save captured screenshots to `.\AActdata\` on an SMB share.(Citation: MoustachedBouncer ESET August 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, IaaS, Linux, macOS|T1074.002|Remote Data Staging|


[MoustachedBouncer](https://attack.mitre.org/groups/G1019) has used legitimate looking filenames for malicious executables including MicrosoftUpdate845255.exe.(Citation: MoustachedBouncer ESET August 2023)
|['mobile-attack']|enterprise-attack, mobile-attack|Android, iOS|T1655.001|Match Legitimate Name or Location|

