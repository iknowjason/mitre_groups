# Windigo - G0124

**Created**: 2021-02-10T19:57:38.042Z

**Modified**: 2022-04-25T14:00:00.188Z

**Contributors**: 

## Aliases

Windigo

## Description

The [Windigo](https://attack.mitre.org/groups/G0124) group has been operating since at least 2011, compromising thousands of Linux and Unix servers using the [Ebury](https://attack.mitre.org/software/S0377) SSH backdoor to create a spam botnet. Despite law enforcement intervention against the creators, [Windigo](https://attack.mitre.org/groups/G0124) operators continued updating [Ebury](https://attack.mitre.org/software/S0377) through 2019.(Citation: ESET Windigo Mar 2014)(Citation: CERN Windigo June 2019)

## Techniques Used


[Windigo](https://attack.mitre.org/groups/G0124) has used a script to detect which Linux distribution and version is currently installed on the system.(Citation: ESET ForSSHe December 2018)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Windigo](https://attack.mitre.org/groups/G0124) has used a script to gather credentials in files left on disk by OpenSSH backdoors.(Citation: ESET ForSSHe December 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[Windigo](https://attack.mitre.org/groups/G0124) has used a script to detect installed software on targeted systems.(Citation: ESET ForSSHe December 2018)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1518|Software Discovery|


[Windigo](https://attack.mitre.org/groups/G0124) has delivered a generic Windows proxy Win32/Glubteta.M. [Windigo](https://attack.mitre.org/groups/G0124) has also used multiple reverse proxy chains as part of their C2 infrastructure.(Citation: ESET Windigo Mar 2014)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090|Proxy|


[Windigo](https://attack.mitre.org/groups/G0124) has used a Perl script for information gathering.(Citation: ESET ForSSHe December 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, IaaS, Office Suite, Identity Provider|T1059|Command and Scripting Interpreter|


[Windigo](https://attack.mitre.org/groups/G0124) has distributed Windows malware via drive-by downloads.(Citation: ESET Windigo Mar 2014)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, Identity Provider|T1189|Drive-by Compromise|


[Windigo](https://attack.mitre.org/groups/G0124) has used a script to check for the presence of files created by OpenSSH backdoors.(Citation: ESET ForSSHe December 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|

