# Strider - G0041

**Created**: 2017-05-31T21:32:07.541Z

**Modified**: 2022-04-25T14:00:00.188Z

**Contributors**: 

## Aliases

Strider,ProjectSauron

## Description

[Strider](https://attack.mitre.org/groups/G0041) is a threat group that has been active since at least 2011 and has targeted victims in Russia, China, Sweden, Belgium, Iran, and Rwanda.(Citation: Symantec Strider Blog)(Citation: Kaspersky ProjectSauron Blog)

## Techniques Used


[Strider](https://attack.mitre.org/groups/G0041) has used local servers with both local network and Internet access to act as internal proxy nodes to exfiltrate data from other parts of the network without direct Internet access.(Citation: Kaspersky ProjectSauron Blog)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090.001|Internal Proxy|


[Strider](https://attack.mitre.org/groups/G0041) has registered its persistence module on domain controllers as a Windows LSA (Local System Authority) password filter to acquire credentials any time a domain, local user, or administrator logs in or changes a password.(Citation: Kaspersky ProjectSauron Full Report)
|['enterprise-attack']|enterprise-attack|Windows|T1556.002|Password Filter DLL|


[Strider](https://attack.mitre.org/groups/G0041) has used a hidden file system that is stored as a file on disk.(Citation: Kaspersky ProjectSauron Full Report)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1564.005|Hidden File System|

