# Thrip - G0076

**Created**: 2018-10-17T00:14:20.652Z

**Modified**: 2022-04-25T14:00:00.188Z

**Contributors**: 

## Aliases

Thrip

## Description

[Thrip](https://attack.mitre.org/groups/G0076) is an espionage group that has targeted satellite communications, telecoms, and defense contractor companies in the U.S. and Southeast Asia. The group uses custom malware as well as "living off the land" techniques. (Citation: Symantec Thrip June 2018)

## Techniques Used


[Thrip](https://attack.mitre.org/groups/G0076) leveraged PowerShell to run commands to download payloads, traverse the compromised networks, and carry out reconnaissance.(Citation: Symantec Thrip June 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Thrip](https://attack.mitre.org/groups/G0076) has used WinSCP to exfiltrate data from a targeted organization over FTP.(Citation: Symantec Thrip June 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1048.003|Exfiltration Over Unencrypted Non-C2 Protocol|


[Thrip](https://attack.mitre.org/groups/G0076) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002) and [PsExec](https://attack.mitre.org/software/S0029).(Citation: Symantec Thrip June 2018)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[Thrip](https://attack.mitre.org/groups/G0076) used a cloud-based remote access software called LogMeIn for their attacks.(Citation: Symantec Thrip June 2018)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1219|Remote Access Software|

