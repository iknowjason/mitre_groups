# Evilnum - G0120

**Created**: 2021-01-22T16:46:17.790Z

**Modified**: 2022-04-25T14:00:00.188Z

**Contributors**: 

## Aliases

Evilnum

## Description

[Evilnum](https://attack.mitre.org/groups/G0120) is a financially motivated threat group that has been active since at least 2018.(Citation: ESET EvilNum July 2020)

## Techniques Used


[Evilnum](https://attack.mitre.org/groups/G0120) has used a component called TerraLoader to check certain hardware and file information to detect sandboxed environments. (Citation: ESET EvilNum July 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1497.001|System Checks|


[EVILNUM](https://attack.mitre.org/software/S0568) has used the malware variant, TerraTV, to run a legitimate TeamViewer application to connect to compromrised machines.(Citation: ESET EvilNum July 2020)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1219|Remote Access Software|


[Evilnum](https://attack.mitre.org/groups/G0120) can steal cookies and session information from browsers.(Citation: ESET EvilNum July 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Office Suite|T1539|Steal Web Session Cookie|


[Evilnum](https://attack.mitre.org/groups/G0120) has used the malware variant, TerraTV, to load a malicious DLL placed in the TeamViewer directory, instead of the original Windows DLL located in a system folder.(Citation: ESET EvilNum July 2020) 
|['enterprise-attack']|enterprise-attack|Windows|T1574.001|DLL Search Order Hijacking|


[Evilnum](https://attack.mitre.org/groups/G0120) has sent spearphishing emails designed to trick the recipient into opening malicious shortcut links which downloads a .LNK file.(Citation: ESET EvilNum July 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[Evilnum](https://attack.mitre.org/groups/G0120) has used PowerShell to bypass UAC.(Citation: ESET EvilNum July 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1548.002|Bypass User Account Control|


[Evilnum](https://attack.mitre.org/groups/G0120) has sent spearphishing emails containing a link to a zip file hosted on Google Drive.(Citation: ESET EvilNum July 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[Evilnum](https://attack.mitre.org/groups/G0120) has deleted files used during infection.(Citation: ESET EvilNum July 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[Evilnum](https://attack.mitre.org/groups/G0120) can deploy additional components or tools as needed.(Citation: ESET EvilNum July 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Evilnum](https://attack.mitre.org/groups/G0120) can collect email credentials from victims.(Citation: ESET EvilNum July 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1555|Credentials from Password Stores|


[Evilnum](https://attack.mitre.org/groups/G0120) has used malicious JavaScript files on the victim's machine.(Citation: ESET EvilNum July 2020)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.007|JavaScript|

