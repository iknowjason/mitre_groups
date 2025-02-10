# Machete - G0095

**Created**: 2019-09-13T12:37:10.394Z

**Modified**: 2021-10-06T19:26:47.988Z

**Contributors**: Matias Nicolas Porolli, ESET

## Aliases

Machete,APT-C-43,El Machete

## Description

[Machete](https://attack.mitre.org/groups/G0095) is a suspected Spanish-speaking cyber espionage group that has been active since at least 2010. It has primarily focused its operations within Latin America, with a particular emphasis on Venezuela, but also in the US, Europe, Russia, and parts of Asia. [Machete](https://attack.mitre.org/groups/G0095) generally targets high-profile organizations such as government institutions, intelligence services, and military units, as well as telecommunications and power companies.(Citation: Cylance Machete Mar 2017)(Citation: Securelist Machete Aug 2014)(Citation: ESET Machete July 2019)(Citation: 360 Machete Sep 2020)

## Techniques Used


[Machete](https://attack.mitre.org/groups/G0095) has relied on users opening malicious attachments delivered through spearphishing to execute malware.(Citation: Cylance Machete Mar 2017)(Citation: Securelist Machete Aug 2014)(Citation: ESET Machete July 2019)(Citation: 360 Machete Sep 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Machete](https://attack.mitre.org/groups/G0095) has sent phishing emails that contain a link to an external server with ZIP and RAR archives.(Citation: Cylance Machete Mar 2017)(Citation: ESET Machete July 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[Machete](https://attack.mitre.org/groups/G0095) has used batch files to initiate additional downloads of malicious files.(Citation: 360 Machete Sep 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Machete](https://attack.mitre.org/groups/G0095) has created scheduled tasks to maintain [Machete](https://attack.mitre.org/software/S0409)'s persistence.(Citation: 360 Machete Sep 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[Machete](https://attack.mitre.org/groups/G0095) used multiple compiled Python scripts on the victim’s system. [Machete](https://attack.mitre.org/groups/G0095)'s main backdoor [Machete](https://attack.mitre.org/software/S0409) is also written in Python.(Citation: Cylance Machete Mar 2017)(Citation: ESET Machete July 2019)(Citation: 360 Machete Sep 2020)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1059.006|Python|


[Machete](https://attack.mitre.org/groups/G0095) has embedded malicious macros within spearphishing attachments to download additional files.(Citation: 360 Machete Sep 2020)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[Machete](https://attack.mitre.org/groups/G0095)'s [Machete](https://attack.mitre.org/software/S0409) MSI installer has masqueraded as a legitimate Adobe Acrobat Reader installer.(Citation: 360 Machete Sep 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


 [Machete](https://attack.mitre.org/groups/G0095) has delivered spearphishing emails that contain a zipped file with malicious contents.(Citation: Securelist Machete Aug 2014)(Citation: ESET Machete July 2019)(Citation: 360 Machete Sep 2020)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Machete](https://attack.mitre.org/groups/G0095) has has relied on users opening malicious links delivered through spearphishing to execute malware.(Citation: Cylance Machete Mar 2017)(Citation: Securelist Machete Aug 2014)(Citation: ESET Machete July 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[Machete](https://attack.mitre.org/groups/G0095) has distributed [Machete](https://attack.mitre.org/software/S0409) through a fake blog website.(Citation: Securelist Machete Aug 2014)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, Identity Provider|T1189|Drive-by Compromise|


[Machete](https://attack.mitre.org/groups/G0095) has used msiexec to install the [Machete](https://attack.mitre.org/software/S0409) malware.(Citation: 360 Machete Sep 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1218.007|Msiexec|


[Machete](https://attack.mitre.org/groups/G0095) malware used FTP for C2.(Citation: Cylance Machete Mar 2017)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.002|File Transfer Protocols|


[Machete](https://attack.mitre.org/groups/G0095) created their own directories to drop files into.(Citation: Cylance Machete Mar 2017)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1074.001|Local Data Staging|


[Machete](https://attack.mitre.org/groups/G0095) malware used Python’s urllib library to make HTTP requests to the C2 server.(Citation: Cylance Machete Mar 2017)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[Machete](https://attack.mitre.org/groups/G0095) used the startup folder for persistence.(Citation: Cylance Machete Mar 2017)
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[Machete](https://attack.mitre.org/groups/G0095) has used free dynamic DNS domains for C2.(Citation: Cylance Machete Mar 2017)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1568.001|Fast Flux DNS|


[Machete](https://attack.mitre.org/groups/G0095) used scheduled tasks for persistence.(Citation: Cylance Machete Mar 2017)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[Machete](https://attack.mitre.org/groups/G0095) employed some visual obfuscation techniques by naming variables as combinations of letters to hinder analysis.(Citation: Cylance Machete Mar 2017)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1027|Obfuscated Files or Information|


[Machete](https://attack.mitre.org/groups/G0095) had a module in its malware to find, encrypt, and upload files from fixed and removable drives.(Citation: Cylance Machete Mar 2017)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1025|Data from Removable Media|

