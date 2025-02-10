# RedCurl - G1039

**Created**: 2024-09-23T21:32:19.337Z

**Modified**: 2024-09-23T23:11:00.562Z

**Contributors**: Joe Gumke, U.S. Bank

## Aliases

RedCurl

## Description

[RedCurl](https://attack.mitre.org/groups/G1039) is a threat actor active since 2018 notable for corporate espionage targeting a variety of locations, including Ukraine, Canada and the United Kingdom, and a variety of industries, including but not limited to travel agencies, insurance companies, and banks.(Citation: group-ib_redcurl1) [RedCurl](https://attack.mitre.org/groups/G1039) is allegedly a Russian-speaking threat actor.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2) The group’s operations typically start with spearphishing emails to gain initial access, then the group executes discovery and collection commands and scripts to find corporate data. The group concludes operations by exfiltrating files to the C2 servers. 

## Techniques Used


[RedCurl](https://attack.mitre.org/groups/G1039) has used web services to download malicious files.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1102|Web Service|


[RedCurl](https://attack.mitre.org/groups/G1039) has used malware with string encryption.(Citation: therecord_redcurl) [RedCurl](https://attack.mitre.org/groups/G1039) has also encrypted data and has encoded PowerShell commands using Base64.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2) [RedCurl](https://attack.mitre.org/groups/G1039) has used `PyArmor` to obfuscate code execution of [LaZagne](https://attack.mitre.org/software/S0349). (Citation: group-ib_redcurl1) Additionally, [RedCurl](https://attack.mitre.org/groups/G1039) has obfuscated downloaded files by renaming them as commonly used tools and has used `echo`, instead of file names themselves, to execute files.(Citation: trendmicro_redcurl) 

|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1027|Obfuscated Files or Information|


[RedCurl](https://attack.mitre.org/groups/G1039) added the “hidden” file attribute to original files, manipulating victims to click on malicious LNK files.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1564.001|Hidden Files and Directories|


[RedCurl](https://attack.mitre.org/groups/G1039) has placed modified LNK files on network drives for lateral movement.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, Linux, macOS, Office Suite|T1080|Taint Shared Content|


[RedCurl](https://attack.mitre.org/groups/G1039) has used malicious files to infect the victim machines.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)(Citation: trendmicro_redcurl) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[RedCurl](https://attack.mitre.org/groups/G1039) has collected data from the local disk of compromised hosts.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[RedCurl](https://attack.mitre.org/groups/G1039) has collected data about network drives.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1039|Data from Network Shared Drive|


[RedCurl](https://attack.mitre.org/groups/G1039) has collected emails to use in future phishing campaigns.(Citation: group-ib_redcurl1)
|['enterprise-attack']|enterprise-attack|Windows|T1114.001|Local Email Collection|


[RedCurl](https://attack.mitre.org/groups/G1039) has used batch scripts to collect data.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS, SaaS, Office Suite|T1119|Automated Collection|


[RedCurl](https://attack.mitre.org/groups/G1039) has used AES-128 CBC to encrypt C2 communications.(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1573.001|Symmetric Cryptography|


[RedCurl](https://attack.mitre.org/groups/G1039) has collected information about email accounts.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1087.003|Email Account|


[RedCurl](https://attack.mitre.org/groups/G1039) has used HTTP, HTTPS and Webdav protocls for C2 communications.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[RedCurl](https://attack.mitre.org/groups/G1039) has used VBScript to run malicious files.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[RedCurl](https://attack.mitre.org/groups/G1039) has downloaded 7-Zip to decompress password protected archives.(Citation: trendmicro_redcurl) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[RedCurl](https://attack.mitre.org/groups/G1039) has collected information about local accounts.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.001|Local Account|


[RedCurl](https://attack.mitre.org/groups/G1039) prompts the user for credentials through a Microsoft Outlook pop-up.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1056.002|GUI Input Capture|


[RedCurl](https://attack.mitre.org/groups/G1039) has created its own tools to use during operations.(Citation: therecord_redcurl)
|['enterprise-attack']|enterprise-attack|PRE|T1587.001|Malware|


[RedCurl](https://attack.mitre.org/groups/G1039) has searched for and collected files on local and network drives.(Citation: therecord_redcurl)(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[RedCurl](https://attack.mitre.org/groups/G1039) has used the Windows Command Prompt to execute commands.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)(Citation: trendmicro_redcurl)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[RedCurl](https://attack.mitre.org/groups/G1039) has used PowerShell to execute commands and to download malware.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)(Citation: trendmicro_redcurl)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[RedCurl](https://attack.mitre.org/groups/G1039) has used phishing emails with malicious files to gain initial access.(Citation: group-ib_redcurl1)(Citation: trendmicro_redcurl) 
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[RedCurl](https://attack.mitre.org/groups/G1039) mimicked legitimate file names and scheduled tasks, e.g. ` MicrosoftCurrentupdatesCheck` and
`MdMMaintenenceTask` to mask malicious files and scheduled tasks.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[RedCurl](https://attack.mitre.org/groups/G1039) has gained access to a contractor to pivot to the victim’s infrastructure.(Citation: therecord_redcurl)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Identity Provider, Office Suite|T1199|Trusted Relationship|


[RedCurl](https://attack.mitre.org/groups/G1039) has used cloud storage to exfiltrate data, in particular the megatools utilities were used to exfiltrate data to Mega, a file storage service.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|IaaS, SaaS, Office Suite|T1537|Transfer Data to Cloud Account|


[RedCurl](https://attack.mitre.org/groups/G1039) has used pcalua.exe to obfuscate binary execution and remote connections.(Citation: trendmicro_redcurl) 
|['enterprise-attack']|enterprise-attack|Windows|T1202|Indirect Command Execution|


[RedCurl](https://attack.mitre.org/groups/G1039) has created scheduled tasks for persistence.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)(Citation: trendmicro_redcurl)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[RedCurl](https://attack.mitre.org/groups/G1039) has used batch scripts to exfiltrate data.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1020|Automated Exfiltration|


[RedCurl](https://attack.mitre.org/groups/G1039) has used HTTPS for C2 communication.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1573.002|Asymmetric Cryptography|


[RedCurl](https://attack.mitre.org/groups/G1039) has used malicious links to infect the victim machines.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[RedCurl](https://attack.mitre.org/groups/G1039) has collected information about the target system, such as system information and list of network connections.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)  
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[RedCurl](https://attack.mitre.org/groups/G1039) has used a Python script to establish outbound communication and to execute commands using SMB port 445.(Citation: trendmicro_redcurl) 
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1059.006|Python|


[RedCurl](https://attack.mitre.org/groups/G1039) used [LaZagne](https://attack.mitre.org/software/S0349) to obtain passwords from memory.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[RedCurl](https://attack.mitre.org/groups/G1039) has used netstat to check if port 4119 is open.(Citation: trendmicro_redcurl) 
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers, Network|T1046|Network Service Discovery|


[RedCurl](https://attack.mitre.org/groups/G1039) has used rundll32.exe to execute malicious files.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)(Citation: trendmicro_redcurl) 
|['enterprise-attack']|enterprise-attack|Windows|T1218.011|Rundll32|


[RedCurl](https://attack.mitre.org/groups/G1039) has collected information about domain accounts using SysInternal’s AdExplorer functionality   .(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[RedCurl](https://attack.mitre.org/groups/G1039) has used phishing emails with malicious links to gain initial access.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[RedCurl](https://attack.mitre.org/groups/G1039) used [LaZagne](https://attack.mitre.org/software/S0349) to obtain passwords in files.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers|T1552.001|Credentials In Files|


[RedCurl](https://attack.mitre.org/groups/G1039) used [LaZagne](https://attack.mitre.org/software/S0349) to obtain passwords from web browsers.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1555.003|Credentials from Web Browsers|


[RedCurl](https://attack.mitre.org/groups/G1039) has deleted files after execution.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)(Citation: trendmicro_redcurl)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[RedCurl](https://attack.mitre.org/groups/G1039) used [LaZagne](https://attack.mitre.org/software/S0349) to obtain passwords in the Registry.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)     
|['enterprise-attack']|enterprise-attack|Windows|T1552.002|Credentials in Registry|


[RedCurl](https://attack.mitre.org/groups/G1039) has established persistence by creating entries in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.(Citation: group-ib_redcurl1)(Citation: group-ib_redcurl2)  
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|

