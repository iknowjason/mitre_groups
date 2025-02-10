# Saint Bear - G1031

**Created**: 2024-05-25T16:11:54.881Z

**Modified**: 2024-08-12T17:32:47.430Z

**Contributors**: 

## Aliases

Saint Bear,Storm-0587,TA471,UAC-0056,Lorec53

## Description

[Saint Bear](https://attack.mitre.org/groups/G1031) is a Russian-nexus threat actor active since early 2021, primarily targeting entities in Ukraine and Georgia. The group is notable for a specific remote access tool, [Saint Bot](https://attack.mitre.org/software/S1018), and information stealer, [OutSteel](https://attack.mitre.org/software/S1017) in campaigns. [Saint Bear](https://attack.mitre.org/groups/G1031) typically relies on phishing or web staging of malicious documents and related file types for initial access, spoofing government or related entities.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )(Citation: Cadet Blizzard emerges as novel threat actor) [Saint Bear](https://attack.mitre.org/groups/G1031) has previously been confused with [Ember Bear](https://attack.mitre.org/groups/G1003) operations, but analysis of behaviors, tools, and targeting indicates these are distinct clusters.

## Techniques Used


[Saint Bear](https://attack.mitre.org/groups/G1031) has delivered malicious Microsoft Office files containing an embedded JavaScript object that would, on execution, download and execute [OutSteel](https://attack.mitre.org/software/S1017) and [Saint Bot](https://attack.mitre.org/software/S1018).(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.007|JavaScript|


[Saint Bear](https://attack.mitre.org/groups/G1031) uses a variety of file formats, such as Microsoft Office documents, ZIP archives, PDF documents, and other items as phishing attachments for initial access.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Saint Bear](https://attack.mitre.org/groups/G1031) has leveraged vulnerabilities in client applications such as CVE-2017-11882 in Microsoft Office to enable code execution in victim environments.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1203|Exploitation for Client Execution|


[Saint Bear](https://attack.mitre.org/groups/G1031) initial loaders will also drop a malicious Windows batch file, available via open source GitHub repositories, that disables Microsoft Defender functionality.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Saint Bear](https://attack.mitre.org/groups/G1031) has, in addition to email-based phishing attachments, used malicious websites masquerading as legitimate entities to host links to malicious files for user execution.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[Saint Bear](https://attack.mitre.org/groups/G1031) has used an initial loader malware featuring a legitimate code signing certificate associated with "Electrum Technologies GmbH."(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|macOS, Windows|T1553.002|Code Signing|


[Saint Bear](https://attack.mitre.org/groups/G1031) gathered victim email information in advance of phishing operations for targeted attacks.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|PRE|T1589.002|Email Addresses|


[Saint Bear](https://attack.mitre.org/groups/G1031) contains several anti-analysis and anti-virtualization checks.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1497|Virtualization/Sandbox Evasion|


[Saint Bear](https://attack.mitre.org/groups/G1031) initial payloads included encoded follow-on payloads located in the resources file of the first-stage loader.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.013|Encrypted/Encoded File|


[Saint Bear](https://attack.mitre.org/groups/G1031) relies extensively on PowerShell execution from malicious attachments and related content to retrieve and execute follow-on payloads.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Saint Bear](https://attack.mitre.org/groups/G1031) relies on user interaction and execution of malicious attachments and similar for initial execution on victim systems.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Saint Bear](https://attack.mitre.org/groups/G1031) has impersonated government and related entities in both phishing activity and developing web sites with malicious links that mimic legitimate resources.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Office Suite|T1656|Impersonation|


[Saint Bear](https://attack.mitre.org/groups/G1031) has used the Windows Script Host (wscript) to execute intermediate files written to victim machines.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, IaaS, Office Suite, Identity Provider|T1059|Command and Scripting Interpreter|


[Saint Bear](https://attack.mitre.org/groups/G1031) has used the Discord content delivery network for hosting malicious content referenced in links and emails.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|PRE|T1608.001|Upload Malware|


[Saint Bear](https://attack.mitre.org/groups/G1031) has leveraged the Discord content delivery network to host malicious content for retrieval during initial access operations.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|PRE|T1583.006|Web Services|


[Saint Bear](https://attack.mitre.org/groups/G1031) will leverage malicious Windows batch scripts to modify registry values associated with Windows Defender functionality.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows|T1112|Modify Registry|


[Saint Bear](https://attack.mitre.org/groups/G1031) clones .NET assemblies from other .NET binaries as well as cloning code signing certificates from other software to obfuscate the initial loader payload.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1027.002|Software Packing|


[Saint Bear](https://attack.mitre.org/groups/G1031) will modify registry entries and scheduled task objects associated with Windows Defender to disable its functionality.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|

