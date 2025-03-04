# Tropic Trooper - G0081

**Created**: 2019-01-29T20:17:48.717Z

**Modified**: 2024-04-18T18:24:29.185Z

**Contributors**: Edward Millington

## Aliases

Tropic Trooper,Pirate Panda,KeyBoy

## Description

[Tropic Trooper](https://attack.mitre.org/groups/G0081) is an unaffiliated threat group that has led targeted campaigns against targets in Taiwan, the Philippines, and Hong Kong. [Tropic Trooper](https://attack.mitre.org/groups/G0081) focuses on targeting government, healthcare, transportation, and high-tech industries and has been active since 2011.(Citation: TrendMicro Tropic Trooper Mar 2018)(Citation: Unit 42 Tropic Trooper Nov 2016)(Citation: TrendMicro Tropic Trooper May 2020)

## Techniques Used


[Tropic Trooper](https://attack.mitre.org/groups/G0081) is capable of enumerating the running processes on the system using <code>pslist</code>.(Citation: Unit 42 Tropic Trooper Nov 2016)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1057|Process Discovery|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has installed a service pointing to a malicious DLL dropped to disk.(Citation: PWC KeyBoys Feb 2017)
|['enterprise-attack']|enterprise-attack|Windows|T1543.003|Windows Service|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has used a delivered trojan to download additional files.(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has deleted dropper files on an infected system using command scripts.(Citation: TrendMicro Tropic Trooper May 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) sent spearphishing emails that contained malicious Microsoft Office and fake installer file attachments.(Citation: Unit 42 Tropic Trooper Nov 2016)(Citation: TrendMicro TropicTrooper 2015)(Citation: CitizenLab Tropic Trooper Aug 2018)(Citation: Anomali Pirate Panda April 2020)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has used HTTP in communication with the C2.(Citation: Anomali Pirate Panda April 2020)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has encrypted traffic with the C2 to prevent network detection.(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1573|Encrypted Channel|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has lured victims into executing malware via malicious e-mail attachments.(Citation: Anomali Pirate Panda April 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has created a hidden directory under <code>C:\ProgramData\Apple\Updates\</code> and <code>C:\Users\Public\Documents\Flash\</code>.(Citation: TrendMicro Tropic Trooper Mar 2018)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1564.001|Hidden Files and Directories|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has used Windows command scripts.(Citation: TrendMicro Tropic Trooper May 2020)	
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has used multiple Windows APIs including HttpInitialize, HttpCreateHttpHandle, and HttpAddUrl.(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1106|Native API|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has exfiltrated data using USB storage devices.(Citation: TrendMicro Tropic Trooper May 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1052.001|Exfiltration over USB|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has used SSL to connect to C2 servers.(Citation: TrendMicro Tropic Trooper Mar 2018)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1573.002|Asymmetric Cryptography|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has created shortcuts in the Startup folder to establish persistence.(Citation: Anomali Pirate Panda April 2020)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has started a web service in the target host and wait for the adversary to connect, acting as a web shell.(Citation: TrendMicro Tropic Trooper May 2020)	
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has monitored files' modified time.(Citation: TrendMicro Tropic Trooper May 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has been known to side-load DLLs using a valid version of a Windows Address Book and Windows Defender executable with one of their tools.(Citation: CitizenLab KeyBoy Nov 2016)(Citation: Anomali Pirate Panda April 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1574.002|DLL Side-Loading|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has used scripts to collect the host's network topology.(Citation: TrendMicro Tropic Trooper May 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1016|System Network Configuration Discovery|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) used <code>pr</code> and an openly available tool to scan for open ports on target systems.(Citation: TrendMicro TropicTrooper 2015)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers, Network|T1046|Network Service Discovery|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) used <code>letmein</code> to scan for saved usernames on the target system.(Citation: TrendMicro TropicTrooper 2015)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) delivered malicious documents with the XLSX extension, typically used by OpenXML documents, but the file itself was actually an OLE (XLS) document.(Citation: Unit 42 Tropic Trooper Nov 2016)
|['enterprise-attack']|enterprise-attack|Windows|T1221|Template Injection|


[Tropic Trooper](https://attack.mitre.org/groups/G0081)'s backdoor has communicated to the C2 over the DNS protocol.(Citation: TrendMicro Tropic Trooper May 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.004|DNS|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has executed commands through Microsoft security vulnerabilities, including CVE-2017-11882, CVE-2018-0802, and CVE-2012-0158.(Citation: TrendMicro Tropic Trooper Mar 2018)(Citation: Unit 42 Tropic Trooper Nov 2016)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1203|Exploitation for Client Execution|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has created the Registry key <code>HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</code> and sets the value to establish persistence.(Citation: Unit 42 Tropic Trooper Nov 2016)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1547.004|Winlogon Helper DLL|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has injected a DLL backdoor into dllhost.exe and svchost.exe.(Citation: TrendMicro Tropic Trooper Mar 2018)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1055.001|Dynamic-link Library Injection|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has collected information automatically using the adversary's [USBferry](https://attack.mitre.org/software/S0452) attack.(Citation: TrendMicro Tropic Trooper May 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS, SaaS, Office Suite|T1119|Automated Collection|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has used base64 encoding to hide command strings delivered from the C2.(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1132.001|Standard Encoding|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has encrypted configuration files.(Citation: TrendMicro Tropic Trooper Mar 2018)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.013|Encrypted/Encoded File|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has hidden payloads in Flash directories and fake installer files.(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has used known administrator account credentials to execute the backdoor directly.(Citation: TrendMicro Tropic Trooper May 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers, Network|T1078.003|Local Accounts|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has attempted to transfer [USBferry](https://attack.mitre.org/software/S0452) from an infected USB device by copying an Autorun function to the target machine.(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1091|Replication Through Removable Media|


[Tropic Trooper](https://attack.mitre.org/groups/G0081)'s backdoor could list the infected system's installed software.(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1518|Software Discovery|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) can search for anti-virus software running on the system.(Citation: Unit 42 Tropic Trooper Nov 2016)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1518.001|Security Software Discovery|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has detected a target system’s OS version and system volume information.(Citation: TrendMicro TropicTrooper 2015)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has used a copy function to automatically exfiltrate sensitive data from air-gapped systems using USB storage.(Citation: TrendMicro Tropic Trooper May 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1020|Automated Exfiltration|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) used <code>netview</code> to scan target systems for shared resources.(Citation: TrendMicro TropicTrooper 2015)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1135|Network Share Discovery|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has tested if the localhost network is available and other connection capability on an infected system using command scripts.(Citation: TrendMicro Tropic Trooper May 2020)	
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1049|System Network Connections Discovery|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has used JPG files with encrypted payloads to mask their backdoor routines and evade detection.(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.003|Steganography|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) used shellcode with an XOR algorithm to decrypt a payload. [Tropic Trooper](https://attack.mitre.org/groups/G0081) also decrypted image files which contained a payload.(Citation: Unit 42 Tropic Trooper Nov 2016)(Citation: TrendMicro Tropic Trooper May 2020)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has detected a target system’s OS version.
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Tropic Trooper](https://attack.mitre.org/groups/G0081) has leveraged the BITSadmin command-line tool to create a job and launch a malicious process.
|['enterprise-attack']|enterprise-attack|Windows|T1197|BITS Jobs|

