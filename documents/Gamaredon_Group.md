# Gamaredon Group - G0047

**Created**: 2017-05-31T21:32:09.849Z

**Modified**: 2024-09-23T20:34:43.022Z

**Contributors**: ESET,Trend Micro Incorporated,Yoshihiro Kori, NEC Corporation,Manikantan Srinivasan, NEC Corporation India,Pooja Natarajan, NEC Corporation India

## Aliases

Gamaredon Group,IRON TILDEN,Primitive Bear,ACTINIUM,Armageddon,Shuckworm,DEV-0157,Aqua Blizzard

## Description

[Gamaredon Group](https://attack.mitre.org/groups/G0047) is a suspected Russian cyber espionage threat group that has targeted military, NGO, judiciary, law enforcement, and non-profit organizations in Ukraine since at least 2013. The name [Gamaredon Group](https://attack.mitre.org/groups/G0047) comes from a misspelling of the word "Armageddon", which was detected in the adversary's early campaigns.(Citation: Palo Alto Gamaredon Feb 2017)(Citation: TrendMicro Gamaredon April 2020)(Citation: ESET Gamaredon June 2020)(Citation: Symantec Shuckworm January 2022)(Citation: Microsoft Actinium February 2022)

In November 2021, the Ukrainian government publicly attributed [Gamaredon Group](https://attack.mitre.org/groups/G0047) to Russia's Federal Security Service (FSB) Center 18.(Citation: Bleepingcomputer Gamardeon FSB November 2021)(Citation: Microsoft Actinium February 2022)

## Techniques Used


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used WMI to execute scripts used for discovery and for determining the C2 IP address.(Citation: CERT-EE Gamaredon January 2021)(Citation: unit42_gamaredon_dec2022) 
|['enterprise-attack']|enterprise-attack|Windows|T1047|Windows Management Instrumentation|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used an Outlook VBA module on infected systems to send phishing emails with malicious attachments to other employees within the organization.(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, SaaS, Office Suite|T1534|Internal Spearphishing|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) macros can scan for Microsoft Word and Excel files to inject with additional malicious macros. [Gamaredon Group](https://attack.mitre.org/groups/G0047) has also used its backdoors to automatically list interesting files (such as Office documents) found on a system.(Citation: ESET Gamaredon June 2020)(Citation: Unit 42 Gamaredon February 2022)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used obfuscated VBScripts with randomly generated variable names and concatenated strings.(Citation: unit42_gamaredon_dec2022) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1001|Data Obfuscation|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has left taunting images and messages on the victims' desktops as proof of system access.(Citation: CERT-EE Gamaredon January 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1491.001|Internal Defacement|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used VPS hosting providers for infrastructure outside of Russia.(Citation: unit42_gamaredon_dec2022)
|['enterprise-attack']|enterprise-attack|PRE|T1583.003|Virtual Private Server|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) malware has used rundll32 to launch additional malicious components.(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1218.011|Rundll32|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has obfuscated .NET executables by inserting junk code.(Citation: ESET Gamaredon June 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.001|Binary Padding|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used legitimate process names to hide malware including <code>svchosst</code>.(Citation: Unit 42 Gamaredon February 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has deployed scripts on compromised systems that automatically scan for interesting documents.(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS, SaaS, Office Suite|T1119|Automated Collection|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has downloaded additional malware and tools onto a compromised host.(Citation: Palo Alto Gamaredon Feb 2017)(Citation: TrendMicro Gamaredon April 2020)(Citation: ESET Gamaredon June 2020)(Citation: Microsoft Actinium February 2022) For example, [Gamaredon Group](https://attack.mitre.org/groups/G0047) uses a backdoor script to retrieve and decode additional payloads once in victim environments.(Citation: unit42_gamaredon_dec2022) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used VNC tools, including UltraVNC, to remotely interact with compromised hosts.(Citation: Symantec Shuckworm January 2022)(Citation: Microsoft Actinium February 2022)(Citation: Unit 42 Gamaredon February 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1021.005|VNC|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has compiled the source code for a downloader directly on the infected system using the built-in <code>Microsoft.CSharp.CSharpCodeProvider</code> class.(Citation: ESET Gamaredon June 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.004|Compile After Delivery|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has collected files from infected systems and uploaded them to a C2 server.(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


A [Gamaredon Group](https://attack.mitre.org/groups/G0047) file stealer can gather the victim's computer name and drive serial numbers to send to a C2 server.(Citation: Palo Alto Gamaredon Feb 2017)(Citation: TrendMicro Gamaredon April 2020)(Citation: CERT-EE Gamaredon January 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has delivered spearphishing emails with malicious attachments to targets.(Citation: TrendMicro Gamaredon April 2020)(Citation: ESET Gamaredon June 2020)(Citation: CERT-EE Gamaredon January 2021)(Citation: Microsoft Actinium February 2022)(Citation: Unit 42 Gamaredon February 2022)(Citation: Secureworks IRON TILDEN Profile)(Citation: unit42_gamaredon_dec2022)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has embedded malicious macros in document templates, which executed VBScript. [Gamaredon Group](https://attack.mitre.org/groups/G0047) has also delivered Microsoft Outlook VBA projects with embedded macros.(Citation: TrendMicro Gamaredon April 2020)(Citation: ESET Gamaredon June 2020)(Citation: CERT-EE Gamaredon January 2021)(Citation: Microsoft Actinium February 2022)(Citation: Secureworks IRON TILDEN Profile)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[Gamaredon Group](https://attack.mitre.org/groups/G0047)'s malware can take screenshots of the compromised computer every minute.(Citation: ESET Gamaredon June 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1113|Screen Capture|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has delivered macros which can tamper with Microsoft Office security settings.(Citation: ESET Gamaredon June 2020)	
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) malware can insert malicious macros into documents using a <code>Microsoft.Office.Interop</code> object.(Citation: ESET Gamaredon June 2020)	
|['enterprise-attack']|enterprise-attack|Windows|T1559.001|Component Object Model|


A [Gamaredon Group](https://attack.mitre.org/groups/G0047) file stealer has the capability to steal data from newly connected logical volumes on a system, including USB drives.(Citation: Palo Alto Gamaredon Feb 2017)(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1025|Data from Removable Media|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used DOCX files to download malicious DOT document templates and has used RTF template injection to download malicious payloads.(Citation: Proofpoint RTF Injection) [Gamaredon Group](https://attack.mitre.org/groups/G0047) can also inject malicious macros or remote templates into documents already present on compromised systems.(Citation: TrendMicro Gamaredon April 2020)(Citation: ESET Gamaredon June 2020)(Citation: CERT-EE Gamaredon January 2021)(Citation: Microsoft Actinium February 2022)(Citation: Unit 42 Gamaredon February 2022)(Citation: Secureworks IRON TILDEN Profile)
|['enterprise-attack']|enterprise-attack|Windows|T1221|Template Injection|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used Telegram Messenger content to discover the IP address for C2 communications.(Citation: unit42_gamaredon_dec2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1102.003|One-Way Communication|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has registered domains to stage payloads.(Citation: Microsoft Actinium February 2022)(Citation: Unit 42 Gamaredon February 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1608.001|Upload Malware|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) malware has collected Microsoft Office documents from mapped network drives.(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1039|Data from Network Shared Drive|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has removed security settings for VBA macro execution by changing registry values <code>HKCU\Software\Microsoft\Office\&lt;version&gt;\&lt;product&gt;\Security\VBAWarnings</code> and <code>HKCU\Software\Microsoft\Office\&lt;version&gt;\&lt;product&gt;\Security\AccessVBOM</code>.(Citation: ESET Gamaredon June 2020)(Citation: CERT-EE Gamaredon January 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1112|Modify Registry|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has tested connectivity between a compromised machine and a C2 server using  [Ping](https://attack.mitre.org/software/S0097) with commands such as `CSIDL_SYSTEM\cmd.exe /c ping -n 1`.(Citation: Symantec Shuckworm January 2022)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1016.001|Internet Connection Discovery|


A [Gamaredon Group](https://attack.mitre.org/groups/G0047) file stealer can gather the victim's username to send to a C2 server.(Citation: Palo Alto Gamaredon Feb 2017)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used <code>hidcon</code> to run batch files in a hidden console window.(Citation: Unit 42 Gamaredon February 2022)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1564.003|Hidden Window|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) tools can delete files used during an operation.(Citation: TrendMicro Gamaredon April 2020)(Citation: Symantec Shuckworm January 2022)(Citation: CERT-EE Gamaredon January 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used obfuscated PowerShell scripts for staging.(Citation: Microsoft Actinium February 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) tools decrypted additional payloads from the C2. [Gamaredon Group](https://attack.mitre.org/groups/G0047) has also decoded base64-encoded source code of a downloader.(Citation: TrendMicro Gamaredon April 2020)(Citation: ESET Gamaredon June 2020) Additionally, [Gamaredon Group](https://attack.mitre.org/groups/G0047) has decoded Telegram content to reveal the IP address for C2 communications.(Citation: unit42_gamaredon_dec2022)  
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used tools to delete files and folders from victims' desktops and profiles.(Citation: CERT-EE Gamaredon January 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1561.001|Disk Content Wipe|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has attempted to get users to click on a link pointing to a malicious HTML file leading to follow-on malicious content.(Citation: unit42_gamaredon_dec2022) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has injected malicious macros into all Word and Excel documents on mapped network drives.(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, Linux, macOS, Office Suite|T1080|Taint Shared Content|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) malware has used <code>CreateProcess</code> to launch additional malicious components.(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1106|Native API|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has incorporated dynamic DNS domains in its infrastructure.(Citation: Unit 42 Gamaredon February 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1568|Dynamic Resolution|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) tools have registered Run keys in the registry to give malicious VBS files persistence.(Citation: TrendMicro Gamaredon April 2020)(Citation: ESET Gamaredon June 2020)(Citation: CERT-EE Gamaredon January 2021)(Citation: unit42_gamaredon_dec2022)
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has attempted to get users to click on Office attachments with malicious macros embedded.(Citation: TrendMicro Gamaredon April 2020)(Citation: ESET Gamaredon June 2020)(Citation: Symantec Shuckworm January 2022)(Citation: CERT-EE Gamaredon January 2021)(Citation: Microsoft Actinium February 2022)(Citation: Unit 42 Gamaredon February 2022)(Citation: Secureworks IRON TILDEN Profile)(Citation: unit42_gamaredon_dec2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used various batch scripts to establish C2 and download additional files. [Gamaredon Group](https://attack.mitre.org/groups/G0047)'s backdoor malware has also been written to a batch file.(Citation: Palo Alto Gamaredon Feb 2017)(Citation: ESET Gamaredon June 2020)(Citation: CERT-EE Gamaredon January 2021)(Citation: Unit 42 Gamaredon February 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used geoblocking to limit downloads of the malicious file to specific geographic locations.(Citation: unit42_gamaredon_dec2022) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1480|Execution Guardrails|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used GitHub repositories for downloaders which will be obtained by the group's .NET executable on the compromised system.(Citation: ESET Gamaredon June 2020)	
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1102|Web Service|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has inserted malicious macros into existing documents, providing persistence when they are reopened. [Gamaredon Group](https://attack.mitre.org/groups/G0047) has loaded the group's previously delivered VBA project by relaunching Microsoft Outlook with the <code>/altvba</code> option, once the Application.Startup event is received.(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1137|Office Application Startup|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used `mshta.exe` to execute malicious files.(Citation: Symantec Shuckworm January 2022)(Citation: unit42_gamaredon_dec2022) 
|['enterprise-attack']|enterprise-attack|Windows|T1218.005|Mshta|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used fast flux DNS to mask their command and control channel behind rotating IP addresses.(Citation: unit42_gamaredon_dec2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1568.001|Fast Flux DNS|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has registered multiple domains to facilitate payload staging and C2.(Citation: Microsoft Actinium February 2022)(Citation: Unit 42 Gamaredon February 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1583.001|Domains|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) tools have contained an application to check performance of USB flash drives. [Gamaredon Group](https://attack.mitre.org/groups/G0047) has also used malware to scan for removable drives.(Citation: Palo Alto Gamaredon Feb 2017)(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1120|Peripheral Device Discovery|


A [Gamaredon Group](https://attack.mitre.org/groups/G0047) file stealer can transfer collected files to a hardcoded C2 server.(Citation: Palo Alto Gamaredon Feb 2017)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1041|Exfiltration Over C2 Channel|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used modules that automatically upload gathered documents to the C2 server.(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1020|Automated Exfiltration|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used HTTP and HTTPS for C2 communications.(Citation: Palo Alto Gamaredon Feb 2017)(Citation: TrendMicro Gamaredon April 2020)(Citation: ESET Gamaredon June 2020)(Citation: Symantec Shuckworm January 2022)(Citation: CERT-EE Gamaredon January 2021)(Citation: Unit 42 Gamaredon February 2022)(Citation: unit42_gamaredon_dec2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used various legitimate tools, such as `mshta.exe` and [Reg](https://attack.mitre.org/software/S0075), and services during operations.(Citation: unit42_gamaredon_dec2022)     
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has delivered self-extracting 7z archive files within malicious document attachments.(Citation: ESET Gamaredon June 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1027|Obfuscated Files or Information|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used tools to enumerate processes on target hosts including Process Explorer.(Citation: Symantec Shuckworm January 2022)(Citation: Unit 42 Gamaredon February 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1057|Process Discovery|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has used obfuscated or encrypted scripts.(Citation: ESET Gamaredon June 2020)(Citation: Microsoft Actinium February 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.010|Command Obfuscation|


[Gamaredon Group](https://attack.mitre.org/groups/G0047) has created scheduled tasks to launch executables after a designated number of minutes have passed.(Citation: ESET Gamaredon June 2020)(Citation: CERT-EE Gamaredon January 2021)(Citation: Microsoft Actinium February 2022)(Citation: unit42_gamaredon_dec2022)	
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|

