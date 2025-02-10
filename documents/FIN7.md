# FIN7 - G0046

**Created**: 2017-05-31T21:32:09.460Z

**Modified**: 2024-04-17T22:09:41.004Z

**Contributors**: Edward Millington

## Aliases

FIN7,GOLD NIAGARA,ITG14,Carbon Spider,ELBRUS,Sangria Tempest

## Description

[FIN7](https://attack.mitre.org/groups/G0046) is a financially-motivated threat group that has been active since 2013. [FIN7](https://attack.mitre.org/groups/G0046) has primarily targeted the retail, restaurant, hospitality, software, consulting, financial services, medical equipment, cloud services, media, food and beverage, transportation, and utilities industries in the U.S. A portion of [FIN7](https://attack.mitre.org/groups/G0046) was run out of a front company called Combi Security and often used point-of-sale malware for targeting efforts. Since 2020, [FIN7](https://attack.mitre.org/groups/G0046) shifted operations to a big game hunting (BGH) approach including use of [REvil](https://attack.mitre.org/software/S0496) ransomware and their own Ransomware as a Service (RaaS), Darkside. FIN7 may be linked to the [Carbanak](https://attack.mitre.org/groups/G0008) Group, but there appears to be several groups using [Carbanak](https://attack.mitre.org/software/S0030) malware and are therefore tracked separately.(Citation: FireEye FIN7 March 2017)(Citation: FireEye FIN7 April 2017)(Citation: FireEye CARBANAK June 2017)(Citation: FireEye FIN7 Aug 2018)(Citation: CrowdStrike Carbon Spider August 2021)(Citation: Mandiant FIN7 Apr 2022)

## Techniques Used


[FIN7](https://attack.mitre.org/groups/G0046) has used malicious links to lure victims into downloading malware.(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[FIN7](https://attack.mitre.org/groups/G0046) used SQL scripts to help perform tasks on the victim's machine.(Citation: FireEye FIN7 Aug 2018)(Citation: Flashpoint FIN 7 March 2019)(Citation: FireEye FIN7 Aug 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network, IaaS, Office Suite, Identity Provider|T1059|Command and Scripting Interpreter|


[FIN7](https://attack.mitre.org/groups/G0046) has used random junk code to obfuscate malware code.(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1027.001|Binary Padding|


[FIN7](https://attack.mitre.org/groups/G0046) has compromised targeted organizations through exploitation of CVE-2021-31207 in Exchange.(Citation: Microsoft Ransomware as a Service)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[FIN7](https://attack.mitre.org/groups/G0046) has used SSH to move laterally through victim environments.(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS|T1021.004|SSH|


[FIN7](https://attack.mitre.org/groups/G0046) has signed [Carbanak](https://attack.mitre.org/software/S0030) payloads with legally purchased code signing certificates. [FIN7](https://attack.mitre.org/groups/G0046) has also digitally signed their phishing documents, backdoors and other staging tools to bypass security controls.(Citation: FireEye CARBANAK June 2017)(Citation: FireEye FIN7 Aug 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows|T1553.002|Code Signing|


[FIN7](https://attack.mitre.org/groups/G0046) has harvested valid administrative credentials for lateral movement.(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[FIN7](https://attack.mitre.org/groups/G0046) has used TightVNC to control compromised hosts.(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1021.005|VNC|


[FIN7](https://attack.mitre.org/groups/G0046) has conducted broad phishing campaigns using malicious links.(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[FIN7](https://attack.mitre.org/groups/G0046) has attempted to run Darkside ransomware with the filename sleep.exe.(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[FIN7](https://attack.mitre.org/groups/G0046) malware has created scheduled tasks to establish persistence.(Citation: FireEye FIN7 April 2017)(Citation: Morphisec FIN7 June 2017)(Citation: FireEye FIN7 Aug 2018)(Citation: Flashpoint FIN 7 March 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1053.005|Scheduled Task|


[FIN7](https://attack.mitre.org/groups/G0046) has used the command `cmd.exe /C quser` to collect user session information.(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[FIN7](https://attack.mitre.org/groups/G0046) used VBS scripts to help perform tasks on the victim's machine.(Citation: FireEye FIN7 Aug 2018)(Citation: Flashpoint FIN 7 March 2019)(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[FIN7](https://attack.mitre.org/groups/G0046) has utilized the remote management tool Atera to download malware to a compromised system.(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS|T1219|Remote Access Software|


[FIN7](https://attack.mitre.org/groups/G0046) has used `rundll32.exe` to execute malware on a compromised network.(Citation: Mandiant FIN7 Apr 2022) 
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1218.011|Rundll32|


[FIN7](https://attack.mitre.org/groups/G0046) has created a scheduled task named “AdobeFlashSync” to establish persistence.(Citation: Morphisec FIN7 June 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, macOS|T1036.004|Masquerade Task or Service|


[FIN7](https://attack.mitre.org/groups/G0046) has used WMI to install malware on targeted systems.(Citation: eSentire FIN7 July 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1047|Windows Management Instrumentation|


[FIN7](https://attack.mitre.org/groups/G0046) malware has created Registry Run and RunOnce keys to establish persistence, and has also added items to the Startup folder.(Citation: FireEye FIN7 April 2017)(Citation: FireEye FIN7 Aug 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[FIN7](https://attack.mitre.org/groups/G0046) has compromised a digital product website and modified multiple download links to point to trojanized versions of offered digital products.(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1608.004|Drive-by Target|


[FIN7](https://attack.mitre.org/groups/G0046) used JavaScript scripts to help perform tasks on the victim's machine.(Citation: FireEye FIN7 Aug 2018)(Citation: Flashpoint FIN 7 March 2019)(Citation: FireEye FIN7 Aug 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux|T1059.007|JavaScript|


[FIN7](https://attack.mitre.org/groups/G0046) used images embedded into document lures that only activate the payload when a user double clicks to avoid sandboxes.(Citation: FireEye FIN7 April 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1497.002|User Activity Based Checks|


[FIN7](https://attack.mitre.org/groups/G0046) spear phishing campaigns have included malicious Word documents with DDE execution.(Citation: CyberScoop FIN7 Oct 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1559.002|Dynamic Data Exchange|


[FIN7](https://attack.mitre.org/groups/G0046) has used the command `net group "domain admins" /domain` to enumerate domain groups.(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1069.002|Domain Groups|


[FIN7](https://attack.mitre.org/groups/G0046) has used application shim databases for persistence.(Citation: FireEye FIN7 Shim Databases)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1546.011|Application Shimming|


[FIN7](https://attack.mitre.org/groups/G0046) used a PowerShell script to launch shellcode that retrieved an additional payload.(Citation: FireEye FIN7 April 2017)(Citation: Morphisec FIN7 June 2017)(Citation: FBI Flash FIN7 USB)(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1059.001|PowerShell|


[FIN7](https://attack.mitre.org/groups/G0046) has utilized a variety of tools such as [Cobalt Strike](https://attack.mitre.org/software/S0154), [PowerSploit](https://attack.mitre.org/software/S0194), and the remote management tool, Atera for targeting efforts.(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1588.002|Tool|


[FIN7](https://attack.mitre.org/groups/G0046) has encrypted virtual disk volumes on ESXi servers using a version of Darkside ransomware.(Citation: CrowdStrike Carbon Spider August 2021)(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, IaaS|T1486|Data Encrypted for Impact|


[FIN7](https://attack.mitre.org/groups/G0046) has set up Amazon S3 buckets to host trojanized digital products.(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1583.006|Web Services|


[FIN7](https://attack.mitre.org/groups/G0046) has used RDP to move laterally in victim environments.(Citation: CrowdStrike Carbon Spider August 2021)

|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1021.001|Remote Desktop Protocol|


[FIN7](https://attack.mitre.org/groups/G0046) used legitimate services like Google Docs, Google Scripts, and Pastebin for C2.(Citation: FireEye FIN7 Aug 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1102.002|Bidirectional Communication|


[FIN7](https://attack.mitre.org/groups/G0046) has downloaded additional malware to execute on the victim's machine, including by using a PowerShell script to launch shellcode that retrieves an additional payload.(Citation: FireEye FIN7 April 2017)(Citation: DOJ FIN7 Aug 2018)(Citation: Mandiant FIN7 Apr 2022) 
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[FIN7](https://attack.mitre.org/groups/G0046) has used compromised credentials for access as SYSTEM on Exchange servers.(Citation: Microsoft Ransomware as a Service)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Containers, Network|T1078.003|Local Accounts|


[FIN7](https://attack.mitre.org/groups/G0046) created new Windows services and added them to the startup directories for persistence.(Citation: FireEye FIN7 Aug 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1543.003|Windows Service|


[FIN7](https://attack.mitre.org/groups/G0046) has collected files and other sensitive information from a compromised network.(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[FIN7](https://attack.mitre.org/groups/G0046) has registered look-alike domains for use in phishing campaigns.(Citation: eSentire FIN7 July 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1583.001|Domains|


[FIN7](https://attack.mitre.org/groups/G0046) has used port-protocol mismatches on ports such as 53, 80, 443, and 8080 during C2.(Citation: FireEye FIN7 Aug 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1571|Non-Standard Port|


[FIN7](https://attack.mitre.org/groups/G0046) created a custom video recording capability that could be used to monitor operations in the victim's environment.(Citation: FireEye FIN7 Aug 2018)(Citation: DOJ FIN7 Aug 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux|T1125|Video Capture|


[FIN7](https://attack.mitre.org/groups/G0046) has used mshta.exe to execute VBScript to execute malicious code on victim systems.(Citation: FireEye FIN7 April 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1218.005|Mshta|


[FIN7](https://attack.mitre.org/groups/G0046) has used fragmented strings, environment variables, standard input (stdin), and native character-replacement functionalities to obfuscate commands.(Citation: FireEye Obfuscation June 2017)(Citation: FireEye FIN7 Aug 2018)(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1027.010|Command Obfuscation|


[FIN7](https://attack.mitre.org/groups/G0046) lured victims to double-click on images in the attachments they sent which would then execute the hidden LNK file.(Citation: FireEye FIN7 April 2017)(Citation: eSentire FIN7 July 2021)(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[FIN7](https://attack.mitre.org/groups/G0046) has gained initial access by compromising a victim's software supply chain.(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1195.002|Compromise Software Supply Chain|


[FIN7](https://attack.mitre.org/groups/G0046) has exploited ZeroLogon (CVE-2020-1472) against vulnerable domain controllers.(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS|T1210|Exploitation of Remote Services|


[FIN7](https://attack.mitre.org/groups/G0046) has developed malware for use in operations, including the creation of infected removable media.(Citation: FBI Flash FIN7 USB)(Citation: FireEye FIN7 Oct 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1587.001|Malware|


[FIN7](https://attack.mitre.org/groups/G0046) captured screenshots and desktop video recordings.(Citation: DOJ FIN7 Aug 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1113|Screen Capture|


[FIN7](https://attack.mitre.org/groups/G0046) has exfiltrated stolen data to the MEGA file sharing site.(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1567.002|Exfiltration to Cloud Storage|


[FIN7](https://attack.mitre.org/groups/G0046) used the command prompt to launch commands on the victim’s machine.(Citation: FireEye FIN7 Aug 2018)(Citation: Flashpoint FIN 7 March 2019)(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1059.003|Windows Command Shell|


[FIN7](https://attack.mitre.org/groups/G0046) sent spearphishing emails with either malicious Microsoft Documents or RTF files attached.(Citation: FireEye FIN7 April 2017)(Citation: DOJ FIN7 Aug 2018)(Citation: Flashpoint FIN 7 March 2019)(Citation: eSentire FIN7 July 2021)(Citation: CrowdStrike Carbon Spider August 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[FIN7](https://attack.mitre.org/groups/G0046) actors have mailed USB drives to potential victims containing malware that downloads and installs various backdoors, including in some cases for ransomware operations.(Citation: FBI Flash FIN7 USB)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1091|Replication Through Removable Media|


[FIN7](https://attack.mitre.org/groups/G0046) has performed C2 using DNS via A, OPT, and TXT records.(Citation: FireEye FIN7 Aug 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1071.004|DNS|


[FIN7](https://attack.mitre.org/groups/G0046)'s Harpy backdoor malware can use DNS as a backup channel for C2 if HTTP fails.(Citation: Crowdstrike GTR2020 Mar 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS|T1008|Fallback Channels|


[FIN7](https://attack.mitre.org/groups/G0046) has used Kerberoasting PowerShell commands such as, `Invoke-Kerberoast` for credential access and to enable lateral movement.(Citation: CrowdStrike Carbon Spider August 2021)(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1558.003|Kerberoasting|


[FIN7](https://attack.mitre.org/groups/G0046) has staged legitimate software, that was trojanized to contain an Atera agent installer, on Amazon S3.(Citation: Mandiant FIN7 Apr 2022)
|['enterprise-attack']|enterprise-attack, ics-attack|PRE|T1608.001|Upload Malware|

