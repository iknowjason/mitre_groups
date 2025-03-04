# MuddyWater - G0069

**Created**: 2018-04-18T17:59:24.739Z

**Modified**: 2024-08-29T14:59:08.071Z

**Contributors**: Ozer Sarilar, @ozersarilar, STM,Daniyal Naeem, BT Security,Marco Pedrinazzi, @pedrinazziM

## Aliases

MuddyWater,Earth Vetala,MERCURY,Static Kitten,Seedworm,TEMP.Zagros,Mango Sandstorm,TA450

## Description

[MuddyWater](https://attack.mitre.org/groups/G0069) is a cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MOIS).(Citation: CYBERCOM Iranian Intel Cyber January 2022) Since at least 2017, [MuddyWater](https://attack.mitre.org/groups/G0069) has targeted a range of government and private organizations across sectors, including telecommunications, local government, defense, and oil and natural gas organizations, in the Middle East, Asia, Africa, Europe, and North America.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)(Citation: ClearSky MuddyWater June 2019)(Citation: Reaqta MuddyWater November 2017)(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: Talos MuddyWater Jan 2022)

## Techniques Used


[MuddyWater](https://attack.mitre.org/groups/G0069) has used mshta.exe to execute its [POWERSTATS](https://attack.mitre.org/software/S0223) payload and to pass a PowerShell one-liner for execution.(Citation: FireEye MuddyWater Mar 2018)(Citation: Securelist MuddyWater Oct 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1218.005|Mshta|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware that leveraged WMI for execution and querying host information.(Citation: Securelist MuddyWater Oct 2018)(Citation: ClearSky MuddyWater Nov 2018)(Citation: Talos MuddyWater May 2019)(Citation: DHS CISA AA22-055A MuddyWater February 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1047|Windows Management Instrumentation|


MuddyWater has used legitimate tools [ConnectWise](https://attack.mitre.org/software/S0591), [RemoteUtilities](https://attack.mitre.org/software/S0592), and SimpleHelp to gain access to the target environment.(Citation: Anomali Static Kitten February 2021)(Citation: group-ib_muddywater_infra)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[MuddyWater](https://attack.mitre.org/groups/G0069) maintains persistence on victim networks through side-loading dlls to trick legitimate programs into running malware.(Citation: DHS CISA AA22-055A MuddyWater February 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1574.002|DLL Side-Loading|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used a Word Template, Normal.dotm, for persistence.(Citation: Reaqta MuddyWater November 2017)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1137.001|Office Template Macros|


[MuddyWater](https://attack.mitre.org/groups/G0069) has sent targeted spearphishing e-mails with malicious links.(Citation: Anomali Static Kitten February 2021)(Citation: Trend Micro Muddy Water March 2021)(Citation: Proofpoint TA450 Phishing March 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware that has the capability to execute malicious code via COM, DCOM, and Outlook.(Citation: Securelist MuddyWater Oct 2018)(Citation: ClearSky MuddyWater June 2019)(Citation: DHS CISA AA22-055A MuddyWater February 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1559.001|Component Object Model|


[MuddyWater](https://attack.mitre.org/groups/G0069) has performed credential dumping with [LaZagne](https://attack.mitre.org/software/S0349).(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1003.004|LSA Secrets|


[MuddyWater](https://attack.mitre.org/groups/G0069) has compromised third parties and used compromised accounts to send spearphishing emails with targeted attachments to recipients.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: FireEye MuddyWater Mar 2018)(Citation: Securelist MuddyWater Oct 2018)(Citation: ClearSky MuddyWater June 2019)(Citation: Anomali Static Kitten February 2021)(Citation: Trend Micro Muddy Water March 2021)	(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: Proofpoint TA450 Phishing March 2024)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used <code>cmd.exe net user /domain</code> to enumerate domain users.(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[MuddyWater](https://attack.mitre.org/groups/G0069) can disable the system's local proxy settings.(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|


[MuddyWater](https://attack.mitre.org/groups/G0069) has disguised malicious executables and used filenames and Registry key names associated with Windows Defender.(Citation: FireEye MuddyWater Mar 2018)(Citation: Talos MuddyWater May 2019)(Citation: Anomali Static Kitten February 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used JavaScript files to execute its [POWERSTATS](https://attack.mitre.org/software/S0223) payload.(Citation: ClearSky MuddyWater Nov 2018)(Citation: FireEye MuddyWater Mar 2018)(Citation: DHS CISA AA22-055A MuddyWater February 2022)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.007|JavaScript|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used CMSTP.exe and a malicious INF to execute its [POWERSTATS](https://attack.mitre.org/software/S0223) payload.(Citation: FireEye MuddyWater Mar 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1218.003|CMSTP|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used a custom tool for creating reverse shells.(Citation: Symantec MuddyWater Dec 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[MuddyWater](https://attack.mitre.org/groups/G0069) has stored a decoy PDF file within a victim's `%temp%` folder.(Citation: Talos MuddyWater Jan 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1074.001|Local Data Staging|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware that can capture screenshots of the victim’s machine.(Citation: Securelist MuddyWater Oct 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1113|Screen Capture|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware to check running processes against a hard-coded list of security tools often used by malware researchers.(Citation: Securelist MuddyWater Oct 2018)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1518.001|Security Software Discovery|


[MuddyWater](https://attack.mitre.org/groups/G0069) uses various techniques to bypass UAC.(Citation: ClearSky MuddyWater Nov 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1548.002|Bypass User Account Control|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used AES to encrypt C2 responses.(Citation: Talos MuddyWater Jan 2022)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1573.001|Symmetric Cryptography|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware that can upload additional files to the victim’s machine.(Citation: Securelist MuddyWater Oct 2018)(Citation: ClearSky MuddyWater Nov 2018)(Citation: Reaqta MuddyWater November 2017)(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used a PowerShell backdoor to check for Skype connectivity on the target machine.(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1518|Software Discovery|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used HTTP for C2 communications.(Citation: ClearSky MuddyWater June 2019)(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware that checked if the ProgramData folder had folders or files with the keywords "Kasper," "Panda," or "ESET."(Citation: Securelist MuddyWater Oct 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[MuddyWater](https://attack.mitre.org/groups/G0069) has added Registry Run key <code>KCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemTextEncoding</code> to establish persistence.(Citation: FireEye MuddyWater Mar 2018)(Citation: Securelist MuddyWater Oct 2018)(Citation: Talos MuddyWater May 2019)(Citation: Reaqta MuddyWater November 2017)(Citation: Trend Micro Muddy Water March 2021)(Citation: Talos MuddyWater Jan 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used VBScript files to execute its [POWERSTATS](https://attack.mitre.org/software/S0223) payload, as well as macros.(Citation: FireEye MuddyWater Mar 2018)(Citation: MuddyWater TrendMicro June 2018)(Citation: Securelist MuddyWater Oct 2018)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)(Citation: ClearSky MuddyWater June 2019)(Citation: Reaqta MuddyWater November 2017)(Citation: Trend Micro Muddy Water March 2021)(Citation: Talos MuddyWater Jan 2022)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used file sharing services including OneHub, Sync, and TeraBox to distribute tools.(Citation: Anomali Static Kitten February 2021)(Citation: Trend Micro Muddy Water March 2021)(Citation: Proofpoint TA450 Phishing March 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1583.006|Web Services|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware to collect the victim’s IP address and domain name.(Citation: Securelist MuddyWater Oct 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1016|System Network Configuration Discovery|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used the .NET csc.exe tool to compile executables from downloaded C# code.(Citation: ClearSky MuddyWater Nov 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.004|Compile After Delivery|


[MuddyWater](https://attack.mitre.org/groups/G0069) has decoded base64-encoded PowerShell, JavaScript, and VBScript.(Citation: FireEye MuddyWater Mar 2018)(Citation: MuddyWater TrendMicro June 2018)(Citation: ClearSky MuddyWater Nov 2018)(Citation: Talos MuddyWater Jan 2022)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware that can execute PowerShell scripts via DDE.(Citation: Securelist MuddyWater Oct 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1559.002|Dynamic Data Exchange|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used Daniel Bohannon’s Invoke-Obfuscation framework and obfuscated PowerShell scripts.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: GitHub Invoke-Obfuscation) The group has also used other obfuscation methods, including Base64 obfuscation of VBScripts and PowerShell commands.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: FireEye MuddyWater Mar 2018)(Citation: Securelist MuddyWater Oct 2018)(Citation: Talos MuddyWater May 2019)(Citation: ClearSky MuddyWater June 2019)(Citation: Trend Micro Muddy Water March 2021)(Citation: Talos MuddyWater Jan 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.010|Command Obfuscation|


[MuddyWater](https://attack.mitre.org/groups/G0069) has performed credential dumping with [Mimikatz](https://attack.mitre.org/software/S0002) and procdump64.exe.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[MuddyWater](https://attack.mitre.org/groups/G0069) has distributed URLs in phishing e-mails that link to lure documents.(Citation: Anomali Static Kitten February 2021)(Citation: Trend Micro Muddy Water March 2021)(Citation: Proofpoint TA450 Phishing March 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[MuddyWater](https://attack.mitre.org/groups/G0069) has stored obfuscated JavaScript code in an image file named temp.jpg.(Citation: ClearSky MuddyWater Nov 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.003|Steganography|


[MuddyWater](https://attack.mitre.org/groups/G0069) has run tools including Browser64 to steal passwords saved in victim web browsers.(Citation: Symantec MuddyWater Dec 2018)(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1555.003|Credentials from Web Browsers|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used the native Windows cabinet creation tool, makecab.exe, likely to compress stolen data to be uploaded.(Citation: Symantec MuddyWater Dec 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware to obtain a list of running processes on the system.(Citation: Securelist MuddyWater Oct 2018)(Citation: ClearSky MuddyWater June 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1057|Process Discovery|


[MuddyWater](https://attack.mitre.org/groups/G0069) has performed credential dumping with [LaZagne](https://attack.mitre.org/software/S0349) and other tools, including by dumping passwords saved in victim email.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1555|Credentials from Password Stores|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used one C2 to obtain enumeration scripts and monitor web logs, but a different C2 to send data back.(Citation: Talos MuddyWater May 2019) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1104|Multi-Stage Channels|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used tools to encode C2 communications including Base64 encoding.(Citation: ClearSky MuddyWater June 2019)(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1132.001|Standard Encoding|


[MuddyWater](https://attack.mitre.org/groups/G0069) has developed tools in Python including [Out1](https://attack.mitre.org/software/S0594).(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1059.006|Python|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware that can collect the victim’s OS version and machine name.(Citation: Securelist MuddyWater Oct 2018)(Citation: Talos MuddyWater May 2019)(Citation: Reaqta MuddyWater November 2017)(Citation: Trend Micro Muddy Water March 2021)(Citation: Talos MuddyWater Jan 2022)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used a PowerShell backdoor to check for Skype connections on the target machine.(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1049|System Network Connections Discovery|


[MuddyWater](https://attack.mitre.org/groups/G0069) has run a tool that steals passwords saved in victim email.(Citation: Symantec MuddyWater Dec 2018)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers|T1552.001|Credentials In Files|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware that leveraged rundll32.exe in a Registry Run key to execute a .dll.(Citation: Securelist MuddyWater Oct 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1218.011|Rundll32|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used web services including OneHub to distribute remote access tools.(Citation: Anomali Static Kitten February 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1102.002|Bidirectional Communication|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used PowerShell for execution.(Citation: FireEye MuddyWater Mar 2018)(Citation: MuddyWater TrendMicro June 2018)(Citation: Securelist MuddyWater Oct 2018)(Citation: Symantec MuddyWater Dec 2018)(Citation: ClearSky MuddyWater Nov 2018)(Citation: Talos MuddyWater May 2019)(Citation: Reaqta MuddyWater November 2017)(Citation: Trend Micro Muddy Water March 2021)(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: Talos MuddyWater Jan 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[MuddyWater](https://attack.mitre.org/groups/G0069) has performed credential dumping with [LaZagne](https://attack.mitre.org/software/S0349).(Citation: Unit 42 MuddyWater Nov 2017)(Citation: Symantec MuddyWater Dec 2018)
|['enterprise-attack']|enterprise-attack|Windows, Linux|T1003.005|Cached Domain Credentials|


[MuddyWater](https://attack.mitre.org/groups/G0069) has exploited the Office vulnerability CVE-2017-0199 for execution.(Citation: ClearSky MuddyWater June 2019)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1203|Exploitation for Client Execution|


[MuddyWater](https://attack.mitre.org/groups/G0069) has exploited the Microsoft Exchange memory corruption vulnerability (CVE-2020-0688).(Citation: DHS CISA AA22-055A MuddyWater February 2022)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[MuddyWater](https://attack.mitre.org/groups/G0069) has exploited the Microsoft Netlogon vulnerability (CVE-2020-1472).(Citation: DHS CISA AA22-055A MuddyWater February 2022)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1210|Exploitation of Remote Services|


[MuddyWater](https://attack.mitre.org/groups/G0069) has controlled [POWERSTATS](https://attack.mitre.org/software/S0223) from behind a proxy network to obfuscate the C2 location.(Citation: Symantec MuddyWater Dec 2018) [MuddyWater](https://attack.mitre.org/groups/G0069) has used a series of compromised websites that victims connected to randomly to relay information to command and control (C2).(Citation: Reaqta MuddyWater November 2017)(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090.002|External Proxy|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used malware that can collect the victim’s username.(Citation: Securelist MuddyWater Oct 2018)(Citation: Trend Micro Muddy Water March 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[MuddyWater](https://attack.mitre.org/groups/G0069) has attempted to get users to open malicious PDF attachment and to enable macros and launch malicious Microsoft Word documents delivered via spearphishing emails.(Citation: Unit 42 MuddyWater Nov 2017)(Citation: FireEye MuddyWater Mar 2018)(Citation: Securelist MuddyWater Oct 2018)(Citation: Talos MuddyWater May 2019)(Citation: ClearSky MuddyWater June 2019)(Citation: Reaqta MuddyWater November 2017)(Citation: Anomali Static Kitten February 2021)(Citation: Trend Micro Muddy Water March 2021)(Citation: DHS CISA AA22-055A MuddyWater February 2022)(Citation: Talos MuddyWater Jan 2022)(Citation: Proofpoint TA450 Phishing March 2024)	 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used scheduled tasks to establish persistence.(Citation: Reaqta MuddyWater November 2017)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used legitimate applications ScreenConnect, AteraAgent and SimpleHelp to manage systems remotely and move laterally.(Citation: Trend Micro Muddy Water March 2021)(Citation: Anomali Static Kitten February 2021)(Citation: Proofpoint TA450 Phishing March 2024)(Citation: group-ib_muddywater_infra)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1219|Remote Access Software|


[MuddyWater](https://attack.mitre.org/groups/G0069) has used C2 infrastructure to receive exfiltrated data.(Citation: Reaqta MuddyWater November 2017)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1041|Exfiltration Over C2 Channel|


[MuddyWater](https://attack.mitre.org/groups/G0069) has specifically targeted government agency employees with spearphishing e-mails.(Citation: Anomali Static Kitten February 2021)	 
|['enterprise-attack']|enterprise-attack|PRE|T1589.002|Email Addresses|

