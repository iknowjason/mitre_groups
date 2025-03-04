# Ke3chang - G0004

**Created**: 2017-05-31T21:31:47.177Z

**Modified**: 2024-01-08T21:47:14.257Z

**Contributors**: Pooja Natarajan, NEC Corporation India,Manikantan Srinivasan, NEC Corporation India,Hiroki Nagahama, NEC Corporation

## Aliases

Ke3chang,APT15,Mirage,Vixen Panda,GREF,Playful Dragon,RoyalAPT,NICKEL,Nylon Typhoon

## Description

[Ke3chang](https://attack.mitre.org/groups/G0004) is a threat group attributed to actors operating out of China. [Ke3chang](https://attack.mitre.org/groups/G0004) has targeted oil, government, diplomatic, military, and NGOs in Central and South America, the Caribbean, Europe, and North America since at least 2010.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)(Citation: APT15 Intezer June 2018)(Citation: Microsoft NICKEL December 2021)

## Techniques Used


[Ke3chang](https://attack.mitre.org/groups/G0004) has used compromised credentials and a .NET tool to dump data from Microsoft Exchange mailboxes.(Citation: NCC Group APT15 Alive and Strong)(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1114.002|Remote Email Collection|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used tools to download files to compromised machines.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used implants capable of collecting the signed-in username.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used implants to collect the system language ID of a compromised machine.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1614.001|System Language Discovery|


[Ke3chang](https://attack.mitre.org/groups/G0004) performs account discovery using commands such as <code>net localgroup administrators</code> and <code>net group "REDACTED" /domain</code> on specific permissions groups.(Citation: Mandiant Operation Ke3chang November 2014)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.001|Local Account|


[Ke3chang](https://attack.mitre.org/groups/G0004) has deobfuscated Base64-encoded shellcode strings prior to loading them.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[Ke3chang](https://attack.mitre.org/groups/G0004) performs account discovery using commands such as <code>net localgroup administrators</code> and <code>net group "REDACTED" /domain</code> on specific permissions groups.(Citation: Mandiant Operation Ke3chang November 2014)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used [Mimikatz](https://attack.mitre.org/software/S0002) to generate Kerberos golden tickets.(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Windows|T1558.001|Golden Ticket|


[Ke3chang](https://attack.mitre.org/groups/G0004) actors have been known to copy files to the network shares of other computers to move laterally.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Windows|T1021.002|SMB/Windows Admin Shares|


[Ke3chang](https://attack.mitre.org/groups/G0004) has performed local network configuration discovery using <code>ipconfig</code>.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1016|System Network Configuration Discovery|


[Ke3chang](https://attack.mitre.org/groups/G0004) has compromised networks by exploiting Internet-facing applications, including vulnerable Microsoft Exchange and SharePoint servers.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[Ke3chang](https://attack.mitre.org/groups/G0004) has dropped their malware into legitimate installed software paths including: `C:\ProgramFiles\Realtek\Audio\HDA\AERTSr.exe`, `C:\Program Files (x86)\Foxit Software\Foxit Reader\FoxitRdr64.exe`, `C:\Program Files (x86)\Adobe\Flash Player\AddIns\airappinstaller\airappinstall.exe`, and `C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd64.exe`.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[Ke3chang](https://attack.mitre.org/groups/G0004) has performed  frequent and scheduled data exfiltration from compromised networks.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1020|Automated Exfiltration|


[Ke3chang](https://attack.mitre.org/groups/G0004) has obtained and used tools such as [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[Ke3chang](https://attack.mitre.org/groups/G0004) performs service discovery using <code>net start</code> commands.(Citation: Mandiant Operation Ke3chang November 2014)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1007|System Service Discovery|


[Ke3chang](https://attack.mitre.org/groups/G0004) backdoor RoyalDNS established persistence through adding a service called <code>Nwsapagent</code>.(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Windows|T1543.003|Windows Service|


[Ke3chang](https://attack.mitre.org/groups/G0004) has performed frequent and scheduled data collection from victim networks.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS, SaaS, Office Suite|T1119|Automated Collection|


[Ke3chang](https://attack.mitre.org/groups/G0004) transferred compressed and encrypted RAR files containing exfiltration through the established backdoor command and control channel during operations.(Citation: Mandiant Operation Ke3chang November 2014)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1041|Exfiltration Over C2 Channel|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used network scanning and enumeration tools, including [Ping](https://attack.mitre.org/software/S0097).(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[Ke3chang](https://attack.mitre.org/groups/G0004) has gained access through VPNs including with compromised accounts and stolen VPN certificates.(Citation: NCC Group APT15 Alive and Strong)(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[Ke3chang](https://attack.mitre.org/groups/G0004) has dumped credentials, including by using gsecdump.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Windows|T1003.002|Security Account Manager|


[Ke3chang](https://attack.mitre.org/groups/G0004) uses command-line interaction to search files and directories.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[Ke3chang](https://attack.mitre.org/groups/G0004) performs discovery of permission groups <code>net group /domain</code>.(Citation: Mandiant Operation Ke3chang November 2014)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1069.002|Domain Groups|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used the right-to-left override character in spearphishing attachment names to trick targets into executing .scr and .exe files.(Citation: Mandiant Operation Ke3chang November 2014)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1036.002|Right-to-Left Override|


Malware used by [Ke3chang](https://attack.mitre.org/groups/G0004) can run commands on the command-line interface.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, IaaS, Office Suite, Identity Provider|T1059|Command and Scripting Interpreter|


The [Ke3chang](https://attack.mitre.org/groups/G0004) group has been known to compress data before exfiltration.(Citation: Mandiant Operation Ke3chang November 2014)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560|Archive Collected Data|


[Ke3chang](https://attack.mitre.org/groups/G0004) is known to use 7Zip and RAR with passwords to encrypt data prior to exfiltration.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used NTDSDump and other password dumping tools to gather credentials.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1003.003|NTDS|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used a tool known as RemoteExec (similar to [PsExec](https://attack.mitre.org/software/S0029)) to remotely execute batch scripts and binaries.(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Windows|T1569.002|Service Execution|


[Ke3chang](https://attack.mitre.org/groups/G0004) gathered information and files from local directories for exfiltration.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[Ke3chang](https://attack.mitre.org/groups/G0004) used a SharePoint enumeration and data dumping tool known as spwebmember.(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1213.002|Sharepoint|


[Ke3chang](https://attack.mitre.org/groups/G0004) malware RoyalDNS has used DNS for C2.(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.004|DNS|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used Base64-encoded shellcode strings.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1027|Obfuscated Files or Information|


[Ke3chang](https://attack.mitre.org/groups/G0004) performs local network connection discovery using <code>netstat</code>.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1049|System Network Connections Discovery|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used keyloggers.(Citation: NCC Group APT15 Alive and Strong)(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Network|T1056.001|Keylogging|


[Ke3chang](https://attack.mitre.org/groups/G0004) has dumped credentials, including by using gsecdump.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Windows|T1003.004|LSA Secrets|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used compromised credentials to sign into victims’ Microsoft 365 accounts.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|SaaS, IaaS, Office Suite, Identity Provider|T1078.004|Cloud Accounts|


[Ke3chang](https://attack.mitre.org/groups/G0004) performs operating system information discovery using <code>systeminfo</code> and has used implants to identify the system language and computer name.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used batch scripts in its malware to install persistence mechanisms.(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Ke3chang](https://attack.mitre.org/groups/G0004) malware including RoyalCli and BS2005 have communicated over HTTP with the C2 server through Internet Explorer (IE) by using the COM interface IWebBrowser2.(Citation: NCC Group APT15 Alive and Strong)(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[Ke3chang](https://attack.mitre.org/groups/G0004) has used credential dumpers or stealers to obtain legitimate credentials, which they used to gain access to victim accounts.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[Ke3chang](https://attack.mitre.org/groups/G0004) performs process discovery using <code>tasklist</code> commands.(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1057|Process Discovery|


[Ke3chang](https://attack.mitre.org/groups/G0004) has developed custom malware that allowed them to maintain persistence on victim networks.(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1587.001|Malware|


[Ke3chang](https://attack.mitre.org/groups/G0004) has dumped credentials, including by using [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Mandiant Operation Ke3chang November 2014)(Citation: NCC Group APT15 Alive and Strong)(Citation: Microsoft NICKEL December 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


Several [Ke3chang](https://attack.mitre.org/groups/G0004) backdoors achieved persistence by adding a Run key.(Citation: NCC Group APT15 Alive and Strong)
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|

