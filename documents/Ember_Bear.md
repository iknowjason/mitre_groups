# Ember Bear - G1003

**Created**: 2022-06-09T14:49:57.704Z

**Modified**: 2024-09-06T21:43:44.941Z

**Contributors**: Hannah Simes, BT Security

## Aliases

Ember Bear,UNC2589,Bleeding Bear,DEV-0586,Cadet Blizzard,Frozenvista,UAC-0056

## Description

[Ember Bear](https://attack.mitre.org/groups/G1003) is a Russian state-sponsored cyber espionage group that has been active since at least 2020, linked to Russia's General Staff Main Intelligence Directorate (GRU) 161st Specialist Training Center (Unit 29155).(Citation: CISA GRU29155 2024) [Ember Bear](https://attack.mitre.org/groups/G1003) has primarily focused operations against Ukrainian government and telecommunication entities, but has also operated against critical infrastructure entities in Europe and the Americas.(Citation: Cadet Blizzard emerges as novel threat actor) [Ember Bear](https://attack.mitre.org/groups/G1003) conducted the [WhisperGate](https://attack.mitre.org/software/S0689) destructive wiper attacks against Ukraine in early 2022.(Citation: CrowdStrike Ember Bear Profile March 2022)(Citation: Mandiant UNC2589 March 2022)(Citation: CISA GRU29155 2024) There is some confusion as to whether [Ember Bear](https://attack.mitre.org/groups/G1003) overlaps with another Russian-linked entity referred to as [Saint Bear](https://attack.mitre.org/groups/G1031). At present available evidence strongly suggests these are distinct activities with different behavioral profiles.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )

## Techniques Used


[Ember Bear](https://attack.mitre.org/groups/G1003) has used tools such as Nmap and MASSCAN for remote service discovery.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[Ember Bear](https://attack.mitre.org/groups/G1003) has configured multi-hop proxies via ProxyChains within victim environments.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090.003|Multi-hop Proxy|


[Ember Bear](https://attack.mitre.org/groups/G1003) attempts to collect mail from accessed systems and servers.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Office Suite|T1114|Email Collection|


[Ember Bear](https://attack.mitre.org/groups/G1003) gathers credential material from target systems, such as SSH keys, to facilitate access to victim environments.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1003|OS Credential Dumping|


[Ember Bear](https://attack.mitre.org/groups/G1003) has compressed collected data prior to exfiltration.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560|Archive Collected Data|


[Ember Bear](https://attack.mitre.org/groups/G1003) has renamed the legitimate Sysinternals tool procdump to alternative names such as <code>dump64.exe</code> to evade detection.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036|Masquerading|


[Ember Bear](https://attack.mitre.org/groups/G1003) uses services such as IVPN, SurfShark, and Tor to add anonymization to operations.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|PRE|T1583|Acquire Infrastructure|


[Ember Bear](https://attack.mitre.org/groups/G1003) retrieves follow-on payloads direct from adversary-owned infrastructure for deployment on compromised hosts.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1570|Lateral Tool Transfer|


[Ember Bear](https://attack.mitre.org/groups/G1003) uses socket-based tunneling utilities for command and control purposes such as NetCat and Go Simple Tunnel (GOST). These tunnels are used to push interactive command prompts over the created sockets.(Citation: Cadet Blizzard emerges as novel threat actor) [Ember Bear](https://attack.mitre.org/groups/G1003) has also used reverse TCP connections from Meterpreter installations to communicate back with C2 infrastructure.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, Network|T1095|Non-Application Layer Protocol|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used virtual private servers (VPSs) to host tools, perform reconnaissance, exploit victim infrastructure, and as a destination for data exfiltration.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1583.003|Virtual Private Server|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used publicly available tools such as MASSCAN and Acunetix for vulnerability scanning of public-facing infrastructure.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1595.002|Vulnerability Scanning|


[Ember Bear](https://attack.mitre.org/groups/G1003) gains initial access to victim environments by exploiting external-facing services. Examples include exploitation of CVE-2021-26084 in Confluence servers; CVE-2022-41040, ProxyShell, and other vulnerabilities in Microsoft Exchange; and multiple vulnerabilities in open-source platforms such as content management systems.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[Ember Bear](https://attack.mitre.org/groups/G1003) has enumerated SECURITY and SYSTEM log files during intrusions.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1654|Log Enumeration|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used various non-standard ports for C2 communication.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1571|Non-Standard Port|


[Ember Bear](https://attack.mitre.org/groups/G1003) deletes files related to lateral movement to avoid detection.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[Ember Bear](https://attack.mitre.org/groups/G1003) engages in mass collection from compromised systems during intrusions.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS, SaaS, Office Suite|T1119|Automated Collection|


[Ember Bear](https://attack.mitre.org/groups/G1003) have used VPNs both for initial access to victim environments and for persistence within them following compromise.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[Ember Bear](https://attack.mitre.org/groups/G1003) has created accounts on dark web forums to obtain various tools and malware.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1585|Establish Accounts|


[Ember Bear](https://attack.mitre.org/groups/G1003) deploys web shells following initial access for either follow-on command execution or protocol tunneling. Example web shells used by [Ember Bear](https://attack.mitre.org/groups/G1003) include P0wnyshell, reGeorg, [P.A.S. Webshell](https://attack.mitre.org/software/S0598), and custom variants of publicly-available web shell examples.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[Ember Bear](https://attack.mitre.org/groups/G1003) is linked to the defacement of several Ukrainian organization websites.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1491.002|External Defacement|


[Ember Bear](https://attack.mitre.org/groups/G1003) has targeted IP ranges for vulnerability scanning related to government and critical infrastructure organizations.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1595.001|Scanning IP Blocks|


[Ember Bear](https://attack.mitre.org/groups/G1003) has conducted password spraying against Outlook Web Access (OWA) infrastructure to identify valid user names and passwords.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110.003|Password Spraying|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used exploits for vulnerabilities such as MS17-010, also known as `Eternal Blue`, during operations.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1210|Exploitation of Remote Services|


[Ember Bear](https://attack.mitre.org/groups/G1003) uses remotely scheduled tasks to facilitate remote command execution on victim machines.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used ProxyChains to tunnel protocols to internal networks.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1572|Protocol Tunneling|


[Ember Bear](https://attack.mitre.org/groups/G1003) used the `su-bruteforce` tool to brute force specific users using the `su` command.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110|Brute Force|


[Ember Bear](https://attack.mitre.org/groups/G1003) has exfiltrated images from compromised IP cameras.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1125|Video Capture|


[Ember Bear](https://attack.mitre.org/groups/G1003) has acquired malware and related tools from dark web forums.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1588.001|Malware|


[Ember Bear](https://attack.mitre.org/groups/G1003) has obtained exploitation scripts against publicly-disclosed vulnerabilities from public repositories.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1588.005|Exploits|


[Ember Bear](https://attack.mitre.org/groups/G1003) has compromised information technology providers and software developers providing services to targets of interest, building initial access to ultimate victims at least in part through compromise of service providers that work with the victim organizations.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1195|Supply Chain Compromise|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used pass-the-hash techniques for lateral movement in victim environments.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1550.002|Pass the Hash|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used tools such as [Rclone](https://attack.mitre.org/software/S1040) to exfiltrate information from victim environments to cloud storage such as `mega.nz`.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1567.002|Exfiltration to Cloud Storage|


[Ember Bear](https://attack.mitre.org/groups/G1003) gathers victim system information such as enumerating the volume of a given device or extracting system and security event logs for analysis.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[Ember Bear](https://attack.mitre.org/groups/G1003) uses the NirSoft AdvancedRun utility to disable Microsoft Defender Antivirus through stopping the WinDefend service on victim machines. [Ember Bear](https://attack.mitre.org/groups/G1003) disables Windows Defender via registry key changes.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|


[Ember Bear](https://attack.mitre.org/groups/G1003) modifies registry values for anti-forensics and defense evasion purposes.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Windows|T1112|Modify Registry|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used PowerShell commands to gather information from compromised systems,  such as email servers.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used DNS tunnelling tools, such as dnscat/2 and Iodine, for C2 purposes.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.004|DNS|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used frameworks such as [Impacket](https://attack.mitre.org/software/S0357) to dump LSA secrets for credential capture.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1003.004|LSA Secrets|


[Ember Bear](https://attack.mitre.org/groups/G1003) acquires victim credentials by extracting registry hives such as the Security Account Manager through commands such as <code>reg save</code>.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1003.002|Security Account Manager|


[Ember Bear](https://attack.mitre.org/groups/G1003) uses valid network credentials gathered through credential harvesting to move laterally within victim networks, often employing the [Impacket](https://attack.mitre.org/software/S0357) framework to do so.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1021|Remote Services|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used WMI execution with password hashes for command execution and lateral movement.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1047|Windows Management Instrumentation|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used tools such as NMAP for remote system discovery and enumeration in victim environments.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers, Network|T1046|Network Service Discovery|


[Ember Bear](https://attack.mitre.org/groups/G1003) has abused default user names and passwords in externally-accessible IP cameras for initial access.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078.001|Default Accounts|


[Ember Bear](https://attack.mitre.org/groups/G1003) conducted destructive operations against victims, including disk structure wiping, via the [WhisperGate](https://attack.mitre.org/software/S0689) malware in Ukraine.(Citation: Cadet Blizzard emerges as novel threat actor)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1561.002|Disk Structure Wipe|


[Ember Bear](https://attack.mitre.org/groups/G1003) has dumped configuration settings in accessed IP cameras including plaintext credentials.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers|T1552.001|Credentials In Files|


[Ember Bear](https://attack.mitre.org/groups/G1003) uses legitimate Sysinternals tools such as procdump to dump LSASS memory.(Citation: Cadet Blizzard emerges as novel threat actor)(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[Ember Bear](https://attack.mitre.org/groups/G1003) has renamed tools to match legitimate utilities, such as renaming GOST tunneling instances to `java` in victim environments.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used exploits to enable follow-on execution of frameworks such as Meterpreter.(Citation: CISA GRU29155 2024)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1203|Exploitation for Client Execution|


[Ember Bear](https://attack.mitre.org/groups/G1003) has stolen legitimate certificates to sign malicious payloads.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|PRE|T1588.003|Code Signing Certificates|


[Ember Bear](https://attack.mitre.org/groups/G1003) has obtained and used open source scripts from GitHub.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 ) 
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[Ember Bear](https://attack.mitre.org/groups/G1003) has sent spearphishing emails containing malicious attachments in the form of PDFs, Word documents, JavaScript files, and Control Panel File (CPL) executables.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 ) 
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used an open source batch script to modify Windows Defender registry keys.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows|T1112|Modify Registry|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used JavaScript to execute malicious code on a victim's machine.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.007|JavaScript|


[Ember Bear](https://attack.mitre.org/groups/G1003) has attempted to lure users to click on a malicious link within a spearphishing email.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[Ember Bear](https://attack.mitre.org/groups/G1003) has attempted to lure victims into executing malicious files.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Ember Bear](https://attack.mitre.org/groups/G1003) has obfuscated malicious scripts to help avoid detection.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.010|Command Obfuscation|


[Ember Bear](https://attack.mitre.org/groups/G1003) had used `cmd.exe` and Windows Script Host (wscript) to execute malicious code.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Ember Bear](https://attack.mitre.org/groups/G1003) has sent spearphishing emails containing malicious links.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[Ember Bear](https://attack.mitre.org/groups/G1003) has added extra spaces between JavaScript code characters to increase the overall file size.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.001|Binary Padding|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used Discord's content delivery network (CDN) to deliver malware and malicious scripts to a compromised host.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1102|Web Service|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used tools to download malicious code.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Ember Bear](https://attack.mitre.org/groups/G1003) has packed malware to help avoid detection.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1027.002|Software Packing|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used stolen certificates from Electrum Technologies GmbH to sign payloads.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|macOS, Windows|T1553.002|Code Signing|


[Ember Bear](https://attack.mitre.org/groups/G1003) has obfuscated malware to help avoid detection.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1027|Obfuscated Files or Information|


[Ember Bear](https://attack.mitre.org/groups/G1003) has exploited Microsoft Office vulnerability CVE-2017-11882.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1203|Exploitation for Client Execution|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used control panel files (CPL), delivered via e-mail, for execution.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows|T1218.002|Control Panel|


[Ember Bear](https://attack.mitre.org/groups/G1003) has used PowerShell to download and execute malicious code.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Ember Bear](https://attack.mitre.org/groups/G1003) has executed a batch script designed to disable Windows Defender on a compromised host.(Citation: Palo Alto Unit 42 OutSteel SaintBot February 2022 )
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|

