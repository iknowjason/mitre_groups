# APT5 - G1023

**Created**: 2024-02-05T19:27:35.655Z

**Modified**: 2024-03-14T18:53:21.577Z

**Contributors**: @_montysecurity

## Aliases

APT5,Mulberry Typhoon,MANGANESE,BRONZE FLEETWOOD,Keyhole Panda,UNC2630

## Description

[APT5](https://attack.mitre.org/groups/G1023) is a China-based espionage actor that has been active since at least 2007 primarily targeting the telecommunications, aerospace, and defense industries throughout the U.S., Europe, and Asia. [APT5](https://attack.mitre.org/groups/G1023) has displayed advanced tradecraft and significant interest in compromising networking devices and their underlying software including through the use of zero-day exploits.(Citation: NSA APT5 Citrix Threat Hunting December 2022)(Citation: Microsoft East Asia Threats September 2023)(Citation: Mandiant Pulse Secure Zero-Day April 2021)(Citation: Mandiant Pulse Secure Update May 2021)(Citation: FireEye Southeast Asia Threat Landscape March 2015)(Citation: Mandiant Advanced Persistent Threats)  

## Techniques Used


[APT5](https://attack.mitre.org/groups/G1023) has moved laterally throughout victim environments using RDP.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[APT5](https://attack.mitre.org/groups/G1023) has modified file timestamps.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.006|Timestomp|


[APT5](https://attack.mitre.org/groups/G1023) has created Local Administrator accounts to maintain access to systems with short-cycle credential rotation.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, Containers|T1136.001|Local Account|


[APT5](https://attack.mitre.org/groups/G1023) has used PowerShell to accomplish tasks within targeted environments.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[APT5](https://attack.mitre.org/groups/G1023) has used the BLOODMINE utility to parse and extract information from Pulse Secure Connect logs.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1654|Log Enumeration|


[APT5](https://attack.mitre.org/groups/G1023) has used the JAR/ZIP file format for exfiltrated files.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[APT5](https://attack.mitre.org/groups/G1023) has used the Task Manager process to target LSASS process memory in order to obtain NTLM password hashes. [APT5](https://attack.mitre.org/groups/G1023) has also dumped clear text passwords and hashes from memory using [Mimikatz](https://attack.mitre.org/software/S0002) hosted through an RDP mapped drive.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[APT5](https://attack.mitre.org/groups/G1023) has used the CLEANPULSE utility to insert command line strings into a targeted process to prevent certain log events from occurring.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1562.006|Indicator Blocking|


[APT5](https://attack.mitre.org/groups/G1023) has staged data on compromised systems prior to exfiltration often in `C:\Users\Public`.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1074.001|Local Data Staging|


[APT5](https://attack.mitre.org/groups/G1023) has used malware with keylogging capabilities to monitor the communications of targeted entities.(Citation: FireEye Southeast Asia Threat Landscape March 2015)(Citation: Mandiant Advanced Persistent Threats)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Network|T1056.001|Keylogging|


[APT5](https://attack.mitre.org/groups/G1023) has modified legitimate binaries and scripts for Pulse Secure VPNs including the legitimate DSUpgrade.pm file to install the ATRIUM webshell for persistence.(Citation: Mandiant Pulse Secure Zero-Day April 2021)(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1554|Compromise Host Software Binary|


[APT5](https://attack.mitre.org/groups/G1023) has accessed Microsoft M365 cloud environments using stolen credentials. (Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|SaaS, IaaS, Office Suite, Identity Provider|T1078.004|Cloud Accounts|


[APT5](https://attack.mitre.org/groups/G1023) has used the THINBLOOD utility to clear SSL VPN log files located at `/home/runtime/logs`.(Citation: Mandiant Pulse Secure Zero-Day April 2021)(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers, Network, Office Suite|T1070|Indicator Removal|


[APT5](https://attack.mitre.org/groups/G1023) has used SSH for lateral movement in compromised environments including for enabling access to ESXi host servers.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS|T1021.004|SSH|


[APT5](https://attack.mitre.org/groups/G1023) has used cmd.exe for execution on compromised systems.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[APT5](https://attack.mitre.org/groups/G1023) has used the CLEANPULSE utility to insert command line strings into a targeted process to alter its functionality.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1055|Process Injection|


[APT5](https://attack.mitre.org/groups/G1023) has made modifications to the crontab file including in `/var/cron/tabs/`.(Citation: NSA APT5 Citrix Threat Hunting December 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS|T1053.003|Cron|


[APT5](https://attack.mitre.org/groups/G1023) has copied and exfiltrated the SAM Registry hive from targeted systems.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1003.002|Security Account Manager|


[APT5](https://attack.mitre.org/groups/G1023) has deleted scripts and web shells to evade detection.(Citation: Mandiant Pulse Secure Zero-Day April 2021)(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[APT5](https://attack.mitre.org/groups/G1023) has created their own accounts with Local Administrator privileges to maintain access to systems with short-cycle credential rotation.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1098.007|Additional Local or Domain Groups|


[APT5](https://attack.mitre.org/groups/G1023) has used Windows-based utilities to carry out tasks including tasklist.exe. (Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1057|Process Discovery|


[APT5](https://attack.mitre.org/groups/G1023) has used the BLOODMINE utility to discover files with .css, .jpg, .png, .gif, .ico, .js, and .jsp extensions in Pulse Secure Connect logs.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[APT5](https://attack.mitre.org/groups/G1023) has exploited vulnerabilities in externally facing software and devices including Pulse Secure VPNs and Citrix Application Delivery Controllers.(Citation: Mandiant Pulse Secure Zero-Day April 2021)(Citation: Mandiant Pulse Secure Update May 2021)(Citation: NSA APT5 Citrix Threat Hunting December 2022) (Citation: Microsoft East Asia Threats September 2023)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[APT5](https://attack.mitre.org/groups/G1023) has used legitimate account credentials to move laterally through compromised environments.(Citation: Mandiant Pulse Secure Zero-Day April 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1078.002|Domain Accounts|


[APT5](https://attack.mitre.org/groups/G1023) has used the BLOODMINE utility to collect data on web requests from Pulse Secure Connect logs.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1049|System Network Connections Discovery|


[APT5](https://attack.mitre.org/groups/G1023) has installed multiple web shells on compromised servers including on Pulse Secure VPN appliances.(Citation: Mandiant Pulse Secure Zero-Day April 2021)(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[APT5](https://attack.mitre.org/groups/G1023) has named exfiltration archives to mimic Windows Updates at times using filenames with a `KB<digits>.zip` pattern.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[APT5](https://attack.mitre.org/groups/G1023) has cleared the command history on targeted ESXi servers.(Citation: Mandiant Pulse Secure Update May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1070.003|Clear Command History|

