# Indrik Spider - G0119

**Created**: 2021-01-06T17:46:35.134Z

**Modified**: 2024-10-28T19:11:56.485Z

**Contributors**: Jennifer Kim Roman, CrowdStrike,Liran Ravich, CardinalOps

## Aliases

Indrik Spider,Evil Corp,Manatee Tempest,DEV-0243,UNC2165

## Description

[Indrik Spider](https://attack.mitre.org/groups/G0119) is a Russia-based cybercriminal group that has been active since at least 2014. [Indrik Spider](https://attack.mitre.org/groups/G0119) initially started with the [Dridex](https://attack.mitre.org/software/S0384) banking Trojan, and then by 2017 they began running ransomware operations using [BitPaymer](https://attack.mitre.org/software/S0570), [WastedLocker](https://attack.mitre.org/software/S0612), and Hades ransomware. Following U.S. sanctions and an indictment in 2019, [Indrik Spider](https://attack.mitre.org/groups/G0119) changed their tactics and diversified their toolset.(Citation: Crowdstrike Indrik November 2018)(Citation: Crowdstrike EvilCorp March 2021)(Citation: Treasury EvilCorp Dec 2019)

## Techniques Used


[Indrik Spider](https://attack.mitre.org/groups/G0119) used [Cobalt Strike](https://attack.mitre.org/software/S0154) to carry out credential dumping using ProcDump.(Citation: Symantec WastedLocker June 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[Indrik Spider](https://attack.mitre.org/groups/G0119) used <code>wmic.exe</code> to add a new user to the system.(Citation: Symantec WastedLocker June 2020)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network, Containers, SaaS, Office Suite, Identity Provider|T1136|Create Account|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has developed malware for their operations, including ransomware such as [BitPaymer](https://attack.mitre.org/software/S0570) and [WastedLocker](https://attack.mitre.org/software/S0612).(Citation: Crowdstrike Indrik November 2018)
|['enterprise-attack']|enterprise-attack|PRE|T1587.001|Malware|


[Indrik Spider](https://attack.mitre.org/groups/G0119) used fake updates for FlashPlayer plugin and Google Chrome as initial infection vectors.(Citation: Crowdstrike Indrik November 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used the win32_service WMI class to retrieve a list of services from the system.(Citation: Symantec WastedLocker June 2020) 
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1007|System Service Discovery|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has modified registry keys to prepare for ransomware execution and to disable common administrative utilities.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Windows|T1112|Modify Registry|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has purchased access to victim VPNs to facilitate access to victim environments.(Citation: Mandiant_UNC2165)   
|['enterprise-attack']|enterprise-attack|PRE|T1583|Acquire Infrastructure|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used PowerShell [Empire](https://attack.mitre.org/software/S0363) for execution of malware.(Citation: Crowdstrike Indrik November 2018)(Citation: Symantec WastedLocker June 2020) 
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has searched files to obtain and exfiltrate credentials.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers|T1552.001|Credentials In Files|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has collected credentials from infected systems, including domain accounts.(Citation: Crowdstrike Indrik November 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1078.002|Domain Accounts|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has exfiltrated data using [Rclone](https://attack.mitre.org/software/S1040) or MEGASync prior to deploying ransomware.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1567.002|Exfiltration to Cloud Storage|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used [Cobalt Strike](https://attack.mitre.org/software/S0154) to empty log files.(Citation: Symantec WastedLocker June 2020) Additionally, [Indrik Spider](https://attack.mitre.org/groups/G0119) has cleared all event logs using `wevutil`.(Citation: Mandiant_UNC2165)   
|['enterprise-attack']|enterprise-attack|Windows|T1070.001|Clear Windows Event Logs|


[Indrik Spider](https://attack.mitre.org/groups/G0119) used [PsExec](https://attack.mitre.org/software/S0029) to leverage Windows Defender to disable scanning of all downloaded files and to restrict real-time monitoring.(Citation: Symantec WastedLocker June 2020) [Indrik Spider](https://attack.mitre.org/groups/G0119) has used `MpCmdRun` to revert the definitions in Microsoft Defender.(Citation: Mandiant_UNC2165) Additionally, [Indrik Spider](https://attack.mitre.org/groups/G0119) has used WMI to stop or uninstall and reset anti-virus products and other defensive services.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has downloaded tools, such as the Advanced Port Scanner utility and Lansweeper, to conduct internal reconnaissance of the victim network. [Indrik Spider](https://attack.mitre.org/groups/G0119) has also accessed the victim’s VMware VCenter, which had information about host configuration, clusters, etc.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|PRE|T1590|Gather Victim Network Information|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has stored collected data in a .tmp file.(Citation: Symantec WastedLocker June 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1074.001|Local Data Staging|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used RDP for lateral movement.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has accessed and exported passwords from password managers.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1555.005|Password Managers|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used PowerView to enumerate all Windows Server, Windows Server 2003, and Windows 7 instances in the Active Directory database.(Citation: Symantec WastedLocker June 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has created local system accounts and has added the accounts to privileged groups.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, Containers|T1136.001|Local Account|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has encrypted domain-controlled systems using [BitPaymer](https://attack.mitre.org/software/S0570).(Citation: Crowdstrike Indrik November 2018) Additionally, [Indrik Spider](https://attack.mitre.org/groups/G0119) used [PsExec](https://attack.mitre.org/software/S0029) to execute a ransomware script.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1486|Data Encrypted for Impact|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has created email accounts to communicate with their ransomware victims, to include providing payment and decryption details.(Citation: Crowdstrike Indrik November 2018)
|['enterprise-attack']|enterprise-attack|PRE|T1585.002|Email Accounts|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used malicious JavaScript files for several components of their attack.(Citation: Symantec WastedLocker June 2020)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.007|JavaScript|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used valid accounts for initial access and lateral movement.(Citation: Mandiant_UNC2165) [Indrik Spider](https://attack.mitre.org/groups/G0119) has also maintained access to the victim environment through the VPN infrastructure.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used batch scripts on victim's machines.(Citation: Crowdstrike Indrik November 2018)(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used WMIC to execute commands on remote computers.(Citation: Symantec WastedLocker June 2020) 
|['enterprise-attack']|enterprise-attack|Windows|T1047|Windows Management Instrumentation|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used Group Policy Objects to deploy batch scripts.(Citation: Crowdstrike Indrik November 2018)(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Windows|T1484.001|Group Policy Modification|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has attempted to get users to click on a malicious zipped file.(Citation: Symantec WastedLocker June 2020) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used a service account to extract copies of the `Security` Registry hive.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Windows|T1012|Query Registry|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has conducted Kerberoasting attacks using a module from GitHub.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Windows|T1558.003|Kerberoasting|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used SSH for lateral movement.(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Linux, macOS|T1021.004|SSH|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has served fake updates via legitimate websites that have been compromised.(Citation: Crowdstrike Indrik November 2018)	
|['enterprise-attack']|enterprise-attack|PRE|T1584.004|Server|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has used [PsExec](https://attack.mitre.org/software/S0029) to stop services prior to the execution of ransomware.(Citation: Symantec WastedLocker June 2020)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1489|Service Stop|


[Indrik Spider](https://attack.mitre.org/groups/G0119) has downloaded additional scripts, malware, and tools onto a compromised host.(Citation: Crowdstrike Indrik November 2018)(Citation: Symantec WastedLocker June 2020)(Citation: Mandiant_UNC2165)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|

