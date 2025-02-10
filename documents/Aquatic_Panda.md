# Aquatic Panda - G0143

**Created**: 2022-01-18T14:49:29.505Z

**Modified**: 2024-10-10T14:31:59.099Z

**Contributors**: NST Assure Research Team, NetSentries Technologies,Pooja Natarajan, NEC Corporation India,Hiroki Nagahama, NEC Corporation,Manikantan Srinivasan, NEC Corporation India,Jai Minton, CrowdStrike,Jennifer Kim Roman, CrowdStrike

## Aliases

Aquatic Panda

## Description

[Aquatic Panda](https://attack.mitre.org/groups/G0143) is a suspected China-based threat group with a dual mission of intelligence collection and industrial espionage. Active since at least May 2020, [Aquatic Panda](https://attack.mitre.org/groups/G0143) has primarily targeted entities in the telecommunications, technology, and government sectors.(Citation: CrowdStrike AQUATIC PANDA December 2021)

## Techniques Used


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has encoded PowerShell commands in Base64.(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.010|Command Obfuscation|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) created new, malicious services using names such as <code>Windows User Service</code> to attempt to blend in with legitimate items on victim systems.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1036.004|Masquerade Task or Service|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) used remote shares to enable lateral movement in victim environments.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1021.002|SMB/Windows Admin Shares|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) modified the <code>ld.so</code> preload file in Linux environments to enable persistence for Winnti malware.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS|T1574.006|Dynamic Linker Hijacking|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) cleared command history in Linux environments to remove traces of activity after operations.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1070.003|Clear Command History|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) used malicious shell scripts in Linux environments following access via SSH to install Linux versions of Winnti malware.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|macOS, Linux, Network|T1059.004|Unix Shell|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has deleted malicious executables from compromised machines.(Citation: CrowdStrike AQUATIC PANDA December 2021)(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) used the <code>last</code> command in Linux environments to identify recently logged-in users on victim machines.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Office Suite, Identity Provider|T1087|Account Discovery|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) created new Windows services for persistence that masqueraded as legitimate Windows services via name change.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1543.003|Windows Service|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) used a registry edit to enable a Windows feature called <code>RestrictedAdmin</code> in victim environments. This change allowed [Aquatic Panda](https://attack.mitre.org/groups/G0143) to leverage "pass the hash" mechanisms as the alteration allows for RDP connections with a valid account name and hash only, without possessing a cleartext password value.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1550.002|Pass the Hash|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has used DLL search-order hijacking to load `exe`, `dll`, and `dat` files into memory.(Citation: CrowdStrike AQUATIC PANDA December 2021) [Aquatic Panda](https://attack.mitre.org/groups/G0143) loaded a malicious DLL into the legitimate Windows Security Health Service executable (<code>SecurityHealthService.exe</code>) to execute malicious code on victim systems.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1574.001|DLL Search Order Hijacking|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) enumerated logs related to authentication in Linux environments prior to deleting selective entries for defense evasion purposes.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1654|Log Enumeration|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) used SSH with captured user credentials to move laterally in victim environments.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS|T1021.004|SSH|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has attempted to discover services for third party EDR products.(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1007|System Service Discovery|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) renamed or moved malicious binaries to legitimate locations to evade defenses and blend into victim environments.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has acquired and used [njRAT](https://attack.mitre.org/software/S0385) in its operations.(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1588.001|Malware|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has attempted to discover third party endpoint detection and response (EDR) tools on compromised systems.(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1518.001|Security Software Discovery|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) modified the victim registry to enable the `RestrictedAdmin` mode feature, allowing for pass the hash behaviors to function via RDP.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1112|Modify Registry|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has downloaded additional malware onto compromised hosts.(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) clears Windows Event Logs following activity to evade defenses.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1070.001|Clear Windows Event Logs|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) leveraged stolen credentials to move laterally via RDP in victim environments.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) captured local Windows security event log data from victim machines using the <code>wevtutil</code> utility to extract contents to an <code>evtx</code> output file.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has used publicly accessible DNS logging services to identify servers vulnerable to Log4j (CVE 2021-44228).(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1595.002|Vulnerability Scanning|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has attempted to harvest credentials through LSASS memory dumping.(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has attempted and failed to run Bash commands on a Windows host by passing them to <code>cmd /C</code>.(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has acquired and used [Cobalt Strike](https://attack.mitre.org/software/S0154) in its operations.(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has attempted to stop endpoint detection and response (EDR) tools on compromised systems.(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) gathers information on recently logged-in users on victim devices.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) used WMI for lateral movement in victim environments.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1047|Windows Management Instrumentation|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has downloaded additional scripts and executed Base64 encoded commands in PowerShell.(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has used native OS commands to understand privilege levels and system details.(Citation: CrowdStrike AQUATIC PANDA December 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) used remote scheduled tasks to install malicious software on victim systems during lateral movement actions.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1021|Remote Services|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) used rundll32.exe to proxy execution of a malicious DLL file identified as a keylogging binary.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1218.011|Rundll32|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) used multiple mechanisms to capture valid user accounts for victim domains to enable lateral movement and access to additional hosts in victim environments.(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1078.002|Domain Accounts|


[Aquatic Panda](https://attack.mitre.org/groups/G0143) has used several publicly available tools, including WinRAR and 7zip, to compress collected files and memory dumps prior to exfiltration.(Citation: CrowdStrike AQUATIC PANDA December 2021)(Citation: Crowdstrike HuntReport 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|

