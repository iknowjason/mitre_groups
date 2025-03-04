# Fox Kitten - G0117

**Created**: 2020-12-21T21:49:47.307Z

**Modified**: 2024-01-08T22:00:34.410Z

**Contributors**: 

## Aliases

Fox Kitten,UNC757,Parisite,Pioneer Kitten,RUBIDIUM,Lemon Sandstorm

## Description

[Fox Kitten](https://attack.mitre.org/groups/G0117) is threat actor with a suspected nexus to the Iranian government that has been active since at least 2017 against entities in the Middle East, North Africa, Europe, Australia, and North America. [Fox Kitten](https://attack.mitre.org/groups/G0117) has targeted multiple industrial verticals including oil and gas, technology, government, defense, healthcare, manufacturing, and engineering.(Citation: ClearkSky Fox Kitten February 2020)(Citation: CrowdStrike PIONEER KITTEN August 2020)(Citation: Dragos PARISITE )(Citation: ClearSky Pay2Kitten December 2020)

## Techniques Used


[Fox Kitten](https://attack.mitre.org/groups/G0117) has downloaded additional tools including [PsExec](https://attack.mitre.org/software/S0029) directly to endpoints.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used a Perl reverse shell to communicate with C2.(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, IaaS, Office Suite, Identity Provider|T1059|Command and Scripting Interpreter|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used Angry IP Scanner to detect remote systems.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has obtained files from the victim's cloud storage instances.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|IaaS, SaaS, Office Suite|T1530|Data from Cloud Storage|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has brute forced RDP credentials.(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110|Brute Force|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has base64 encoded scripts to avoid detection.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.010|Command Obfuscation|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used 7-Zip to archive data.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has searched local system resources to access sensitive documents.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has created KeyBase accounts to communicate with ransomware victims.(Citation: ClearSky Pay2Kitten December 2020)(Citation: Check Point Pay2Key November 2020)
|['enterprise-attack']|enterprise-attack|PRE|T1585|Establish Accounts|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has exploited known vulnerabilities in remote services including RDP.(Citation: ClearkSky Fox Kitten February 2020)(Citation: CrowdStrike PIONEER KITTEN August 2020)(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1210|Exploitation of Remote Services|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has created a local user account with administrator privileges.(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, Containers|T1136.001|Local Account|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has installed TightVNC server and client on compromised servers and endpoints for lateral movement.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1021.005|VNC|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used scripts to access credential information from the KeePass database.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1555.005|Password Managers|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used Volume Shadow Copy to access credential information from NTDS.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1003.003|NTDS|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has exploited known vulnerabilities in Fortinet, PulseSecure, and Palo Alto VPN appliances.(Citation: ClearkSky Fox Kitten February 2020)(Citation: Dragos PARISITE )(Citation: CrowdStrike PIONEER KITTEN August 2020)(Citation: CISA AA20-259A Iran-Based Actor September 2020)(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used cmd.exe likely as a password changing mechanism.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used Google Chrome bookmarks to identify internal resources and assets.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1217|Browser Information Discovery|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has accessed files to gain valid credentials.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers|T1552.001|Credentials In Files|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has accessed victim security and IT environments and Microsoft Teams to mine valuable information.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|SaaS, Office Suite|T1213.005|Messaging Applications|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has base64 encoded payloads to avoid detection.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.013|Encrypted/Encoded File|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used valid accounts to access SMB shares.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1021.002|SMB/Windows Admin Shares|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used the open source reverse proxy tools including FRPC and Go Proxy to establish connections from C2 to local servers.(Citation: CISA AA20-259A Iran-Based Actor September 2020)(Citation: ClearSky Pay2Kitten December 2020)(Citation: Check Point Pay2Key November 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090|Proxy|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used protocol tunneling for communication and RDP activity on compromised hosts through the use of open source tools such as [ngrok](https://attack.mitre.org/software/S0508) and custom tool SSHMinion.(Citation: CrowdStrike PIONEER KITTEN August 2020)(Citation: CISA AA20-259A Iran-Based Actor September 2020)(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1572|Protocol Tunneling|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has accessed Registry hives ntuser.dat and UserClass.dat.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1012|Query Registry|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used the PuTTY and Plink tools for lateral movement.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS|T1021.004|SSH|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used the Softerra LDAP browser to browse documentation on service accounts.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has accessed ntuser.dat and UserClass.dat on compromised hosts.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.001|Local Account|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has named the task for a reverse proxy lpupdate to appear legitimate.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1036.004|Masquerade Task or Service|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used prodump to dump credentials from LSASS.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has installed web shells on compromised hosts to maintain access.(Citation: CISA AA20-259A Iran-Based Actor September 2020)(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used Scheduled Tasks for persistence and to load and execute a reverse proxy binary.(Citation: CISA AA20-259A Iran-Based Actor September 2020)(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used PowerShell scripts to access credential data.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used WizTree to obtain network files and directory listings.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used a Twitter account to communicate with ransomware victims.(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|PRE|T1585.001|Social Media Accounts|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has named binaries and configuration files svhost and dllhost respectively to appear legitimate.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used RDP to log in and move laterally in the target environment.(Citation: CISA AA20-259A Iran-Based Actor September 2020)(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used tools including NMAP to conduct broad scanning to identify open ports.(Citation: CISA AA20-259A Iran-Based Actor September 2020)(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers, Network|T1046|Network Service Discovery|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used sticky keys to launch a command prompt.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1546.008|Accessibility Features|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used Amazon Web Services to host C2.(Citation: ClearSky Pay2Kitten December 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1102|Web Service|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has searched network shares to access sensitive documents.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1039|Data from Network Shared Drive|


[Fox Kitten](https://attack.mitre.org/groups/G0117) has used valid credentials with various services during lateral movement.(Citation: CISA AA20-259A Iran-Based Actor September 2020)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|

