# OilRig - G0049

**Created**: 2017-12-14T16:46:06.044Z

**Modified**: 2024-09-04T20:33:04.739Z

**Contributors**: Robert Falcone,Bryan Lee,Dragos Threat Intelligence

## Aliases

OilRig,COBALT GYPSY,IRN2,APT34,Helix Kitten,Evasive Serpens,Hazel Sandstorm,EUROPIUM,ITG13

## Description

[OilRig](https://attack.mitre.org/groups/G0049) is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of sectors, including financial, government, energy, chemical, and telecommunications. It appears the group carries out supply chain attacks, leveraging the trust relationship between organizations to attack their primary targets. The group works on behalf of the Iranian government based on infrastructure details that contain references to Iran, use of Iranian infrastructure, and targeting that aligns with nation-state interests.(Citation: FireEye APT34 Dec 2017)(Citation: Palo Alto OilRig April 2017)(Citation: ClearSky OilRig Jan 2017)(Citation: Palo Alto OilRig May 2016)(Citation: Palo Alto OilRig Oct 2016)(Citation: Unit42 OilRig Playbook 2023)(Citation: Unit 42 QUADAGENT July 2018)

## Techniques Used


[OilRig](https://attack.mitre.org/groups/G0049) malware ISMAgent falls back to its DNS tunneling mechanism if it is unable to reach the C2 server over HTTP.(Citation: OilRig ISMAgent July 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS|T1008|Fallback Channels|


[OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [Mimikatz](https://attack.mitre.org/software/S0002) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1003.001|LSASS Memory|


[OilRig](https://attack.mitre.org/groups/G0049) has used HTTP for C2.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT34 July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tool named VALUEVAULT to steal credentials from the Windows Credential Manager.(Citation: FireEye APT34 July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1555.004|Windows Credential Manager|


[OilRig](https://attack.mitre.org/groups/G0049) has run <code>hostname</code> and <code>systeminfo</code> on a victim.(Citation: Palo Alto OilRig May 2016)(Citation: Palo Alto OilRig Oct 2016)(Citation: FireEye APT34 July 2019)(Citation: Check Point APT34 April 2021)	
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[OilRig](https://attack.mitre.org/groups/G0049) has used web shells, often to maintain access to a victim network.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: Crowdstrike GTR2020 Mar 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[OilRig](https://attack.mitre.org/groups/G0049) has used a CHM payload to load and execute another malicious file once delivered to a victim.(Citation: Palo Alto OilRig May 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1218.001|Compiled HTML File|


[OilRig](https://attack.mitre.org/groups/G0049) has used .doc file extensions to mask malicious executables.(Citation: Check Point APT34 April 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Containers|T1036|Masquerading|


[OilRig](https://attack.mitre.org/groups/G0049) has used Remote Desktop Protocol for lateral movement. The group has also used tunneling tools to tunnel RDP into the environment.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: Crowdstrike GTR2020 Mar 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1021.001|Remote Desktop Protocol|


[OilRig](https://attack.mitre.org/groups/G0049) has used macros to deliver malware such as [QUADAGENT](https://attack.mitre.org/software/S0269) and [OopsIE](https://attack.mitre.org/software/S0264).(Citation: FireEye APT34 Dec 2017)(Citation: OilRig ISMAgent July 2017)(Citation: Unit 42 OopsIE! Feb 2018)(Citation: Unit 42 QUADAGENT July 2018)(Citation: Unit42 OilRig Nov 2018) [OilRig](https://attack.mitre.org/groups/G0049) has used batch scripts.(Citation: FireEye APT34 Dec 2017)(Citation: OilRig ISMAgent July 2017)(Citation: Unit 42 OopsIE! Feb 2018)(Citation: Unit 42 QUADAGENT July 2018)(Citation: Unit42 OilRig Nov 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1059.003|Windows Command Shell|


[OilRig](https://attack.mitre.org/groups/G0049) has used <code>net group /domain</code>, <code>net group “domain admins” /domain</code>, and <code>net group “Exchange Trusted Subsystem” /domain</code> to find domain group permission settings.(Citation: Palo Alto OilRig May 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1069.002|Domain Groups|


[OilRig](https://attack.mitre.org/groups/G0049) has a tool called CANDYKING to capture a screenshot of user's desktop.(Citation: FireEye APT34 Webinar Dec 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1113|Screen Capture|


[OilRig](https://attack.mitre.org/groups/G0049) has used the publicly available tool SoftPerfect Network Scanner as well as a custom tool called GOLDIRONY to conduct network scanning.(Citation: FireEye APT34 Webinar Dec 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Linux, macOS, Containers, Network|T1046|Network Service Discovery|


[OilRig](https://attack.mitre.org/groups/G0049) has abused the Outlook Home Page feature for persistence. [OilRig](https://attack.mitre.org/groups/G0049) has also used CVE-2017-11774 to roll back the initial patch designed to protect against Home Page abuse.(Citation: FireEye Outlook Dec 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Office Suite|T1137.004|Outlook Home Page|


[OilRig](https://attack.mitre.org/groups/G0049) has run <code>net user</code>, <code>net user /domain</code>, <code>net group “domain admins” /domain</code>, and <code>net group “Exchange Trusted Subsystem” /domain</code> to get account listings on a victim.(Citation: Palo Alto OilRig May 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1087.001|Local Account|


[OilRig](https://attack.mitre.org/groups/G0049) has exfiltrated data over FTP separately from its primary C2 channel over DNS.(Citation: Palo Alto OilRig Oct 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1048.003|Exfiltration Over Unencrypted Non-C2 Protocol|


A [OilRig](https://attack.mitre.org/groups/G0049) macro has run a PowerShell command to decode file contents. [OilRig](https://attack.mitre.org/groups/G0049) has also used [certutil](https://attack.mitre.org/software/S0160) to decode base64-encoded files on victims.(Citation: FireEye APT34 Dec 2017)(Citation: OilRig New Delivery Oct 2017)(Citation: Unit 42 OopsIE! Feb 2018)(Citation: Crowdstrike GTR2020 Mar 2020)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[OilRig](https://attack.mitre.org/groups/G0049) has used VBScript macros for execution on compromised hosts.(Citation: Check Point APT34 April 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[OilRig](https://attack.mitre.org/groups/G0049) has used brute force techniques to obtain credentials.(Citation: FireEye APT34 Webinar Dec 2017)(Citation: IBM ZeroCleare Wiper December 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110|Brute Force|


[OilRig](https://attack.mitre.org/groups/G0049) has sent spearphising emails with malicious links to potential victims.(Citation: Unit 42 OopsIE! Feb 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[OilRig](https://attack.mitre.org/groups/G0049) has deleted files associated with their payload after execution.(Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 OopsIE! Feb 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[OilRig](https://attack.mitre.org/groups/G0049) has used PowerShell scripts for execution, including use of a macro to run a PowerShell command to decode file contents.(Citation: FireEye APT34 Dec 2017)(Citation: OilRig New Delivery Oct 2017)(Citation: Crowdstrike Helix Kitten Nov 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1059.001|PowerShell|


[OilRig](https://attack.mitre.org/groups/G0049) has delivered macro-enabled documents that required targets to click the "enable content" button to execute the payload on the system.(Citation: Unit 42 OopsIE! Feb 2018)(Citation: Unit 42 QUADAGENT July 2018)(Citation: Crowdstrike Helix Kitten Nov 2018)(Citation: Check Point APT34 April 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[OilRig](https://attack.mitre.org/groups/G0049) uses remote services such as VPN, Citrix, or OWA to persist in an environment.(Citation: FireEye APT34 Webinar Dec 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[OilRig](https://attack.mitre.org/groups/G0049) has used <code>sc query</code> on a victim to gather information about services.(Citation: Palo Alto OilRig May 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux|T1007|System Service Discovery|


[OilRig](https://attack.mitre.org/groups/G0049) has run <code>net user</code>, <code>net user /domain</code>, <code>net group “domain admins” /domain</code>, and <code>net group “Exchange Trusted Subsystem” /domain</code> to get account listings on a victim.(Citation: Palo Alto OilRig May 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [LaZagne](https://attack.mitre.org/software/S0349) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1003.004|LSA Secrets|


[OilRig](https://attack.mitre.org/groups/G0049) has used net.exe in a script with <code>net accounts /domain</code> to find the password policy of a domain.(Citation: FireEye Targeted Attacks Middle East Banks)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux, macOS, IaaS, Network, Identity Provider, SaaS, Office Suite|T1201|Password Policy Discovery|


[OilRig](https://attack.mitre.org/groups/G0049) has run <code>whoami</code> on a victim.(Citation: Palo Alto OilRig May 2016)(Citation: Palo Alto OilRig Oct 2016)(Citation: Check Point APT34 April 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[OilRig](https://attack.mitre.org/groups/G0049) has used LinkedIn to send spearphishing links.(Citation: FireEye APT34 July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1566.003|Spearphishing via Service|


[OilRig](https://attack.mitre.org/groups/G0049) has used keylogging tools called KEYPUNCH and LONGWATCH.(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT34 July 2019)	

|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux, Network|T1056.001|Keylogging|


[OilRig](https://attack.mitre.org/groups/G0049) has used Putty to access compromised systems.(Citation: Unit42 OilRig Playbook 2023)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS|T1021.004|SSH|


[OilRig](https://attack.mitre.org/groups/G0049) has used WMI for execution.(Citation: FireEye APT34 Webinar Dec 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1047|Windows Management Instrumentation|


[OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [LaZagne](https://attack.mitre.org/software/S0349) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, IaaS|T1555|Credentials from Password Stores|


[OilRig](https://attack.mitre.org/groups/G0049) has used the Plink utility and other tools to create tunnels to C2 servers.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT34 July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1572|Protocol Tunneling|


[OilRig](https://attack.mitre.org/groups/G0049) has used DNS for C2 including the publicly available <code>requestbin.net</code> tunneling service.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT34 July 2019)(Citation: Check Point APT34 April 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1071.004|DNS|


[OilRig](https://attack.mitre.org/groups/G0049) has used tools to identify if a mouse is connected to a targeted system.(Citation: Check Point APT34 April 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, macOS, Linux|T1120|Peripheral Device Discovery|


[OilRig](https://attack.mitre.org/groups/G0049) has used <code>netstat -an</code> on a victim to get a listing of network connections.(Citation: Palo Alto OilRig May 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Linux, macOS, Network|T1049|System Network Connections Discovery|


[OilRig](https://attack.mitre.org/groups/G0049) can download remote files onto victims.(Citation: FireEye APT34 Dec 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[OilRig](https://attack.mitre.org/groups/G0049) has sent spearphising emails with malicious attachments to potential victims using compromised and/or spoofed email accounts.(Citation: Unit 42 OopsIE! Feb 2018)(Citation: Unit 42 QUADAGENT July 2018)(Citation: Crowdstrike Helix Kitten Nov 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[OilRig](https://attack.mitre.org/groups/G0049) has created scheduled tasks that run a VBScript to execute a payload on victim machines.(Citation: Unit 42 OopsIE! Feb 2018)(Citation: Unit 42 QUADAGENT July 2018)(Citation: FireEye APT34 July 2019)(Citation: Check Point APT34 April 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1053.005|Scheduled Task|


[OilRig](https://attack.mitre.org/groups/G0049) has used automated collection.(Citation: Unit42 OilRig Playbook 2023)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, IaaS, SaaS, Office Suite|T1119|Automated Collection|


[OilRig](https://attack.mitre.org/groups/G0049) has used compromised credentials to access other systems on a victim network.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: IBM ZeroCleare Wiper December 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[OilRig](https://attack.mitre.org/groups/G0049) has delivered malicious links to achieve execution on the target system.(Citation: Unit 42 OopsIE! Feb 2018)(Citation: Unit 42 QUADAGENT July 2018)(Citation: Crowdstrike Helix Kitten Nov 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[OilRig](https://attack.mitre.org/groups/G0049) used the Plink utility and other tools to create tunnels to C2 servers.(Citation: FireEye APT34 Webinar Dec 2017)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1573.002|Asymmetric Cryptography|


[OilRig](https://attack.mitre.org/groups/G0049) has used macros to verify if a mouse is connected to a compromised machine.(Citation: Check Point APT34 April 2021)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1497.001|System Checks|


[OilRig](https://attack.mitre.org/groups/G0049) has used various types of scripting for execution.(Citation: FireEye APT34 Dec 2017)(Citation: OilRig ISMAgent July 2017)(Citation: Unit 42 OopsIE! Feb 2018)(Citation: Unit 42 QUADAGENT July 2018)(Citation: Unit42 OilRig Nov 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network, IaaS, Office Suite, Identity Provider|T1059|Command and Scripting Interpreter|


[OilRig](https://attack.mitre.org/groups/G0049) has tested malware samples to determine AV detection and subsequently modified the samples to ensure AV evasion.(Citation: Palo Alto OilRig April 2017)(Citation: Unit42 OilRig Nov 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1027.005|Indicator Removal from Tools|


[OilRig](https://attack.mitre.org/groups/G0049) has encrypted and encoded data in its malware, including by using base64.(Citation: FireEye APT34 Dec 2017)(Citation: Unit 42 QUADAGENT July 2018)(Citation: Unit42 OilRig Playbook 2023)(Citation: Crowdstrike Helix Kitten Nov 2018)(Citation: Unit42 OilRig Nov 2018)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1027.013|Encrypted/Encoded File|


[OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [LaZagne](https://attack.mitre.org/software/S0349) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, Linux|T1003.005|Cached Domain Credentials|


[OilRig](https://attack.mitre.org/groups/G0049) has used <code>reg query “HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default”</code> on a victim to query the Registry.(Citation: Palo Alto OilRig May 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows|T1012|Query Registry|


[OilRig](https://attack.mitre.org/groups/G0049) has run <code>ipconfig /all</code> on a victim.(Citation: Palo Alto OilRig May 2016)(Citation: Palo Alto OilRig Oct 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1016|System Network Configuration Discovery|


[OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [LaZagne](https://attack.mitre.org/software/S0349) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Windows, IaaS, Linux, macOS, Containers|T1552.001|Credentials In Files|


[OilRig](https://attack.mitre.org/groups/G0049) has used <code>net localgroup administrators</code> to find local administrators on compromised systems.(Citation: Palo Alto OilRig May 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1069.001|Local Groups|


[OilRig](https://attack.mitre.org/groups/G0049) has used credential dumping tools such as [LaZagne](https://attack.mitre.org/software/S0349) to steal credentials to accounts logged into the compromised system and to Outlook Web Access.(Citation: Unit42 OilRig Playbook 2023)(Citation: FireEye APT34 Webinar Dec 2017)(Citation: FireEye APT35 2018)(Citation: FireEye APT34 July 2019) [OilRig](https://attack.mitre.org/groups/G0049) has also used tool named PICKPOCKET to dump passwords from web browsers.(Citation: FireEye APT34 July 2019)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows|T1555.003|Credentials from Web Browsers|


[OilRig](https://attack.mitre.org/groups/G0049) has run <code>tasklist</code> on a victim's machine.(Citation: Palo Alto OilRig May 2016)
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network|T1057|Process Discovery|


[OilRig](https://attack.mitre.org/groups/G0049) has used the command-line interface for execution.
|['enterprise-attack']|enterprise-attack, ics-attack|Linux, macOS, Windows, Network, IaaS, Office Suite, Identity Provider|T1059|Command and Scripting Interpreter|


[OilRig](https://attack.mitre.org/groups/G0049) has embedded a macro within spearphishing attachments that has been made up of both a VBScript and a PowerShell script.(Citation: Robert Falcone, Bryan Lee May 2016)
|['ics-attack']|enterprise-attack, ics-attack|None|T0853|Scripting|


[OilRig](https://attack.mitre.org/groups/G0049) has been seen utilizing watering hole attacks to collect credentials which could be used to gain access into ICS networks. (Citation: Eduard Kovacs May 2018)
|['ics-attack']|enterprise-attack, ics-attack|None|T0817|Drive-by Compromise|


[OilRig](https://attack.mitre.org/groups/G0049) utilized stolen credentials to gain access to victim machines.(Citation: Dragos)
|['ics-attack']|enterprise-attack, ics-attack|None|T0859|Valid Accounts|


[OilRig](https://attack.mitre.org/groups/G0049) communicated with its command and control using HTTP requests. (Citation: Robert Falcone, Bryan Lee May 2016)
|['ics-attack']|enterprise-attack, ics-attack|None|T0869|Standard Application Layer Protocol|


[OilRig](https://attack.mitre.org/groups/G0049) used spearphishing emails with malicious Microsoft Excel spreadsheet attachments. (Citation: Robert Falcone, Bryan Lee May 2016)
|['ics-attack']|enterprise-attack, ics-attack|None|T0865|Spearphishing Attachment|

