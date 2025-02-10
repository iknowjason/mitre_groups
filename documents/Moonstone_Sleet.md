# Moonstone Sleet - G1036

**Created**: 2024-08-26T17:39:06.020Z

**Modified**: 2024-10-01T11:51:31.065Z

**Contributors**: Aung Kyaw Min Naing, @Nolan

## Aliases

Moonstone Sleet,Storm-1789

## Description

[Moonstone Sleet](https://attack.mitre.org/groups/G1036) is a North Korean-linked threat actor executing both financially motivated attacks and espionage operations. The group previously overlapped significantly with another North Korean-linked entity, [Lazarus Group](https://attack.mitre.org/groups/G0032), but has differentiated its tradecraft since 2023. [Moonstone Sleet](https://attack.mitre.org/groups/G1036) is notable for creating fake companies and personas to interact with victim entities, as well as developing unique malware such as a variant delivered via a fully functioning game.(Citation: Microsoft Moonstone Sleet 2024)

## Techniques Used


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) has created email accounts to interact with victims, including for phishing purposes.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1585.002|Email Accounts|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) used curl to connect to adversary-controlled infrastructure and retrieve additional payloads.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) deployed various malware such as YouieLoader that can perform system user discovery actions.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) has developed custom malware, including a malware delivery mechanism masquerading as a legitimate game.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1587.001|Malware|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) gathered victim email address information for follow-on phishing activity.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1589.002|Email Addresses|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) delivered payloads using multiple rounds of obfuscation and encoding to evade defenses and analysis.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) has gathered information on victim organizations through email and social media interaction.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1591|Gather Victim Org Information|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) retrieved a final stage payload from command and control infrastructure during initial installation on victim systems.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) has gathered information on victim network configuration.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1016|System Network Configuration Discovery|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) delivers encrypted payloads in pieces that are then combined together to form a new portable executable (PE) file during installation.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1027|Obfuscated Files or Information|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) registered virtual private servers to host payloads for download.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1583.003|Virtual Private Server|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) delivered various payloads to victims as spearphishing attachments.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) staged malicious capabilities online for follow-on download by victims or malware.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1608.001|Upload Malware|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) used spearphishing messages containing items such as tracking pixels to determine if users interacted with malicious messages.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1598.003|Spearphishing Link|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) retrieved credentials from LSASS memory.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) used scheduled tasks for program execution during initial access to victim machines.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) relied on users interacting with malicious files, such as a trojanized PuTTY installer, for initial execution.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) used registry run keys for process execution during initial victim infection.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) deployed malware such as YouieLoader capable of capturing victim system browser information.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1217|Browser Information Discovery|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) has used social media services to spear phish victims to deliver trojainized software.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1566.003|Spearphishing via Service|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) embedded payloads in trojanized software for follow-on execution.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1027.009|Embedded Payloads|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) developed malicious npm packages for delivery to or retrieval by victims.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1587|Develop Capabilities|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) has gathered information on victim systems.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) has deployed ransomware in victim environments.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1486|Data Encrypted for Impact|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) has created social media accounts to interact with victims.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1585.001|Social Media Accounts|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) has used encrypted payloads within files for follow-on execution and defense evasion.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.013|Encrypted/Encoded File|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) used intermediate loader malware such as YouieLoader and SplitLoader that create malicious services.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1569.002|Service Execution|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) has interacted with victims to gather information via email.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1598|Phishing for Information|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) has distributed a trojanized version of PuTTY software for initial access to victims.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1195.002|Compromise Software Supply Chain|


[Moonstone Sleet](https://attack.mitre.org/groups/G1036) registered domains to develop effective personas for fake companies used in phishing activity.(Citation: Microsoft Moonstone Sleet 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1583.001|Domains|

