# Winter Vivern - G1035

**Created**: 2024-07-29T22:23:03.779Z

**Modified**: 2024-10-10T14:33:40.986Z

**Contributors**: Onur Atali

## Aliases

Winter Vivern,TA473,UAC-0114

## Description

Winter Vivern is a group linked to Russian and Belorussian interests active since at least 2020 targeting various European government and NGO entities, along with sporadic targeting of Indian and US victims. The group leverages a combination of document-based phishing activity and server-side exploitation for initial access, leveraging adversary-controlled and -created infrastructure for follow-on command and control.(Citation: DomainTools WinterVivern 2021)(Citation: SentinelOne WinterVivern 2023)(Citation: CERT-UA WinterVivern 2023)(Citation: ESET WinterVivern 2023)(Citation: Proofpoint WinterVivern 2023)

## Techniques Used


[Winter Vivern](https://attack.mitre.org/groups/G1035) used XLM 4.0 macros for initial code execution for malicious document files.(Citation: DomainTools WinterVivern 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, IaaS, Office Suite, Identity Provider|T1059|Command and Scripting Interpreter|


[Winter Vivern](https://attack.mitre.org/groups/G1035) PowerShell scripts execute `whoami` to identify the executing user.(Citation: SentinelOne WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1033|System Owner/User Discovery|


[Winter Vivern](https://attack.mitre.org/groups/G1035) registered and hosted domains to allow for creation of web pages mimicking legitimate government email logon sites to collect logon information.(Citation: SentinelOne WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1056.003|Web Portal Capture|


[Winter Vivern](https://attack.mitre.org/groups/G1035) uses HTTP and HTTPS protocols for exfiltration and command and control activity.(Citation: SentinelOne WinterVivern 2023)(Citation: CERT-UA WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[Winter Vivern](https://attack.mitre.org/groups/G1035) delivered PowerShell scripts capable of taking screenshots of victim machines.(Citation: CERT-UA WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1113|Screen Capture|


[Winter Vivern](https://attack.mitre.org/groups/G1035) has distributed malicious scripts and executables mimicking virus scanners.(Citation: SentinelOne WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1036.004|Masquerade Task or Service|


[Winter Vivern](https://attack.mitre.org/groups/G1035) leverages malicious attachments delivered via email for initial access activity.(Citation: DomainTools WinterVivern 2021)(Citation: SentinelOne WinterVivern 2023)(Citation: CERT-UA WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Winter Vivern](https://attack.mitre.org/groups/G1035) used adversary-owned and -controlled servers to host web vulnerability scanning applications.(Citation: SentinelOne WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1583.003|Virtual Private Server|


[Winter Vivern](https://attack.mitre.org/groups/G1035) delivered malicious JavaScript to exploit targets when exploiting Roundcube Webmail servers.(Citation: ESET WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.007|JavaScript|


[Winter Vivern](https://attack.mitre.org/groups/G1035) has exploited known and zero-day vulnerabilities in software usch as Roundcube Webmail servers and the "Follina" vulnerability.(Citation: ESET WinterVivern 2023)(Citation: Proofpoint WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[Winter Vivern](https://attack.mitre.org/groups/G1035) has used remotely-hosted instances of the Acunetix vulnerability scanner.(Citation: SentinelOne WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1595.002|Vulnerability Scanning|


[Winter Vivern](https://attack.mitre.org/groups/G1035) executed PowerShell scripts to create scheduled tasks to retrieve remotely-hosted payloads.(Citation: DomainTools WinterVivern 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Winter Vivern](https://attack.mitre.org/groups/G1035) executed PowerShell scripts that would subsequently attempt to establish persistence by creating scheduled tasks objects to periodically retrieve and execute remotely-hosted payloads.(Citation: DomainTools WinterVivern 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[Winter Vivern](https://attack.mitre.org/groups/G1035) has used compromised WordPress sites to host malicious payloads for download.(Citation: SentinelOne WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1584.006|Web Services|


[Winter Vivern](https://attack.mitre.org/groups/G1035) created specially-crafted documents mimicking legitimate government or similar documents during phishing campaigns.(Citation: SentinelOne WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036|Masquerading|


[Winter Vivern](https://attack.mitre.org/groups/G1035) delivered a PowerShell script capable of recursively scanning victim machines looking for various file types before exfiltrating identified files via HTTP.(Citation: CERT-UA WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1041|Exfiltration Over C2 Channel|


[Winter Vivern](https://attack.mitre.org/groups/G1035) created dedicated web pages mimicking legitimate government websites to deliver malicious fake anti-virus software.(Citation: CERT-UA WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, Identity Provider|T1189|Drive-by Compromise|


[Winter Vivern](https://attack.mitre.org/groups/G1035) delivered a PowerShell script capable of recursively scanning victim machines looking for various file types before exfiltrating identified files via HTTP.(Citation: CERT-UA WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1020|Automated Exfiltration|


[Winter Vivern](https://attack.mitre.org/groups/G1035) delivered a PowerShell script capable of recursively scanning victim machines looking for various file types before exfiltrating identified files via HTTP.(Citation: CERT-UA WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS, SaaS, Office Suite|T1119|Automated Collection|


[Winter Vivern](https://attack.mitre.org/groups/G1035) delivered exploit payloads via base64-encoded payloads in malicious email messages.(Citation: ESET WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[Winter Vivern](https://attack.mitre.org/groups/G1035) passed execution from document macros to PowerShell scripts during initial access operations.(Citation: DomainTools WinterVivern 2021) [Winter Vivern](https://attack.mitre.org/groups/G1035) used batch scripts that called PowerShell commands as part of initial access and installation operations.(Citation: CERT-UA WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Winter Vivern](https://attack.mitre.org/groups/G1035) distributed Windows batch scripts disguised as virus scanners to prompt download of malicious payloads using built-in system tools.(Citation: SentinelOne WinterVivern 2023)(Citation: CERT-UA WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Winter Vivern](https://attack.mitre.org/groups/G1035) registered domains mimicking other entities throughout various campaigns.(Citation: DomainTools WinterVivern 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1583.001|Domains|


[Winter Vivern](https://attack.mitre.org/groups/G1035) script execution includes basic victim information gathering steps which are then transmitted to command and control servers.(Citation: DomainTools WinterVivern 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Winter Vivern](https://attack.mitre.org/groups/G1035) has mimicked legitimate government-related domains to deliver malicious webpages containing links to documents or other content for user execution.(Citation: SentinelOne WinterVivern 2023)(Citation: CERT-UA WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[Winter Vivern](https://attack.mitre.org/groups/G1035) delivered malicious JavaScript payloads capable of exfiltrating email messages from exploited email servers.(Citation: ESET WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Windows|T1114.001|Local Email Collection|


[Winter Vivern](https://attack.mitre.org/groups/G1035) delivered malicious JavaScript payloads capable of listing folders and emails in exploited email servers.(Citation: ESET WinterVivern 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|

