# Leviathan - G0065

**Created**: 2018-04-18T17:59:24.739Z

**Modified**: 2024-01-08T20:33:16.460Z

**Contributors**: Valerii Marchuk, Cybersecurity Help s.r.o.

## Aliases

Leviathan,MUDCARP,Kryptonite Panda,Gadolinium,BRONZE MOHAWK,TEMP.Jumper,APT40,TEMP.Periscope,Gingham Typhoon

## Description

[Leviathan](https://attack.mitre.org/groups/G0065) is a Chinese state-sponsored cyber espionage group that has been attributed to the Ministry of State Security's (MSS) Hainan State Security Department and an affiliated front company.(Citation: CISA AA21-200A APT40 July 2021) Active since at least 2009, [Leviathan](https://attack.mitre.org/groups/G0065) has targeted the following sectors: academia, aerospace/aviation, biomedical, defense industrial base, government, healthcare, manufacturing, maritime, and transportation across the US, Canada, Europe, the Middle East, and Southeast Asia.(Citation: CISA AA21-200A APT40 July 2021)(Citation: Proofpoint Leviathan Oct 2017)(Citation: FireEye Periscope March 2018)

## Techniques Used


[Leviathan](https://attack.mitre.org/groups/G0065) has used an uploader known as LUNCHMONEY that can exfiltrate files to Dropbox.(Citation: Proofpoint Leviathan Oct 2017)(Citation: FireEye Periscope March 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1567.002|Exfiltration to Cloud Storage|


[Leviathan](https://attack.mitre.org/groups/G0065) has obfuscated code using base64 and gzip compression.(Citation: Proofpoint Leviathan Oct 2017)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.013|Encrypted/Encoded File|


[Leviathan](https://attack.mitre.org/groups/G0065) has collected compromised credentials to use for targeting efforts.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1589.001|Credentials|


[Leviathan](https://attack.mitre.org/groups/G0065) has used JavaScript to create a shortcut file in the Startup folder that points to its main backdoor.(Citation: Proofpoint Leviathan Oct 2017)(Citation: FireEye Periscope March 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[Leviathan](https://attack.mitre.org/groups/G0065) has compromised social media accounts to conduct social engineering attacks.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1586.001|Social Media Accounts|


[Leviathan](https://attack.mitre.org/groups/G0065) has used publicly available tools to dump password hashes, including ProcDump and WCE.(Citation: FireEye APT40 March 2019)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[Leviathan](https://attack.mitre.org/groups/G0065) has received C2 instructions from user profiles created on legitimate websites such as Github and TechNet.(Citation: FireEye Periscope March 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1102.003|One-Way Communication|


[Leviathan](https://attack.mitre.org/groups/G0065) used ssh for internal reconnaissance.(Citation: FireEye APT40 March 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS|T1021.004|SSH|


[Leviathan](https://attack.mitre.org/groups/G0065) has downloaded additional scripts and files from adversary-controlled servers.(Citation: Proofpoint Leviathan Oct 2017)(Citation: FireEye Periscope March 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Leviathan](https://attack.mitre.org/groups/G0065) has used WMI for execution.(Citation: Proofpoint Leviathan Oct 2017)
|['enterprise-attack']|enterprise-attack|Windows|T1047|Windows Management Instrumentation|


[Leviathan](https://attack.mitre.org/groups/G0065) has inserted garbage characters into code, presumably to avoid anti-virus detection.(Citation: Proofpoint Leviathan Oct 2017)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.001|Binary Padding|


[Leviathan](https://attack.mitre.org/groups/G0065) has used multi-hop proxies to disguise the source of their malicious traffic.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090.003|Multi-hop Proxy|


[Leviathan](https://attack.mitre.org/groups/G0065) has used PowerShell for execution.(Citation: Proofpoint Leviathan Oct 2017)(Citation: FireEye Periscope March 2018)(Citation: CISA AA21-200A APT40 July 2021)(Citation: Accenture MUDCARP March 2019)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Leviathan](https://attack.mitre.org/groups/G0065) has used JavaScript to create a shortcut file in the Startup folder that points to its main backdoor.(Citation: Proofpoint Leviathan Oct 2017)(Citation: FireEye Periscope March 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1547.009|Shortcut Modification|


[Leviathan](https://attack.mitre.org/groups/G0065) has infected victims using watering holes.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, Identity Provider|T1189|Drive-by Compromise|


[Leviathan](https://attack.mitre.org/groups/G0065) has used steganography to hide stolen data inside other files stored on Github.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.003|Steganography|


[Leviathan](https://attack.mitre.org/groups/G0065) has created new social media accounts for targeting efforts.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1585.001|Social Media Accounts|


[Leviathan](https://attack.mitre.org/groups/G0065) has used WMI for persistence.(Citation: FireEye Periscope March 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1546.003|Windows Management Instrumentation Event Subscription|


[Leviathan](https://attack.mitre.org/groups/G0065) has exploited multiple Microsoft Office and .NET vulnerabilities for execution, including CVE-2017-0199, CVE-2017-8759, and CVE-2017-11882.(Citation: Proofpoint Leviathan Oct 2017)(Citation: FireEye Periscope March 2018)(Citation: CISA AA21-200A APT40 July 2021)(Citation: Accenture MUDCARP March 2019)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1203|Exploitation for Client Execution|


[Leviathan](https://attack.mitre.org/groups/G0065) has utilized techniques like reflective DLL loading to write a DLL into memory and load a shell that provides backdoor access to the victim.(Citation: Accenture MUDCARP March 2019)
|['enterprise-attack']|enterprise-attack|Windows|T1055.001|Dynamic-link Library Injection|


[Leviathan](https://attack.mitre.org/groups/G0065) has sent spearphishing emails with malicious attachments, including .rtf, .doc, and .xls files.(Citation: Proofpoint Leviathan Oct 2017)(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Leviathan](https://attack.mitre.org/groups/G0065) has established domains that impersonate legitimate entities to use for targeting efforts. (Citation: CISA AA21-200A APT40 July 2021)(Citation: Accenture MUDCARP March 2019)
|['enterprise-attack']|enterprise-attack|PRE|T1583.001|Domains|


[Leviathan](https://attack.mitre.org/groups/G0065) has sent spearphishing emails with links, often using a fraudulent lookalike domain and stolen branding.(Citation: Proofpoint Leviathan Oct 2017)(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[Leviathan](https://attack.mitre.org/groups/G0065) has created new email accounts for targeting efforts.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1585.002|Email Accounts|


[Leviathan](https://attack.mitre.org/groups/G0065) has utilized OLE as a method to insert malicious content inside various phishing documents. (Citation: Accenture MUDCARP March 2019)
|['enterprise-attack']|enterprise-attack|Windows|T1559.002|Dynamic Data Exchange|


[Leviathan](https://attack.mitre.org/groups/G0065) has used regsvr32 for execution.(Citation: Proofpoint Leviathan Oct 2017)
|['enterprise-attack']|enterprise-attack|Windows|T1218.010|Regsvr32|


[Leviathan](https://attack.mitre.org/groups/G0065) has conducted internal spearphishing within the victim's environment for lateral movement.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, SaaS, Office Suite|T1534|Internal Spearphishing|


[Leviathan](https://attack.mitre.org/groups/G0065) has used C:\Windows\Debug and C:\Perflogs as staging directories.(Citation: FireEye Periscope March 2018)(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1074.001|Local Data Staging|


[Leviathan](https://attack.mitre.org/groups/G0065) has used [BITSAdmin](https://attack.mitre.org/software/S0190) to download additional tools.(Citation: FireEye Periscope March 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1197|BITS Jobs|


[Leviathan](https://attack.mitre.org/groups/G0065) has staged data remotely prior to exfiltration.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1074.002|Remote Data Staging|


[Leviathan](https://attack.mitre.org/groups/G0065) has used a DLL known as SeDll to decrypt and execute other JavaScript backdoors.(Citation: Proofpoint Leviathan Oct 2017)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[Leviathan](https://attack.mitre.org/groups/G0065) has sent spearphishing attachments attempting to get a user to click.(Citation: Proofpoint Leviathan Oct 2017)(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Leviathan](https://attack.mitre.org/groups/G0065) has obtained valid accounts to gain initial access.(Citation: CISA AA21-200A APT40 July 2021)(Citation: Accenture MUDCARP March 2019)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[Leviathan](https://attack.mitre.org/groups/G0065) has used stolen code signing certificates to sign malware.(Citation: FireEye Periscope March 2018)(Citation: FireEye APT40 March 2019)
|['enterprise-attack']|enterprise-attack|macOS, Windows|T1553.002|Code Signing|


[Leviathan](https://attack.mitre.org/groups/G0065) has used VBScript.(Citation: Proofpoint Leviathan Oct 2017)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[Leviathan](https://attack.mitre.org/groups/G0065) has compromised email accounts to conduct social engineering attacks.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1586.002|Email Accounts|


[Leviathan](https://attack.mitre.org/groups/G0065) has used publicly available tools to dump password hashes, including [HOMEFRY](https://attack.mitre.org/software/S0232).(Citation: FireEye APT40 March 2019)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1003|OS Credential Dumping|


[Leviathan](https://attack.mitre.org/groups/G0065) has used protocol tunneling to further conceal C2 communications and infrastructure.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1572|Protocol Tunneling|


[Leviathan](https://attack.mitre.org/groups/G0065) has used external remote services such as virtual private networks (VPN) to gain initial access.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[Leviathan](https://attack.mitre.org/groups/G0065) has sent spearphishing email links attempting to get a user to click.(Citation: Proofpoint Leviathan Oct 2017)(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[Leviathan](https://attack.mitre.org/groups/G0065) has exfiltrated data over its C2 channel.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1041|Exfiltration Over C2 Channel|


[Leviathan](https://attack.mitre.org/groups/G0065) relies on web shells for an initial foothold as well as persistence into the victim's systems.(Citation: FireEye APT40 March 2019)(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[Leviathan](https://attack.mitre.org/groups/G0065) has archived victim's data prior to exfiltration.(Citation: CISA AA21-200A APT40 July 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560|Archive Collected Data|


[Leviathan](https://attack.mitre.org/groups/G0065) has targeted RDP credentials and used it to move through the victim environment.(Citation: FireEye APT40 March 2019) 
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[Leviathan](https://attack.mitre.org/groups/G0065) has used valid, compromised email accounts for defense evasion, including to send malicious emails to other victim organizations.(Citation: Proofpoint Leviathan Oct 2017)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[Leviathan](https://attack.mitre.org/groups/G0065) uses a backdoor known as BADFLICK that is is capable of generating a reverse shell, and has used multiple types of scripting for execution, including JavaScript and JavaScript Scriptlets in XML.(Citation: Proofpoint Leviathan Oct 2017).(Citation: FireEye Periscope March 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|

