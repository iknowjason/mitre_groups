# Kimsuky - G0094

**Created**: 2019-08-26T15:03:02.577Z

**Modified**: 2024-10-10T14:32:27.067Z

**Contributors**: Taewoo Lee, KISA,Dongwook Kim, KISA

## Aliases

Kimsuky,Black Banshee,Velvet Chollima,Emerald Sleet,THALLIUM,APT43,TA427

## Description

[Kimsuky](https://attack.mitre.org/groups/G0094) is a North Korea-based cyber espionage group that has been active since at least 2012. The group initially focused on targeting South Korean government entities, think tanks, and individuals identified as experts in various fields, and expanded its operations to include the UN and the government, education, business services, and manufacturing sectors in the United States, Japan, Russia, and Europe. [Kimsuky](https://attack.mitre.org/groups/G0094) has focused its intelligence collection activities on foreign policy and national security issues related to the Korean peninsula, nuclear policy, and sanctions. [Kimsuky](https://attack.mitre.org/groups/G0094) operations have overlapped with those of other North Korean cyber espionage actors likely as a result of ad hoc collaborations or other limited resource sharing.(Citation: EST Kimsuky April 2019)(Citation: Cybereason Kimsuky November 2020)(Citation: Malwarebytes Kimsuky June 2021)(Citation: CISA AA20-301A Kimsuky)(Citation: Mandiant APT43 March 2024)(Citation: Proofpoint TA427 April 2024)

[Kimsuky](https://attack.mitre.org/groups/G0094) was assessed to be responsible for the 2014 Korea Hydro & Nuclear Power Co. compromise; other notable campaigns include Operation STOLEN PENCIL (2018), Operation Kabar Cobra (2019), and Operation Smoke Screen (2019).(Citation: Netscout Stolen Pencil Dec 2018)(Citation: EST Kimsuky SmokeScreen April 2019)(Citation: AhnLab Kimsuky Kabar Cobra Feb 2019)

North Korean group definitions are known to have significant overlap, and some security researchers report all North Korean state-sponsored cyber activity under the name [Lazarus Group](https://attack.mitre.org/groups/G0032) instead of tracking clusters or subgroups.

## Techniques Used


[Kimsuky](https://attack.mitre.org/groups/G0094) has sent spearphishing emails containing a link to a document that contained malicious macros or took the victim to an actor-controlled domain.(Citation: EST Kimsuky April 2019)(Citation: Netscout Stolen Pencil Dec 2018)(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used a tool called GREASE to add a Windows admin account in order to allow them continued access via RDP.(Citation: Netscout Stolen Pencil Dec 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers, Network|T1078.003|Local Accounts|


[Kimsuky](https://attack.mitre.org/groups/G0094) has obtained and used tools such as Nirsoft WebBrowserPassVIew, [Mimikatz](https://attack.mitre.org/software/S0002), and [PsExec](https://attack.mitre.org/software/S0029).(Citation: Netscout Stolen Pencil Dec 2018)(Citation: Talos Kimsuky Nov 2021)(Citation: Mandiant APT43 March 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[Kimsuky](https://attack.mitre.org/groups/G0094) has developed its own unique malware such as MailFetch.py for use in operations.(Citation: KISA Operation Muzabi)(Citation: Talos Kimsuky Nov 2021)(Citation: Mandiant APT43 March 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1587.001|Malware|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used funds from stolen and laundered cryptocurrency to acquire operational infrastructure.(Citation: Mandiant APT43 March 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1583|Acquire Infrastructure|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used RDP for direct remote point-and-click access.(Citation: Netscout Stolen Pencil Dec 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[Kimsuky](https://attack.mitre.org/groups/G0094) has collected Office, PDF, and HWP documents from its victims.(Citation: Securelist Kimsuky Sept 2013)(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used the Nirsoft SniffPass network sniffer to obtain passwords sent over non-secure protocols.(Citation: CISA AA20-301A Kimsuky)(Citation: Netscout Stolen Pencil Dec 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, IaaS|T1040|Network Sniffing|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used attempted to lure victims into opening malicious e-mail attachments.(Citation: ThreatConnect Kimsuky September 2020)(Citation: VirusBulletin Kimsuky October 2019)(Citation: CISA AA20-301A Kimsuky)(Citation: Cybereason Kimsuky November 2020)(Citation: Malwarebytes Kimsuky June 2021)(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Kimsuky](https://attack.mitre.org/groups/G0094) has created email accounts for phishing operations.(Citation: KISA Operation Muzabi)(Citation: Mandiant APT43 March 2024)(Citation: Proofpoint TA427 April 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1585.002|Email Accounts|


[Kimsuky](https://attack.mitre.org/groups/G0094) has lured victims into clicking malicious links.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[Kimsuky](https://attack.mitre.org/groups/G0094) has exploited various vulnerabilities for initial access, including Microsoft Exchange vulnerability CVE-2020-0688.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[Kimsuky](https://attack.mitre.org/groups/G0094) has sent internal spearphishing emails for lateral movement after stealing victim information.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, SaaS, Office Suite|T1534|Internal Spearphishing|


[Kimsuky](https://attack.mitre.org/groups/G0094) has downloaded additional scripts, tools, and malware onto victim systems.(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used compromised and acquired infrastructure to host and deliver malware including Blogspot to host beacons, file exfiltrators, and implants.(Citation: Talos Kimsuky Nov 2021)(Citation: Mandiant APT43 March 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1608.001|Upload Malware|


[Kimsuky](https://attack.mitre.org/groups/G0094) has exfiltrated stolen files and data to actor-controlled Blogspot accounts.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1567.002|Exfiltration to Cloud Storage|


[Kimsuky](https://attack.mitre.org/groups/G0094) created and used a mailing toolkit to use in spearphishing attacks.(Citation: VirusBulletin Kimsuky October 2019)
|['enterprise-attack']|enterprise-attack|PRE|T1587|Develop Capabilities|


[Kimsuky](https://attack.mitre.org/groups/G0094) has decoded malicious VBScripts using Base64.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used Blogspot pages for C2.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1102.002|Bidirectional Communication|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used tailored spearphishing emails to gather victim information including contat lists to identify additional targets.(Citation: Mandiant APT43 March 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1598|Phishing for Information|


[Kimsuky](https://attack.mitre.org/groups/G0094) has disguised services to appear as benign software or related to operating system functions.(Citation: CISA AA20-301A Kimsuky)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1036.004|Masquerade Task or Service|


[Kimsuky](https://attack.mitre.org/groups/G0094) has signed files with the name EGIS CO,. Ltd..(Citation: ThreatConnect Kimsuky September 2020)
|['enterprise-attack']|enterprise-attack|macOS, Windows|T1553.002|Code Signing|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used Twitter to monitor potential victims and to prepare targeted phishing e-mails.(Citation: Malwarebytes Kimsuky June 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1593.001|Social Media|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used an instrumentor script to gather the names of all services running on a victim's system.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1007|System Service Discovery|


[Kimsuky](https://attack.mitre.org/groups/G0094) has stolen and laundered cryptocurrency to self-fund operations including the acquisition of infrastructure.(Citation: Mandiant APT43 March 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Office Suite|T1657|Financial Theft|


[Kimsuky](https://attack.mitre.org/groups/G0094) has created accounts with <code>net user</code>.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network, Containers|T1136.001|Local Account|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used pass the hash for authentication to remote access software used in C2.(Citation: CISA AA20-301A Kimsuky)
|['enterprise-attack']|enterprise-attack|Windows|T1550.002|Pass the Hash|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used modified versions of PHProxy to examine web traffic between the victim and the accessed website.(Citation: CISA AA20-301A Kimsuky)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Network|T1557|Adversary-in-the-Middle|


[Kimsuky](https://attack.mitre.org/groups/G0094) has compromised email accounts to send spearphishing e-mails.(Citation: VirusBulletin Kimsuky October 2019)(Citation: Malwarebytes Kimsuky June 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1586.002|Email Accounts|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used RC4 encryption before exfil.(Citation: Securelist Kimsuky Sept 2013)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.003|Archive via Custom Method|


[Kimsuky](https://attack.mitre.org/groups/G0094) has manipulated timestamps for creation or compilation dates to defeat anti-forensics.(Citation: Cybereason Kimsuky November 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.006|Timestomp|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used links in e-mail to steal account information including web beacons for target profiling.(Citation: VirusBulletin Kimsuky October 2019)(Citation: Malwarebytes Kimsuky June 2021)(Citation: KISA Operation Muzabi)(Citation: Proofpoint TA427 April 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1598.003|Spearphishing Link|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used a modified TeamViewer client as a command and control channel.(Citation: Securelist Kimsuky Sept 2013)(Citation: Crowdstrike GTR2020 Mar 2020)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1219|Remote Access Software|


[Kimsuky](https://attack.mitre.org/groups/G0094) has purchased hosting servers with virtual currency and prepaid cards.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|PRE|T1583.004|Server|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used `rundll32.exe` to execute malicious scripts and malware on a victim's network.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1218.011|Rundll32|


[Kimsuky](https://attack.mitre.org/groups/G0094) has collected victim employee name information.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|PRE|T1589.003|Employee Names|


[Kimsuky](https://attack.mitre.org/groups/G0094) has deleted the exfiltrated data on disk after transmission. [Kimsuky](https://attack.mitre.org/groups/G0094) has also used an instrumentor script to terminate browser processes running on an infected system and then delete the cookie files on disk.(Citation: Securelist Kimsuky Sept 2013)(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used Google Chrome browser extensions to infect victims and to steal passwords and cookies.(Citation: Zdnet Kimsuky Dec 2018)(Citation: Netscout Stolen Pencil Dec 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1176|Browser Extensions|


[Kimsuky](https://attack.mitre.org/groups/G0094) has run <code>reg add ‘HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList’ /v</code> to hide a newly created user.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1564.002|Hidden Users|


[Kimsuky](https://attack.mitre.org/groups/G0094) has obtained specific Registry keys and values on a compromised host.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1012|Query Registry|


[Kimsuky](https://attack.mitre.org/groups/G0094) has registered domains to spoof targeted organizations and trusted third parties including search engines, web platforms, and cryptocurrency exchanges.(Citation: ThreatConnect Kimsuky September 2020)(Citation: Zdnet Kimsuky Group September 2020)(Citation: CISA AA20-301A Kimsuky)(Citation: Cybereason Kimsuky November 2020)(Citation: Malwarebytes Kimsuky June 2021)(Citation: KISA Operation Muzabi)(Citation: Mandiant APT43 March 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1583.001|Domains|


[Kimsuky](https://attack.mitre.org/groups/G0094) has executed Windows commands by using `cmd` and running batch scripts.(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[Kimsuky](https://attack.mitre.org/groups/G0094) has created social media accounts to monitor news and security trends as well as potential targets.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|PRE|T1585.001|Social Media Accounts|


[Kimsuky](https://attack.mitre.org/groups/G0094) has collected victim organization information including but not limited to organization hierarchy, functions, press releases, and others.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|PRE|T1591|Gather Victim Org Information|


[Kimsuky](https://attack.mitre.org/groups/G0094)  has used HTTP GET and POST requests for C2.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used a proprietary tool to intercept one time passwords required for two-factor authentication.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1111|Multi-Factor Authentication Interception|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used the Invoke-Mimikatz PowerShell script to reflectively load a Mimikatz credential stealing DLL into memory.(Citation: Mandiant APT43 March 2024)
|['enterprise-attack']|enterprise-attack|macOS, Linux, Windows|T1620|Reflective Code Loading|


[Kimsuky](https://attack.mitre.org/groups/G0094) has searched for information on the target company's website.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|PRE|T1594|Search Victim-Owned Websites|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used `ipconfig/all` and web beacons sent via email to gather network configuration information.(Citation: Talos Kimsuky Nov 2021)(Citation: Proofpoint TA427 April 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1016|System Network Configuration Discovery|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used QuickZip to archive stolen files before exfiltration.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[Kimsuky](https://attack.mitre.org/groups/G0094) has packed malware with UPX.(Citation: Malwarebytes Kimsuky June 2021)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1027.002|Software Packing|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used a PowerShell-based keylogger as well as a tool called MECHANICAL to log keystrokes.(Citation: EST Kimsuky April 2019)(Citation: Securelist Kimsuky Sept 2013)(Citation: CISA AA20-301A Kimsuky)(Citation: Netscout Stolen Pencil Dec 2018)(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Network|T1056.001|Keylogging|


[Kimsuky](https://attack.mitre.org/groups/G0094) has staged collected data files under <code>C:\Program Files\Common Files\System\Ole DB\</code>.(Citation: CISA AA20-301A Kimsuky)(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1074.001|Local Data Staging|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used e-mail to send exfiltrated data to C2 servers.(Citation: CISA AA20-301A Kimsuky)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.003|Mail Protocols|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used tools that are capable of obtaining credentials from saved mail.(Citation: Netscout Stolen Pencil Dec 2018)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers|T1552.001|Credentials In Files|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used Win7Elevate to inject malicious code into explorer.exe.(Citation: Securelist Kimsuky Sept 2013)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1055|Process Injection|


[Kimsuky](https://attack.mitre.org/groups/G0094) has executed a variety of PowerShell scripts including Invoke-Mimikatz.(Citation: EST Kimsuky April 2019)(Citation: CISA AA20-301A Kimsuky)(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)(Citation: Mandiant APT43 March 2024)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[Kimsuky](https://attack.mitre.org/groups/G0094) has obtained exploit code for various CVEs.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|PRE|T1588.005|Exploits|


[Kimsuky](https://attack.mitre.org/groups/G0094) has been observed disabling the system firewall.(Citation: Securelist Kimsuky Sept 2013)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1562.004|Disable or Modify System Firewall|


[Kimsuky](https://attack.mitre.org/groups/G0094) has executed malware with <code>regsvr32s</code>.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows|T1218.010|Regsvr32|


[Kimsuky](https://attack.mitre.org/groups/G0094) has modified Registry settings for default file associations to enable all macros and for persistence.(Citation: CISA AA20-301A Kimsuky)(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows|T1112|Modify Registry|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used browser extensions including Google Chrome to steal passwords and cookies from browsers. [Kimsuky](https://attack.mitre.org/groups/G0094) has also used Nirsoft's WebBrowserPassView tool to dump the passwords obtained from victims.(Citation: Zdnet Kimsuky Dec 2018)(Citation: CISA AA20-301A Kimsuky)(Citation: Netscout Stolen Pencil Dec 2018)(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1555.003|Credentials from Web Browsers|


[Kimsuky](https://attack.mitre.org/groups/G0094) can gather a list of all processes running on a victim's machine.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1057|Process Discovery|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used emails containing Word, Excel and/or HWP (Hangul Word Processor) documents in their spearphishing campaigns.(Citation: Zdnet Kimsuky Dec 2018)(Citation: Securelist Kimsuky Sept 2013)(Citation: ThreatConnect Kimsuky September 2020)(Citation: VirusBulletin Kimsuky October 2019)(Citation: Cybereason Kimsuky November 2020)(Citation: Malwarebytes Kimsuky June 2021)(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Kimsuky](https://attack.mitre.org/groups/G0094) has a HWP document stealer module which changes the default program association in the registry to open HWP documents.(Citation: Securelist Kimsuky Sept 2013)
|['enterprise-attack']|enterprise-attack|Windows|T1546.001|Change Default File Association|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used mshta.exe to run malicious scripts on the system.(Citation: EST Kimsuky April 2019)(Citation: CISA AA20-301A Kimsuky)(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows|T1218.005|Mshta|


[Kimsuky](https://attack.mitre.org/groups/G0094) has exfiltrated data over its C2 channel.(Citation: Securelist Kimsuky Sept 2013)(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1041|Exfiltration Over C2 Channel|


[Kimsuky](https://attack.mitre.org/groups/G0094) has checked for the presence of antivirus software with <code>powershell Get-CimInstance -Namespace root/securityCenter2 – classname antivirusproduct</code>.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1518.001|Security Software Discovery|


[Kimsuky](https://attack.mitre.org/groups/G0094) has obfuscated binary strings including the use of XOR encryption and Base64 encoding.(Citation: ThreatConnect Kimsuky September 2020)(Citation: VirusBulletin Kimsuky October 2019) [Kimsuky](https://attack.mitre.org/groups/G0094) has also modified the first byte of DLL implants targeting victims to prevent recognition of the executable file format.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1027|Obfuscated Files or Information|


[Kimsuky](https://attack.mitre.org/groups/G0094) has compromised legitimate sites and used them to distribute malware.(Citation: KISA Operation Muzabi)(Citation: Mandiant APT43 March 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1584.001|Domains|


[Kimsuky](https://attack.mitre.org/groups/G0094) has collected valid email addresses including personal accounts that were subsequently used for spearphishing and other forms of social engineering.(Citation: Malwarebytes Kimsuky June 2021)(Citation: Proofpoint TA427 April 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1589.002|Email Addresses|


[Kimsuky](https://attack.mitre.org/groups/G0094) has enumerated drives, OS type, OS version, and other information using a script or the "systeminfo" command.(Citation: Securelist Kimsuky Sept 2013)(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used RDP to establish persistence.(Citation: CISA AA20-301A Kimsuky)
|['enterprise-attack']|enterprise-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used JScript for logging and downloading additional tools.(Citation: VirusBulletin Kimsuky October 2019)(Citation: CISA AA20-301A Kimsuky)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.007|JavaScript|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used Visual Basic to download malicious payloads.(Citation: ThreatConnect Kimsuky September 2020)(Citation: VirusBulletin Kimsuky October 2019)(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: Talos Kimsuky Nov 2021) [Kimsuky](https://attack.mitre.org/groups/G0094) has also used malicious VBA macros within maldocs disguised as forms that trigger when a victim types any content into the lure.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[Kimsuky](https://attack.mitre.org/groups/G0094) has gathered credentials using [Mimikatz](https://attack.mitre.org/software/S0002) and ProcDump.(Citation: CISA AA20-301A Kimsuky)(Citation: Netscout Stolen Pencil Dec 2018)(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows|T1003.001|LSASS Memory|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used a file injector DLL to spawn a benign process on the victim's system and inject the malicious payload into it via process hollowing.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1055.012|Process Hollowing|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used FTP to download additional malware to the target machine.(Citation: VirusBulletin Kimsuky October 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.002|File Transfer Protocols|


[Kimsuky](https://attack.mitre.org/groups/G0094) has set auto-forward rules on victim's e-mail accounts.(Citation: CISA AA20-301A Kimsuky)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Office Suite|T1114.003|Email Forwarding Rule|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used tools such as the MailFetch mail crawler to collect victim emails (excluding spam) from online services via IMAP.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1114.002|Remote Email Collection|


[Kimsuky](https://attack.mitre.org/groups/G0094) has added accounts to specific groups with <code>net localgroup</code>.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1098.007|Additional Local or Domain Groups|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used modified versions of open source PHP web shells to maintain access, often adding "Dinosaur" references within the code.(Citation: CISA AA20-301A Kimsuky)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used a macOS Python implant to gather data as well as MailFetcher.py code to automatically collect email data.(Citation: CISA AA20-301A Kimsuky)(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1059.006|Python|


[Kimsuky](https://attack.mitre.org/groups/G0094) has the ability to enumerate all files and directories on an infected system.(Citation: Securelist Kimsuky Sept 2013)(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[Kimsuky](https://attack.mitre.org/groups/G0094) has used an information gathering module that will hide an AV software window from the victim.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1564.003|Hidden Window|


[Kimsuky](https://attack.mitre.org/groups/G0094) has hosted content used for targeting efforts via web services such as Blogspot.(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1583.006|Web Services|


[Kimsuky](https://attack.mitre.org/groups/G0094) has placed scripts in the startup folder for persistence and modified the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce` Registry key.(Citation: Securelist Kimsuky Sept 2013)(Citation: CISA AA20-301A Kimsuky)(Citation: Crowdstrike GTR2020 Mar 2020)(Citation: Talos Kimsuky Nov 2021)(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[Kimsuky](https://attack.mitre.org/groups/G0094) has created new services for persistence.(Citation: Securelist Kimsuky Sept 2013)(Citation: CISA AA20-301A Kimsuky)
|['enterprise-attack']|enterprise-attack|Windows|T1543.003|Windows Service|


[Kimsuky](https://attack.mitre.org/groups/G0094) has been observed turning off Windows Security Center and can hide the AV software window from the view of the infected user.(Citation: Securelist Kimsuky Sept 2013)(Citation: Talos Kimsuky Nov 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|


[Kimsuky](https://attack.mitre.org/groups/G0094) has searched for vulnerabilities, tools, and geopolitical trends on Google to target victims.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|PRE|T1593.002|Search Engines|


[Kimsuky](https://attack.mitre.org/groups/G0094) has renamed malware to legitimate names such as <code>ESTCommon.dll</code> or <code>patch.dll</code>.(Citation: Kimsuky Malwarebytes)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[Kimsuky](https://attack.mitre.org/groups/G0094) has downloaded additional malware with scheduled tasks.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[Kimsuky](https://attack.mitre.org/groups/G0094) has disguised its C2 addresses as the websites of shopping malls, governments, universities, and others.(Citation: KISA Operation Muzabi)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036|Masquerading|

