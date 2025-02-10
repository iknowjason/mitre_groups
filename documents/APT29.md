# APT29 - G0016

**Created**: 2017-05-31T21:31:52.748Z

**Modified**: 2024-09-03T18:48:32.299Z

**Contributors**: Daniyal Naeem, BT Security,Matt Brenton, Zurich Insurance Group,Katie Nickels, Red Canary,Joe Gumke, U.S. Bank,Liran Ravich, CardinalOps

## Aliases

APT29,IRON RITUAL,IRON HEMLOCK,NobleBaron,Dark Halo,NOBELIUM,UNC2452,YTTRIUM,The Dukes,Cozy Bear,CozyDuke,SolarStorm,Blue Kitsune,UNC3524,Midnight Blizzard

## Description

[APT29](https://attack.mitre.org/groups/G0016) is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).(Citation: White House Imposing Costs RU Gov April 2021)(Citation: UK Gov Malign RIS Activity April 2021) They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks. [APT29](https://attack.mitre.org/groups/G0016) reportedly compromised the Democratic National Committee starting in the summer of 2015.(Citation: F-Secure The Dukes)(Citation: GRIZZLY STEPPE JAR)(Citation: Crowdstrike DNC June 2016)(Citation: UK Gov UK Exposes Russia SolarWinds April 2021)

In April 2021, the US and UK governments attributed the [SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024) to the SVR; public statements included citations to [APT29](https://attack.mitre.org/groups/G0016), Cozy Bear, and The Dukes.(Citation: NSA Joint Advisory SVR SolarWinds April 2021)(Citation: UK NSCS Russia SolarWinds April 2021) Industry reporting also referred to the actors involved in this campaign as UNC2452, NOBELIUM, StellarParticle, Dark Halo, and SolarStorm.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: CrowdStrike SUNSPOT Implant January 2021)(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Unit 42 SolarStorm December 2020)

## Techniques Used


[APT29](https://attack.mitre.org/groups/G0016) has used repeated MFA requests to gain access to victim accounts.(Citation: Suspected Russian Activity Targeting Government and Business Entities Around the Globe)(Citation: NCSC et al APT29 2024)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, IaaS, SaaS, Office Suite, Identity Provider|T1621|Multi-Factor Authentication Request Generation|


[APT29](https://attack.mitre.org/groups/G0016) has exploited CVE-2021-36934 to escalate privileges on a compromised host.(Citation: ESET T3 Threat Report 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1068|Exploitation for Privilege Escalation|


[APT29](https://attack.mitre.org/groups/G0016) has used Dynamic DNS providers for their malware C2 infrastructure.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1568|Dynamic Resolution|


[APT29](https://attack.mitre.org/groups/G0016) uses stolen tokens to access victim accounts, without needing a password.(Citation: NCSC et al APT29 2024)
|['enterprise-attack']|enterprise-attack|SaaS, Containers, IaaS, Office Suite, Identity Provider|T1528|Steal Application Access Token|


[APT29](https://attack.mitre.org/groups/G0016) has used WMI event subscriptions for persistence.(Citation: Mandiant No Easy Breach)
|['enterprise-attack']|enterprise-attack|Windows|T1546.003|Windows Management Instrumentation Event Subscription|


[APT29](https://attack.mitre.org/groups/G0016) added Registry Run keys to establish persistence.(Citation: Mandiant No Easy Breach)
|['enterprise-attack']|enterprise-attack|Windows|T1547.001|Registry Run Keys / Startup Folder|


[APT29](https://attack.mitre.org/groups/G0016) has used the `reg save` command to save registry hives.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|Windows|T1003.002|Security Account Manager|


[APT29](https://attack.mitre.org/groups/G0016) has used the meek domain fronting plugin for [Tor](https://attack.mitre.org/software/S0183) to hide the destination of C2 traffic.(Citation: Mandiant No Easy Breach)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1090.004|Domain Fronting|


[APT29](https://attack.mitre.org/groups/G0016) has obtained and used a variety of tools including [Mimikatz](https://attack.mitre.org/software/S0002), [SDelete](https://attack.mitre.org/software/S0195), [Tor](https://attack.mitre.org/software/S0183), [meek](https://attack.mitre.org/software/S0175), and [Cobalt Strike](https://attack.mitre.org/software/S0154).(Citation: Mandiant No Easy Breach)(Citation: F-Secure The Dukes)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[APT29](https://attack.mitre.org/groups/G0016) has used spearphishing emails with an attachment to deliver files with exploits to initial victims.(Citation: F-Secure The Dukes)(Citation: MSTIC NOBELIUM May 2021)(Citation: ESET T3 Threat Report 2021)(Citation: Secureworks IRON HEMLOCK Profile)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[APT29](https://attack.mitre.org/groups/G0016) has gained access to a global administrator account in Azure AD and has used `Service Principal` credentials in Exchange.(Citation: Mandiant APT29 Microsoft 365 2022)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|SaaS, IaaS, Office Suite, Identity Provider|T1078.004|Cloud Accounts|


[APT29](https://attack.mitre.org/groups/G0016) can create new users through Azure AD.(Citation: MSTIC Nobelium Oct 2021)
|['enterprise-attack']|enterprise-attack|IaaS, SaaS, Office Suite, Identity Provider|T1136.003|Cloud Account|


[APT29](https://attack.mitre.org/groups/G0016) has downloaded additional tools and malware onto compromised networks.(Citation: Mandiant No Easy Breach)(Citation: PWC WellMess July 2020)(Citation: F-Secure The Dukes)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[APT29](https://attack.mitre.org/groups/G0016) has used Azure Run Command and Azure Admin-on-Behalf-of (AOBO) to execute code on virtual machines.(Citation: MSTIC Nobelium Oct 2021)
|['enterprise-attack']|enterprise-attack|IaaS|T1651|Cloud Administration Command|


[APT29](https://attack.mitre.org/groups/G0016) has created self-signed digital certificates to enable mutual TLS authentication for malware.(Citation: PWC WellMess July 2020)(Citation: PWC WellMess C2 August 2020)
|['enterprise-attack']|enterprise-attack|PRE|T1587.003|Digital Certificates|


[APT29](https://attack.mitre.org/groups/G0016) has stolen data from compromised hosts.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[APT29](https://attack.mitre.org/groups/G0016) has enrolled their own devices into compromised cloud tenants, including enrolling a device in MFA to an Azure AD environment following a successful password guessing attack against a dormant account.(Citation: Mandiant APT29 Microsoft 365 2022)(Citation: NCSC et al APT29 2024)
|['enterprise-attack']|enterprise-attack|Windows, Identity Provider|T1098.005|Device Registration|


[APT29](https://attack.mitre.org/groups/G0016) has collected emails from targeted mailboxes within a compromised Azure AD tenant and compromised Exchange servers, including via Exchange Web Services (EWS) API requests.(Citation: Mandiant APT29 Microsoft 365 2022)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1114.002|Remote Email Collection|


[APT29](https://attack.mitre.org/groups/G0016) used large size files to avoid detection by security solutions with hardcoded size limits.(Citation: SentinelOne NobleBaron June 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1027.001|Binary Padding|


[APT29](https://attack.mitre.org/groups/G0016) has renamed malicious DLLs with legitimate names to appear benign; they have also created an Azure AD certificate with a Common Name that matched the display name of the compromised service principal.(Citation: SentinelOne NobleBaron June 2021)(Citation: Mandiant APT29 Microsoft 365 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[APT29](https://attack.mitre.org/groups/G0016) has conducted brute force password spray attacks.(Citation: MSRC Nobelium June 2021)(Citation: MSTIC Nobelium Oct 2021)(Citation: NCSC et al APT29 2024)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110.003|Password Spraying|


[APT29](https://attack.mitre.org/groups/G0016) has used encoded PowerShell scripts uploaded to [CozyCar](https://attack.mitre.org/software/S0046) installations to download and install [SeaDuke](https://attack.mitre.org/software/S0053).(Citation: Symantec Seaduke 2015)(Citation: Mandiant No Easy Breach)(Citation: ESET T3 Threat Report 2021)(Citation: Secureworks IRON HEMLOCK Profile)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[APT29](https://attack.mitre.org/groups/G0016) has edited the `Microsoft.IdentityServer.Servicehost.exe.config` file to load a malicious DLL into the AD FS process, thereby enabling persistent access to any service federated with AD FS for a user with a specified User Principal Name.(Citation: MagicWeb)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Office Suite, Identity Provider|T1556.007|Hybrid Identity|


[APT29](https://attack.mitre.org/groups/G0016) has hijacked legitimate application-specific startup scripts to enable malware to execute on system startup.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux, Network|T1037|Boot or Logon Initialization Scripts|


A backdoor used by [APT29](https://attack.mitre.org/groups/G0016) created a [Tor](https://attack.mitre.org/software/S0183) hidden service to forward traffic from the [Tor](https://attack.mitre.org/software/S0183) client to local ports 3389 (RDP), 139 (Netbios), and 445 (SMB) enabling full remote access from outside the network and has also used TOR.(Citation: Mandiant No Easy Breach)(Citation: MSTIC Nobelium Oct 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090.003|Multi-hop Proxy|


[APT29](https://attack.mitre.org/groups/G0016) has registered algorithmically generated Twitter handles that are used for C2 by malware, such as [HAMMERTOSS](https://attack.mitre.org/software/S0037). [APT29](https://attack.mitre.org/groups/G0016) has also used legitimate web services such as Dropbox and Constant Contact in their operations.(Citation: FireEye APT29)(Citation: MSTIC NOBELIUM May 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1583.006|Web Services|


[APT29](https://attack.mitre.org/groups/G0016) has used named and hijacked scheduled tasks to establish persistence.(Citation: Mandiant No Easy Breach)
|['enterprise-attack']|enterprise-attack|Windows|T1053.005|Scheduled Task|


[APT29](https://attack.mitre.org/groups/G0016) has used unique malware in many of their operations.(Citation: F-Secure The Dukes)(Citation: Mandiant No Easy Breach)(Citation: MSTIC Nobelium Toolset May 2021)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|PRE|T1587.001|Malware|


[APT29](https://attack.mitre.org/groups/G0016) has ensured web servers in a victim environment are Internet accessible before copying tools or malware to it.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1016.001|Internet Connection Discovery|


[APT29](https://attack.mitre.org/groups/G0016) has used various forms of spearphishing attempting to get a user to click on a malicious link.(Citation: MSTIC NOBELIUM May 2021)(Citation: Secureworks IRON RITUAL USAID Phish May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[APT29](https://attack.mitre.org/groups/G0016) has used multiple software exploits for common client software, like Microsoft Word, Exchange, and Adobe Reader, to gain code execution.(Citation: F-Secure The Dukes)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: MSTIC NOBELIUM May 2021)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1203|Exploitation for Client Execution|


[APT29](https://attack.mitre.org/groups/G0016) used Kerberos ticket attacks for lateral movement.(Citation: Mandiant No Easy Breach)
|['enterprise-attack']|enterprise-attack|Windows|T1550.003|Pass the Ticket|


[APT29](https://attack.mitre.org/groups/G0016) has embedded an ISO file within an HTML attachment that contained JavaScript code to initiate malware execution.(Citation: ESET T3 Threat Report 2021) 
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1027.006|HTML Smuggling|


[APT29](https://attack.mitre.org/groups/G0016) has used [SDelete](https://attack.mitre.org/software/S0195) to remove artifacts from victim networks.(Citation: Mandiant No Easy Breach)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.004|File Deletion|


[APT29](https://attack.mitre.org/groups/G0016) has compromised IT, cloud services, and managed services providers to gain broad access to multiple customers for subsequent operations.(Citation: MSTIC Nobelium Oct 2021)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Identity Provider, Office Suite|T1199|Trusted Relationship|


[APT29](https://attack.mitre.org/groups/G0016) has installed web shells on exploited Microsoft Exchange servers.(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[APT29](https://attack.mitre.org/groups/G0016) has used a compromised account to access an organization's VPN infrastructure.(Citation: Mandiant APT29 Microsoft 365 2022)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[APT29](https://attack.mitre.org/groups/G0016) has used the legitimate mailing service Constant Contact to send phishing e-mails.(Citation: MSTIC NOBELIUM May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1566.003|Spearphishing via Service|


[APT29](https://attack.mitre.org/groups/G0016) has used residential proxies, including Azure Virtual Machines, to obfuscate their access to victim environments.(Citation: Mandiant APT29 Microsoft 365 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1586.003|Cloud Accounts|


[APT29](https://attack.mitre.org/groups/G0016) has successfully conducted password guessing attacks against a list of mailboxes.(Citation: Mandiant APT29 Microsoft 365 2022)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1110.001|Password Guessing|


[APT29](https://attack.mitre.org/groups/G0016) used WMI to steal credentials and execute backdoors at a future time.(Citation: Mandiant No Easy Breach)
|['enterprise-attack']|enterprise-attack|Windows|T1047|Windows Management Instrumentation|


[APT29](https://attack.mitre.org/groups/G0016) has used multiple layers of encryption within malware to protect C2 communication.(Citation: Secureworks IRON HEMLOCK Profile)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1573|Encrypted Channel|


[APT29](https://attack.mitre.org/groups/G0016) uses compromised residential endpoints as proxies for defense evasion and network access.(Citation: NCSC et al APT29 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090.002|External Proxy|


[APT29](https://attack.mitre.org/groups/G0016) has exploited CVE-2019-19781 for Citrix, CVE-2019-11510 for Pulse Secure VPNs, CVE-2018-13379 for FortiGate VPNs, and CVE-2019-9670 in Zimbra software to gain access.(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: NCSC APT29 July 2020)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Network, Linux, macOS, Containers|T1190|Exploit Public-Facing Application|


[APT29](https://attack.mitre.org/groups/G0016) has used the `reg save` command to extract LSA secrets offline.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|Windows|T1003.004|LSA Secrets|


[APT29](https://attack.mitre.org/groups/G0016) uses compromised residential endpoints, typically within the same ISP IP address range, as proxies to hide the true source of C2 traffic.(Citation: NCSC et al APT29 2024)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux, Network|T1665|Hide Infrastructure|


[APT29](https://attack.mitre.org/groups/G0016) has developed malware variants written in Python.(Citation: Symantec Seaduke 2015)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1059.006|Python|


[APT29](https://attack.mitre.org/groups/G0016) has use `mshta` to execute malicious scripts on a compromised host.(Citation: ESET T3 Threat Report 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1218.005|Mshta|


[APT29](https://attack.mitre.org/groups/G0016) has leveraged compromised high-privileged on-premises accounts synced to Office 365 to move laterally into a cloud environment, including through the use of Azure AD PowerShell.(Citation: Mandiant Remediation and Hardening Strategies for Microsoft 365)
|['enterprise-attack']|enterprise-attack|SaaS, IaaS, Office Suite, Identity Provider|T1021.007|Cloud Services|


[APT29](https://attack.mitre.org/groups/G0016) has installed a run command on a compromised system to enable malware execution on system startup.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|macOS, Linux, Network|T1037.004|RC Scripts|


[APT29](https://attack.mitre.org/groups/G0016) has used compromised identities to access networks via VPNs and Citrix.(Citation: NCSC APT29 July 2020)(Citation: Mandiant APT29 Microsoft 365 2022)
|['enterprise-attack']|enterprise-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[APT29](https://attack.mitre.org/groups/G0016) has used timestomping to alter the Standard Information timestamps on their web shells to match other files in the same directory.(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.006|Timestomp|


[APT29](https://attack.mitre.org/groups/G0016) has used spearphishing with a link to trick victims into clicking on a link to a zip file containing malicious files.(Citation: Mandiant No Easy Breach)(Citation: MSTIC NOBELIUM May 2021)(Citation: Secureworks IRON RITUAL USAID Phish May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[APT29](https://attack.mitre.org/groups/G0016) has conducted widespread scanning of target environments to identify vulnerabilities for exploit.(Citation: Cybersecurity Advisory SVR TTP May 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1595.002|Vulnerability Scanning|


[APT29](https://attack.mitre.org/groups/G0016) used sticky-keys to obtain unauthenticated, privileged console access.(Citation: Mandiant No Easy Breach)(Citation: FireEye APT29 Domain Fronting)
|['enterprise-attack']|enterprise-attack|Windows|T1546.008|Accessibility Features|


[APT29](https://attack.mitre.org/groups/G0016) has compromised email accounts to further enable phishing campaigns and taken control of dormant accounts.(Citation: ANSSI Nobelium Phishing December 2021)(Citation: Mandiant APT29 Microsoft 365 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1586.002|Email Accounts|


[APT29](https://attack.mitre.org/groups/G0016) has leveraged the Microsoft Graph API to perform various actions across Azure and M365 environments. They have also utilized AADInternals PowerShell Modules to access the API (Citation: MSTIC Nobelium Toolset May 2021)
|['enterprise-attack']|enterprise-attack|IaaS, SaaS, Office Suite, Identity Provider|T1059.009|Cloud API|


[APT29](https://attack.mitre.org/groups/G0016) has disabled Purview Audit on targeted accounts prior to stealing emails from  Microsoft 365 tenants.(Citation: Mandiant APT29 Microsoft 365 2022)
|['enterprise-attack']|enterprise-attack|IaaS, SaaS, Office Suite, Identity Provider|T1562.008|Disable or Modify Cloud Logs|


[APT29](https://attack.mitre.org/groups/G0016) has bypassed UAC.(Citation: Mandiant No Easy Breach)
|['enterprise-attack']|enterprise-attack|Windows|T1548.002|Bypass User Account Control|


[APT29](https://attack.mitre.org/groups/G0016) used UPX to pack files.(Citation: Mandiant No Easy Breach)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1027.002|Software Packing|


[APT29](https://attack.mitre.org/groups/G0016) has used various forms of spearphishing attempting to get a user to open attachments, including, but not limited to, malicious Microsoft Word documents, .pdf, and .lnk files. (Citation: F-Secure The Dukes)(Citation: ESET T3 Threat Report 2021)(Citation: Secureworks IRON HEMLOCK Profile)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[APT29](https://attack.mitre.org/groups/G0016) has conducted enumeration of Azure AD accounts.(Citation: MSTIC Nobelium Oct 2021)
|['enterprise-attack']|enterprise-attack|SaaS, IaaS, Office Suite, Identity Provider|T1087.004|Cloud Account|


[APT29](https://attack.mitre.org/groups/G0016) has embedded ISO images and VHDX files in HTML to evade Mark-of-the-Web.(Citation: ESET T3 Threat Report 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1553.005|Mark-of-the-Web Bypass|


[APT29](https://attack.mitre.org/groups/G0016) has abused misconfigured AD CS certificate templates to impersonate admin users and create additional authentication certificates.(Citation: Mandiant APT29 Trello)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, Identity Provider|T1649|Steal or Forge Authentication Certificates|


[APT29](https://attack.mitre.org/groups/G0016) targets dormant or inactive user accounts, accounts belonging to individuals no longer at the organization but whose accounts remain on the system, for access and persistence.(Citation: NCSC et al APT29 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers, Network|T1078.003|Local Accounts|


[APT29](https://attack.mitre.org/groups/G0016) has used a compromised global administrator account in Azure AD to backdoor a service principal with `ApplicationImpersonation` rights to start collecting emails from targeted mailboxes; [APT29](https://attack.mitre.org/groups/G0016) has also used compromised accounts holding `ApplicationImpersonation` rights in Exchange to collect emails.(Citation: Mandiant APT29 Microsoft 365 2022)(Citation: Mandiant APT29 Eye Spy Email Nov 22)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1098.002|Additional Email Delegate Permissions|


[APT29](https://attack.mitre.org/groups/G0016) has used PowerShell to discover domain accounts by executing <code>Get-ADUser</code> and <code>Get-ADGroupMember</code>.(Citation: CrowdStrike StellarParticle January 2022)(Citation: Secureworks IRON RITUAL Profile)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[APT29](https://attack.mitre.org/groups/G0016) drops a Windows shortcut file for execution.(Citation: FireEye APT29 Nov 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1547.009|Shortcut Modification|


[APT29](https://attack.mitre.org/groups/G0016) used [SDelete](https://attack.mitre.org/software/S0195) to remove artifacts from victims.
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers, Network, Office Suite|T1070|Indicator Removal|


[APT29](https://attack.mitre.org/groups/G0016) obtained information about the configured Exchange virtual directory using <code>Get-WebServicesVirtualDirectory</code>.(Citation: Volexity SolarWinds)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[APT29](https://attack.mitre.org/groups/G0016) has set the hostnames of its C2 infrastructure to match legitimate hostnames in the victim environment. They have also used IP addresses originating from the same country as the victim for their VPN infrastructure.(Citation: FireEye SUNBURST Backdoor December 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036|Masquerading|


[APT29](https://attack.mitre.org/groups/G0016) has acquired C2 domains, sometimes through resellers.(Citation: MSTIC NOBELIUM Mar 2021)(Citation: FireEye SUNSHUTTLE Mar 2021)(Citation: MSTIC NOBELIUM May 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1583.001|Domains|


[APT29](https://attack.mitre.org/groups/G0016) obtained a list of users and their roles from an Exchange server using <code>Get-ManagementRoleAssignment</code>.(Citation: Volexity SolarWinds)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Office Suite, Identity Provider|T1087|Account Discovery|


[APT29](https://attack.mitre.org/groups/G0016) temporarily replaced legitimate utilities with their own, executed their payload, and then restored the original file.(Citation: FireEye SUNBURST Backdoor December 2020)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers, Network, Office Suite|T1070|Indicator Removal|


[APT29](https://attack.mitre.org/groups/G0016) used account credentials they obtained to attempt access to Group Managed Service Account (gMSA) passwords.(Citation: Microsoft Deep Dive Solorigate January 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1555|Credentials from Password Stores|


[APT29](https://attack.mitre.org/groups/G0016) has accessed victims’ internal knowledge repositories (wikis) to view sensitive corporate information on products, services, and internal business operations.(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, SaaS, IaaS, Office Suite|T1213|Data from Information Repositories|


[APT29](https://attack.mitre.org/groups/G0016) has used encoded PowerShell commands.(Citation: FireEye APT29 Nov 2018)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1027|Obfuscated Files or Information|


[APT29](https://attack.mitre.org/groups/G0016) has used multiple command-line utilities to enumerate running processes.(Citation: Volexity SolarWinds)(Citation: Microsoft Deep Dive Solorigate January 2021)(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1057|Process Discovery|


[APT29](https://attack.mitre.org/groups/G0016) has used RDP sessions from public-facing systems to internal servers.(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1021.001|Remote Desktop Protocol|


[APT29](https://attack.mitre.org/groups/G0016) used forged SAML tokens that allowed the actors to impersonate users and bypass MFA, enabling [APT29](https://attack.mitre.org/groups/G0016) to access enterprise cloud applications and services.(Citation: Microsoft 365 Defender Solorigate)(Citation: Secureworks IRON RITUAL Profile)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Containers, Identity Provider, Office Suite|T1550|Use Alternate Authentication Material|


[APT29](https://attack.mitre.org/groups/G0016) used the <code>Get-ManagementRoleAssignment</code> PowerShell cmdlet to enumerate Exchange management role assignments through an Exchange Management Shell.(Citation: Volexity SolarWinds)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Office Suite, Identity Provider|T1069|Permission Groups Discovery|


[APT29](https://attack.mitre.org/groups/G0016) added their own devices as allowed IDs for active sync using <code>Set-CASMailbox</code>, allowing it to obtain copies of victim mailboxes. It also added additional permissions (such as Mail.Read and Mail.ReadWrite) to compromised Application or Service Principals.(Citation: Volexity SolarWinds)(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks)(Citation: MSTIC Nobelium Oct 2021)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1098.002|Additional Email Delegate Permissions|


[APT29](https://attack.mitre.org/groups/G0016) has compromised domains to use for C2.(Citation: MSTIC NOBELIUM Mar 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1584.001|Domains|


[APT29](https://attack.mitre.org/groups/G0016) modified timestamps of backdoors to match legitimate Windows files.(Citation: Microsoft Deep Dive Solorigate January 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1070.006|Timestomp|


[APT29](https://attack.mitre.org/groups/G0016) has extracted files from compromised networks.(Citation: Volexity SolarWinds) 
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[APT29](https://attack.mitre.org/groups/G0016) changed domain federation trust settings using Azure AD administrative permissions to configure the domain to accept authorization tokens signed by their own SAML signing certificate.(Citation: Microsoft 365 Defender Solorigate)(Citation: Secureworks IRON RITUAL Profile)
|['enterprise-attack']|enterprise-attack|Windows, Identity Provider|T1484.002|Trust Modification|


[APT29](https://attack.mitre.org/groups/G0016) gained initial network access to some victims via a trojanized update of SolarWinds Orion software.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: Cybersecurity Advisory SVR TTP May 2021)(Citation: Secureworks IRON RITUAL Profile)(Citation: MSTIC Nobelium Oct 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1195.002|Compromise Software Supply Chain|


[APT29](https://attack.mitre.org/groups/G0016) has used valid accounts, including administrator accounts, to help facilitate lateral movement on compromised networks.(Citation: ESET Dukes October 2019)(Citation: NCSC APT29 July 2020)(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1078.002|Domain Accounts|


[APT29](https://attack.mitre.org/groups/G0016) has added credentials to OAuth Applications and Service Principals.(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks)(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|IaaS, SaaS, Identity Provider|T1098.001|Additional Cloud Credentials|


[APT29](https://attack.mitre.org/groups/G0016) has disabled Purview Audit on targeted accounts prior to stealing emails from  Microsoft 365 tenants.(Citation: Mandiant APT29 Microsoft 365 2022)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|


[APT29](https://attack.mitre.org/groups/G0016) used 7-Zip to decode its [Raindrop](https://attack.mitre.org/software/S0565) malware.(Citation: Symantec RAINDROP January 2021)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1140|Deobfuscate/Decode Files or Information|


[APT29](https://attack.mitre.org/groups/G0016) has written malware variants in Visual Basic.(Citation: Cybersecurity Advisory SVR TTP May 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.005|Visual Basic|


[APT29](https://attack.mitre.org/groups/G0016) has used [AdFind](https://attack.mitre.org/software/S0552) to enumerate domain groups.(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1069.002|Domain Groups|


[APT29](https://attack.mitre.org/groups/G0016) used 7-Zip to compress stolen emails into password-protected archives prior to exfiltration; [APT29](https://attack.mitre.org/groups/G0016) has also compressed text files into zipped archives.(Citation: Volexity SolarWinds)(Citation: Microsoft Deep Dive Solorigate January 2021)(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[APT29](https://attack.mitre.org/groups/G0016) leveraged privileged accounts to replicate directory service data with domain controllers.(Citation: Microsoft 365 Defender Solorigate)(Citation: Microsoft Deep Dive Solorigate January 2021)(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1003.006|DCSync|


[APT29](https://attack.mitre.org/groups/G0016) used stolen cookies to access cloud resources, and a forged <code>duo-sid</code> cookie to bypass MFA set on an email account.(Citation: Volexity SolarWinds)(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|SaaS, IaaS, Office Suite|T1550.004|Web Session Cookie|


[APT29](https://attack.mitre.org/groups/G0016) registered devices in order to enable mailbox syncing via the <code>Set-CASMailbox</code> command.(Citation: Volexity SolarWinds)
|['enterprise-attack']|enterprise-attack|Windows, Identity Provider|T1098.005|Device Registration|


[APT29](https://attack.mitre.org/groups/G0016) has used a compromised O365 administrator account to create a new Service Principal.(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|SaaS, IaaS, Office Suite, Identity Provider|T1078.004|Cloud Accounts|


[APT29](https://attack.mitre.org/groups/G0016) used <code>cmd.exe</code> to execute commands on remote machines.(Citation: Volexity SolarWinds)(Citation: Microsoft Analyzing Solorigate Dec 2020)
|['enterprise-attack']|enterprise-attack|Windows|T1059.003|Windows Command Shell|


[APT29](https://attack.mitre.org/groups/G0016) named tasks <code>\Microsoft\Windows\SoftwareProtectionPlatform\EventCacheManager</code> in order to appear legitimate.(Citation: Volexity SolarWinds)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1036.004|Masquerade Task or Service|


[APT29](https://attack.mitre.org/groups/G0016) has used compromised local accounts to access victims' networks.(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers, Network|T1078.003|Local Accounts|


[APT29](https://attack.mitre.org/groups/G0016) has stolen Chrome browser cookies by copying the Chrome profile directories of targeted users.(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Office Suite|T1539|Steal Web Session Cookie|


[APT29](https://attack.mitre.org/groups/G0016) has exfiltrated collected data over a simple HTTPS request to a password-protected archive staged on a victim's OWA servers.(Citation: Volexity SolarWinds)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1048.002|Exfiltration Over Asymmetric Encrypted Non-C2 Protocol|


[APT29](https://attack.mitre.org/groups/G0016) has used <code>Rundll32.exe</code> to execute payloads.(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks)(Citation: Microsoft Deep Dive Solorigate January 2021)(Citation: FireEye APT29 Nov 2018)
|['enterprise-attack']|enterprise-attack|Windows|T1218.011|Rundll32|


[APT29](https://attack.mitre.org/groups/G0016) has used administrative accounts to connect over SMB to targeted users.(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1021.002|SMB/Windows Admin Shares|


[APT29](https://attack.mitre.org/groups/G0016) has granted `company administrator` privileges to a newly created service principal.(Citation: CrowdStrike StellarParticle January 2022) 
|['enterprise-attack']|enterprise-attack|IaaS, SaaS, Office Suite, Identity Provider|T1098.003|Additional Cloud Roles|


[APT29](https://attack.mitre.org/groups/G0016) used <code>AUDITPOL</code> to prevent the collection of audit logs.(Citation: Microsoft Deep Dive Solorigate January 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1562.002|Disable Windows Event Logging|


[APT29](https://attack.mitre.org/groups/G0016) has used HTTP for C2 and data exfiltration.(Citation: Volexity SolarWinds)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1071.001|Web Protocols|


[APT29](https://attack.mitre.org/groups/G0016) has used [AdFind](https://attack.mitre.org/software/S0552) to enumerate remote systems.(Citation: Microsoft Deep Dive Solorigate January 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[APT29](https://attack.mitre.org/groups/G0016) used the service control manager on a remote system to disable services associated with security monitoring products.(Citation: Microsoft Deep Dive Solorigate January 2021)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Containers, IaaS, Network|T1562.001|Disable or Modify Tools|


[APT29](https://attack.mitre.org/groups/G0016) obtained Ticket Granting Service (TGS) tickets for Active Directory Service Principle Names to crack offline.(Citation: Microsoft Deep Dive Solorigate January 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1558.003|Kerberoasting|


[APT29](https://attack.mitre.org/groups/G0016) has used steganography to hide C2 communications in images.(Citation: ESET Dukes October 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1001.002|Steganography|


[APT29](https://attack.mitre.org/groups/G0016) used dynamic DNS resolution to construct and resolve to randomly-generated subdomains for C2.(Citation: Volexity SolarWinds)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1568|Dynamic Resolution|


[APT29](https://attack.mitre.org/groups/G0016) has stolen user's saved passwords from Chrome.(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1555.003|Credentials from Web Browsers|


[APT29](https://attack.mitre.org/groups/G0016) has used social media platforms to hide communications to C2 servers.(Citation: ESET Dukes October 2019)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1102.002|Bidirectional Communication|


[APT29](https://attack.mitre.org/groups/G0016) has conducted credential theft operations to obtain credentials to be used for access to victim environments.(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1589.001|Credentials|


[APT29](https://attack.mitre.org/groups/G0016) has used compromised service principals to make changes to the Office 365 environment.(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|SaaS, Containers, IaaS, Office Suite, Identity Provider|T1550.001|Application Access Token|


[APT29](https://attack.mitre.org/groups/G0016) has used WinRM via PowerShell to execute command and payloads on remote hosts.(Citation: Symantec RAINDROP January 2021)
|['enterprise-attack']|enterprise-attack|Windows|T1021.006|Windows Remote Management|


[APT29](https://attack.mitre.org/groups/G0016) has downloaded source code from code repositories.(Citation: Microsoft Internal Solorigate Investigation Blog)
|['enterprise-attack']|enterprise-attack|SaaS|T1213.003|Code Repositories|


[APT29](https://attack.mitre.org/groups/G0016) has bypassed MFA set on OWA accounts by generating a cookie value from a previously stolen secret key.(Citation: Volexity SolarWinds)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, IaaS|T1606.001|Web Cookies|


[APT29](https://attack.mitre.org/groups/G0016) has used SSH port forwarding capabilities on public-facing systems, and configured at least one instance of [Cobalt Strike](https://attack.mitre.org/software/S0154) to use a network pipe over SMB during the 2020 SolarWinds intrusion.(Citation: Symantec RAINDROP January 2021)(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090.001|Internal Proxy|


[APT29](https://attack.mitre.org/groups/G0016) staged data and files in password-protected archives on a victim's OWA server.(Citation: Volexity SolarWinds)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS|T1074.002|Remote Data Staging|


[APT29](https://attack.mitre.org/groups/G0016) has used TCP for C2 communications.(Citation: FireEye APT29 Nov 2018)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, Network|T1095|Non-Application Layer Protocol|


[APT29](https://attack.mitre.org/groups/G0016) used the <code>Get-AcceptedDomain</code> PowerShell cmdlet to enumerate accepted domains through an Exchange Management Shell.(Citation: Volexity SolarWinds) They also used [AdFind](https://attack.mitre.org/software/S0552) to enumerate domains and to discover trust between federated domains.(Citation: Microsoft Deep Dive Solorigate January 2021)(Citation: CrowdStrike StellarParticle January 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1482|Domain Trust Discovery|


[APT29](https://attack.mitre.org/groups/G0016) used <code>fsutil</code> to check available free space before executing actions that might create large files on disk.(Citation: Microsoft Deep Dive Solorigate January 2021)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[APT29](https://attack.mitre.org/groups/G0016) has used [GoldFinder](https://attack.mitre.org/software/S0597) to perform HTTP GET requests to check internet connectivity and identify HTTP proxy servers and other redirectors that an HTTP request travels through.(Citation: MSTIC NOBELIUM Mar 2021)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1016.001|Internet Connection Discovery|


[APT29](https://attack.mitre.org/groups/G0016) used <code>netsh</code> to configure firewall rules that limited certain UDP outbound packets.(Citation: Microsoft Deep Dive Solorigate January 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1562.004|Disable or Modify System Firewall|


[APT29](https://attack.mitre.org/groups/G0016) was able to get [SUNBURST](https://attack.mitre.org/software/S0559) signed by SolarWinds code signing certificates by injecting the malware into the SolarWinds Orion software lifecycle.(Citation: FireEye SUNBURST Backdoor December 2020)
|['enterprise-attack']|enterprise-attack|macOS, Windows|T1553.002|Code Signing|


[APT29](https://attack.mitre.org/groups/G0016) obtained PKI keys, certificate files and the private encryption key from an Active Directory Federation Services (AD FS) container to decrypt corresponding SAML signing certificates.(Citation: Microsoft 365 Defender Solorigate)(Citation: Cybersecurity Advisory SVR TTP May 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1552.004|Private Keys|


[APT29](https://attack.mitre.org/groups/G0016) removed evidence of email export requests using <code>Remove-MailboxExportRequest</code>.(Citation: Volexity SolarWinds)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Office Suite|T1070.008|Clear Mailbox Data|


[APT29](https://attack.mitre.org/groups/G0016) used different compromised credentials for remote access and to move laterally.(Citation: FireEye SUNBURST Backdoor December 2020)(Citation: MSTIC NOBELIUM Mar 2021)(Citation: Cybersecurity Advisory SVR TTP May 2021)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[APT29](https://attack.mitre.org/groups/G0016) collected emails from specific individuals, such as executives and IT staff, using <code>New-MailboxExportRequest</code> followed by <code>Get-MailboxExportRequest</code>.(Citation: Volexity SolarWinds)(Citation: Cybersecurity Advisory SVR TTP May 2021)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1114.002|Remote Email Collection|


[APT29](https://attack.mitre.org/groups/G0016) created tokens using compromised SAML signing certificates.(Citation: Microsoft - Customer Guidance on Recent Nation-State Cyber Attacks)(Citation: Secureworks IRON RITUAL Profile)
|['enterprise-attack']|enterprise-attack|SaaS, Windows, IaaS, Office Suite, Identity Provider|T1606.002|SAML Tokens|

