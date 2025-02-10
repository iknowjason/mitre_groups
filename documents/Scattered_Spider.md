# Scattered Spider - G1015

**Created**: 2023-07-05T17:54:54.789Z

**Modified**: 2024-04-04T21:24:48.602Z

**Contributors**: 

## Aliases

Scattered Spider,Roasted 0ktapus,Octo Tempest,Storm-0875

## Description

[Scattered Spider](https://attack.mitre.org/groups/G1015) is a native English-speaking cybercriminal group that has been active since at least 2022.(Citation: CrowdStrike Scattered Spider Profile)(Citation: MSTIC Octo Tempest Operations October 2023) The group initially targeted customer relationship management and business-process outsourcing (BPO) firms as well as telecommunications and technology companies. Beginning in 2023, [Scattered Spider](https://attack.mitre.org/groups/G1015) expanded its operations to compromise victims in the gaming, hospitality, retail, MSP, manufacturing, and financial sectors.(Citation: MSTIC Octo Tempest Operations October 2023) During campaigns, [Scattered Spider](https://attack.mitre.org/groups/G1015) has leveraged targeted social-engineering techniques, attempted to bypass popular endpoint security tools, and more recently, deployed ransomware for financial gain.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: CrowdStrike Scattered Spider BYOVD January 2023)(Citation: CrowdStrike Scattered Spider Profile)(Citation: MSTIC Octo Tempest Operations October 2023)(Citation: Crowdstrike TELCO BPO Campaign December 2022)

## Techniques Used


[Scattered Spider](https://attack.mitre.org/groups/G1015) enumerates cloud environments to identify server and backup management infrastructure, resource access, databases and storage containers.(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|IaaS|T1580|Cloud Infrastructure Discovery|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has used a combination of credential phishing and social engineering to capture one-time-password (OTP) codes.(Citation: CrowdStrike Scattered Spider BYOVD January 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|PRE|T1598|Phishing for Information|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has used self-signed and stolen certificates originally issued to NVIDIA and Global Software LLC.(Citation: CrowdStrike Scattered Spider BYOVD January 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|macOS, Windows|T1553.002|Code Signing|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has added additional trusted locations to Azure AD conditional access policies. (Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|IaaS, Identity Provider|T1556.009|Conditional Access Policies|


[Scattered Spider](https://attack.mitre.org/groups/G1015) creates inbound rules on the compromised email accounts of security personnel to automatically delete emails from vendor security products.(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, Linux, macOS, Office Suite|T1564.008|Email Hiding Rules|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has extracted the `NTDS.dit` file by creating volume shadow copies of virtual domain controller disks.(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows|T1003.003|NTDS|


[Scattered Spider](https://attack.mitre.org/groups/G1015) leverages legitimate domain accounts to gain access to the target environment.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[Scattered Spider](https://attack.mitre.org/groups/G1015) adds a federated identity provider to the victim’s SSO tenant and activates automatic account linking.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, Identity Provider|T1484.002|Trust Modification|


[Scattered Spider](https://attack.mitre.org/groups/G1015) abused AWS Systems Manager Inventory to identify targets on the compromised network prior to lateral movement.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|IaaS, SaaS, Office Suite, Identity Provider|T1538|Cloud Service Dashboard|


[Scattered Spider](https://attack.mitre.org/groups/G1015) retrieves browser cookies via Raccoon Stealer.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows, SaaS, Office Suite|T1539|Steal Web Session Cookie|


[Scattered Spider](https://attack.mitre.org/groups/G1015) enumerate and exfiltrate code-signing certificates from a compromised host.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows, Network|T1552.004|Private Keys|


[Scattered Spider](https://attack.mitre.org/groups/G1015) Spider enumerates a target organization for files and directories of interest, including source code.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows, Network|T1083|File and Directory Discovery|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has leveraged legitimate remote management tools to maintain persistent access.(Citation: CrowdStrike Scattered Spider BYOVD January 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has impersonated organization IT and helpdesk staff to instruct victims to execute commercial remote access tools to gain initial access.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, Windows, macOS, IaaS, Containers|T1204|User Execution|


After compromising user accounts, [Scattered Spider](https://attack.mitre.org/groups/G1015) registers their own MFA tokens.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, SaaS, IaaS, Linux, macOS, Office Suite, Identity Provider|T1556.006|Multi-Factor Authentication|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has used BlackCat ransomware to encrypt files on VMWare ESXi servers.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows, IaaS|T1486|Data Encrypted for Impact|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has deployed a malicious kernel driver through exploitation of CVE-2015-2291 in the Intel Ethernet diagnostics driver for Windows (iqvw64.sys).(Citation: CrowdStrike Scattered Spider BYOVD January 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows, Containers|T1068|Exploitation for Privilege Escalation|


[Scattered Spider](https://attack.mitre.org/groups/G1015) threat actors search the victim’s Slack and Microsoft Teams for conversations about the intrusion and incident response.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|SaaS, Office Suite|T1213.005|Messaging Applications|


[Scattered Spider](https://attack.mitre.org/groups/G1015) retrieves browser histories via infostealer malware such as Raccoon Stealer.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, Windows, macOS|T1217|Browser Information Discovery|


[Scattered Spider](https://attack.mitre.org/groups/G1015) enumerates data stored in cloud resources for collection and exfiltration purposes.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|IaaS, SaaS, Office Suite|T1530|Data from Cloud Storage|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has created volume shadow copies of virtual domain controller disks to extract the `NTDS.dit` file.(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, Network|T1006|Direct Volume Access|


[Scattered Spider](https://attack.mitre.org/groups/G1015) enumerates data stored within victim code repositories, such as internal GitHub repositories.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|SaaS|T1213.003|Code Repositories|


During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) used IAM manipulation to gain persistence and to assume or elevate privileges.(Citation: Crowdstrike TELCO BPO Campaign December 2022)

[Scattered Spider](https://attack.mitre.org/groups/G1015) has also assigned user access admin roles in order to gain Tenant Root Group management permissions in Azure.(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|IaaS, SaaS, Office Suite, Identity Provider|T1098.003|Additional Cloud Roles|


During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) directed victims to run remote monitoring and management (RMM) tools.(Citation: Crowdstrike TELCO BPO Campaign December 2022)

In addition to directing victims to run remote software, Scattered Spider members themselves also deploy RMM software including AnyDesk, LogMeIn, and ConnectWise Control to establish persistence on the compromised network.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: Trellix Scattered Spider MO August 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, Windows, macOS|T1219|Remote Access Software|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has deployed ransomware on compromised hosts for financial gain.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: Trellix Scattered Spider MO August 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows, SaaS, Office Suite|T1657|Financial Theft|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has used multifactor authentication (MFA) fatigue by sending repeated MFA authentication requests to targets.(Citation: CrowdStrike Scattered Spider BYOVD January 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, Linux, macOS, IaaS, SaaS, Office Suite, Identity Provider|T1621|Multi-Factor Authentication Request Generation|


During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) used compromised Azure credentials for credential theft activity and lateral movement to on-premises systems.(Citation: Crowdstrike TELCO BPO Campaign December 2022)

Scattered Spider has also leveraged pre-existing AWS EC2 instances for lateral movement and data collection purposes.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|SaaS, IaaS, Office Suite, Identity Provider|T1021.007|Cloud Services|


During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) impersonated legitimate IT personnel in phone calls and text messages either to direct victims to a credential harvesting site or getting victims to run commercial remote monitoring and management (RMM) tools.(Citation: Crowdstrike TELCO BPO Campaign December 2022)

[Scattered Spider](https://attack.mitre.org/groups/G1015) utilized social engineering to compel IT help desk personnel to reset passwords and MFA tokens.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows, SaaS, Office Suite|T1656|Impersonation|


During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) used access to the victim's Azure tenant to create Azure VMs.(Citation: Crowdstrike TELCO BPO Campaign December 2022)

[Scattered Spider](https://attack.mitre.org/groups/G1015) has also created Amazon EC2 instances within the victim's environment.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|IaaS|T1578.002|Create Cloud Instance|


Scattered Spider threat actors search the victim’s Microsoft Exchange for emails about the intrusion and incident response.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, macOS, Linux, Office Suite|T1114|Email Collection|


[Scattered Spider](https://attack.mitre.org/groups/G1015) Spider searches for credential storage documentation on a compromised host.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, IaaS, Linux, macOS, Containers|T1552.001|Credentials In Files|


[Scattered Spider](https://attack.mitre.org/groups/G1015) can enumerate remote systems, such as VMware vCenter infrastructure.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[Scattered Spider](https://attack.mitre.org/groups/G1015) creates new user identities within the compromised organization.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, IaaS, Linux, macOS, Network, Containers, SaaS, Office Suite, Identity Provider|T1136|Create Account|


[Scattered Spider](https://attack.mitre.org/groups/G1015) stages data in a centralized database prior to exfiltration.(Citation: CISA Scattered Spider Advisory November 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Windows, IaaS, Linux, macOS|T1074|Data Staged|


During [C0027](https://attack.mitre.org/campaigns/C0027), [Scattered Spider](https://attack.mitre.org/groups/G1015) used phone calls to instruct victims to navigate to credential-harvesting websites.(Citation: Crowdstrike TELCO BPO Campaign December 2022)

[Scattered Spider](https://attack.mitre.org/groups/G1015) has also called employees at target organizations and compelled them to navigate to fake login portals using adversary-in-the-middle toolkits.(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|PRE|T1598.004|Spearphishing Voice|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has exfiltrated victim data to the MEGA file sharing site.(Citation: CISA Scattered Spider Advisory November 2023)(Citation: MSTIC Octo Tempest Operations October 2023)
|['enterprise-attack']|enterprise-attack, mobile-attack|Linux, macOS, Windows|T1567.002|Exfiltration to Cloud Storage|


[Scattered Spider](https://attack.mitre.org/groups/G1015) has sent SMS phishing messages to employee phone numbers with a link to a site configured with a fake credential harvesting login portal.(Citation: MSTIC Octo Tempest Operations October 2023)
|['mobile-attack']|enterprise-attack, mobile-attack|Android, iOS|T1660|Phishing|

