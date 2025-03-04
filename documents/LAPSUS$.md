# LAPSUS$ - G1004

**Created**: 2022-06-09T19:14:31.327Z

**Modified**: 2024-01-11T21:51:11.405Z

**Contributors**: David Hughes, BT Security,Matt Brenton, Zurich Insurance Group,Flavio Costa, Cisco,Caio Silva

## Aliases

LAPSUS$,DEV-0537,Strawberry Tempest

## Description

[LAPSUS$](https://attack.mitre.org/groups/G1004) is cyber criminal threat group that has been active since at least mid-2021. [LAPSUS$](https://attack.mitre.org/groups/G1004) specializes in large-scale social engineering and extortion operations, including destructive attacks without the use of ransomware. The group has targeted organizations globally, including in the government, manufacturing, higher education, energy, healthcare, technology, telecommunications, and media sectors.(Citation: BBC LAPSUS Apr 2022)(Citation: MSTIC DEV-0537 Mar 2022)(Citation: UNIT 42 LAPSUS Mar 2022)

## Techniques Used


[LAPSUS$](https://attack.mitre.org/groups/G1004) has obtained tools such as RVTools and AD Explorer for their operations.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has gathered detailed information of target employees to enhance their social engineering lures.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1589|Gather Victim Identity Information|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has searched a victim's network for collaboration platforms like Confluence and JIRA to discover further high-privilege account credentials.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|SaaS|T1213.001|Confluence|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has used the AD Explorer tool to enumerate groups on a victim's network.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1069.002|Domain Groups|


[LAPSUS$](https://attack.mitre.org/groups/G1004) uploaded sensitive files, information, and credentials from a targeted organization for extortion or public release.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has searched a victim's network for code repositories like GitLab and GitHub to discover further high-privilege account credentials.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|SaaS|T1213.003|Code Repositories|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has deleted the target's systems and resources both on-premises and in the cloud.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Containers|T1485|Data Destruction|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has gathered detailed knowledge of team structures within a target organization.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1591.004|Identify Roles|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has used VPS hosting providers for infrastructure.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1583.003|Virtual Private Server|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has leverage NordVPN for its egress points when targeting intended victims.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1090|Proxy|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has searched a victim's network for collaboration platforms like SharePoint to discover further high-privilege account credentials.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1213.002|Sharepoint|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has searched public code repositories for exposed credentials.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1593.003|Code Repositories|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has created global admin accounts in the targeted organization's cloud instances to gain persistence.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|IaaS, SaaS, Office Suite, Identity Provider|T1136.003|Cloud Account|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has shut down virtual machines from within a victim's on-premise VMware ESXi infrastructure.(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS|T1489|Service Stop|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has deleted the target's systems and resources in the cloud to trigger the organization's incident and crisis response process.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|IaaS|T1578.003|Delete Cloud Instance|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has gathered detailed knowledge of an organization's supply chain relationships.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1591.002|Business Relationships|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has set an Office 365 tenant level mail transport rule to send all mail in and out of the targeted organization to the newly created account.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Office Suite|T1114.003|Email Forwarding Rule|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has used the AD Explorer tool to enumerate users on a victim's network.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1087.002|Domain Account|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has used compromised credentials and/or session tokens to gain access into a victim's VPN, VDI, RDP, and IAMs.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has gained access to internet-facing systems and applications, including virtual private network (VPN), remote desktop protocol (RDP), and virtual desktop infrastructure (VDI) including Citrix. (Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has called victims' help desk to convince the support personnel to reset a privileged account’s credentials.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1598.004|Spearphishing Voice|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has targeted various collaboration tools like Slack, Teams, JIRA, Confluence, and others to hunt for exposed credentials to support privilege escalation and lateral movement.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|SaaS, Office Suite|T1552.008|Chat Messages|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has recruited target organization employees or contractors who provide credentials and approve an associated MFA prompt, or install remote management software onto a corporate workstation, allowing [LAPSUS$](https://attack.mitre.org/groups/G1004) to take control of an authenticated system.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, IaaS, Containers|T1204|User Execution|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has called victims' help desk and impersonated legitimate users with previously gathered information in order to gain access to privileged accounts.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Office Suite|T1656|Impersonation|


[LAPSUS$](https://attack.mitre.org/groups/G1004) acquired and used the Redline password stealer in their operations.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1588.001|Malware|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has spammed target users with MFA prompts in the hope that the legitimate user will grant necessary approval.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, IaaS, SaaS, Office Suite, Identity Provider|T1621|Multi-Factor Authentication Request Generation|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has payed employees, suppliers, and business partners of target organizations for credentials.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1586.002|Email Accounts|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has used DCSync attacks to gather credentials for privilege escalation routines.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1003.006|DCSync|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has gathered employee email addresses, including personal accounts, for social engineering and initial access efforts.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1589.002|Email Addresses|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has searched a victim's network for organization collaboration channels like MS Teams or Slack to discover further high-privilege account credentials.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|SaaS, Office Suite|T1213.005|Messaging Applications|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has added the global admin role to accounts they have created in the targeted organization's cloud instances.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|IaaS, SaaS, Office Suite, Identity Provider|T1098.003|Additional Cloud Roles|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has gathered user identities and credentials to gain initial access to a victim's organization; the group has also called an organization's help desk to reset a target's credentials.(Citation: MSTIC DEV-0537 Mar 2022)(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1589.001|Credentials|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has removed a targeted organization's global admin accounts to lock the organization out of all access.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, IaaS, Office Suite|T1531|Account Access Removal|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has exploited unpatched vulnerabilities on internally accessible servers including JIRA, GitLab, and Confluence for privilege escalation.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1068|Exploitation for Privilege Escalation|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has obtained passwords and session tokens with the use of the Redline password stealer.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1555.003|Credentials from Web Browsers|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has used compromised credentials to access cloud assets within a target organization.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|SaaS, IaaS, Office Suite, Identity Provider|T1078.004|Cloud Accounts|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has created new virtual machines within the target's cloud environment after leveraging credential access to cloud assets.(Citation: MSTIC DEV-0537 Mar 2022) 
|['enterprise-attack']|enterprise-attack|IaaS|T1578.002|Create Cloud Instance|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has purchased credentials and session tokens from criminal underground forums.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1597.002|Purchase Technical Data|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has replayed stolen session token and passwords to trigger simple-approval MFA prompts in hope of the legitimate user will grant necessary approval.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1111|Multi-Factor Authentication Interception|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has used Windows built-in tool `ntdsutil` to extract the Active Directory (AD) database.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Windows|T1003.003|NTDS|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has reconfigured a victim's DNS records to actor-controlled domains and websites.(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1584.002|DNS Server|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has accessed local password managers and databases to obtain further credentials from a compromised network.(Citation: NCC Group LAPSUS Apr 2022)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1555.005|Password Managers|


[LAPSUS$](https://attack.mitre.org/groups/G1004) has accessed internet-facing identity providers such as Azure Active Directory and Okta to target specific organizations.(Citation: MSTIC DEV-0537 Mar 2022)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Identity Provider, Office Suite|T1199|Trusted Relationship|

