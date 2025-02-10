# CURIUM - G1012

**Created**: 2023-01-13T20:51:13.494Z

**Modified**: 2024-10-02T12:13:42.278Z

**Contributors**: Denise Tan,Wirapong Petshagun

## Aliases

CURIUM,Crimson Sandstorm,TA456,Tortoise Shell,Yellow Liderc

## Description

[CURIUM](https://attack.mitre.org/groups/G1012) is an Iranian threat group, first reported in September 2019 and active since at least July 2018, targeting IT service providers in the Middle East.(Citation: Symantec Tortoiseshell 2019) [CURIUM](https://attack.mitre.org/groups/G1012) has since invested in building relationships with potential targets via social media over a period of months to establish trust and confidence before sending malware. Security researchers note [CURIUM](https://attack.mitre.org/groups/G1012) has demonstrated great patience and persistence by chatting with potential targets daily and sending benign files to help lower their security consciousness.(Citation: Microsoft Iranian Threat Actor Trends November 2021)

## Techniques Used


[CURIUM](https://attack.mitre.org/groups/G1012) has used social media to deliver malicious files to victims.(Citation: Microsoft Iranian Threat Actor Trends November 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1566.003|Spearphishing via Service|


[CURIUM](https://attack.mitre.org/groups/G1012) has been linked to web shells following likely server compromise as an initial access vector into victim networks.(Citation: Symantec Tortoiseshell 2019)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS, Network|T1505.003|Web Shell|


[CURIUM](https://attack.mitre.org/groups/G1012) has lured users into opening malicious files delivered via social media.(Citation: Microsoft Iranian Threat Actor Trends November 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[CURIUM](https://attack.mitre.org/groups/G1012) has established a network of fictitious social media accounts, including on Facebook and LinkedIn, to establish relationships with victims, often posing as an attractive woman.(Citation: Microsoft Iranian Threat Actor Trends November 2021)
|['enterprise-attack']|enterprise-attack|PRE|T1585.001|Social Media Accounts|


[CURIUM](https://attack.mitre.org/groups/G1012) has exfiltrated data from a compromised machine.(Citation: Microsoft Iranian Threat Actor Trends November 2021)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1005|Data from Local System|


[CURIUM](https://attack.mitre.org/groups/G1012) used strategic website compromise to fingerprint then target victims.(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1608.004|Drive-by Target|


[CURIUM](https://attack.mitre.org/groups/G1012) has used SMTPS to exfiltrate collected data from victims.(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1048.002|Exfiltration Over Asymmetric Encrypted Non-C2 Protocol|


[CURIUM](https://attack.mitre.org/groups/G1012) has created dedicated email accounts for use with tools such as [IMAPLoader](https://attack.mitre.org/software/S1152).(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1585.002|Email Accounts|


[CURIUM](https://attack.mitre.org/groups/G1012) deployed mechanisms to check system time information following strategic website compromise attacks.(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|Windows, Network, Linux, macOS|T1124|System Time Discovery|


[CURIUM](https://attack.mitre.org/groups/G1012) has compromised legitimate websites to enable strategic website compromise attacks.(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1584.006|Web Services|


[CURIUM](https://attack.mitre.org/groups/G1012) created virtual private server instances to facilitate use of malicious domains and other items.(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1583.003|Virtual Private Server|


[CURIUM](https://attack.mitre.org/groups/G1012) deploys information gathering tools focused on capturing IP configuration, running application, system information, and network connectivity information.(Citation: Symantec Tortoiseshell 2019)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|


[CURIUM](https://attack.mitre.org/groups/G1012) has used strategic website compromise to infect victims with malware such as [IMAPLoader](https://attack.mitre.org/software/S1152).(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, Identity Provider|T1189|Drive-by Compromise|


[CURIUM](https://attack.mitre.org/groups/G1012) used malicious links to adversary-controlled resources for credential harvesting.(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1598.003|Spearphishing Link|


[CURIUM](https://attack.mitre.org/groups/G1012) has used IMAP and SMTPS for exfiltration via tools such as [IMAPLoader](https://attack.mitre.org/software/S1152).(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1041|Exfiltration Over C2 Channel|


[CURIUM](https://attack.mitre.org/groups/G1012) created domains to facilitate strategic website compromise and credential capture activities.(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1583.001|Domains|


[CURIUM](https://attack.mitre.org/groups/G1012) has created dedicated servers for command and control and exfiltration purposes.(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1583.004|Server|


[CURIUM](https://attack.mitre.org/groups/G1012) has leveraged PowerShell scripts for initial process execution and data gathering in victim environments.(Citation: Symantec Tortoiseshell 2019)
|['enterprise-attack']|enterprise-attack|Windows|T1059.001|PowerShell|


[CURIUM](https://attack.mitre.org/groups/G1012) has used phishing with malicious attachments for initial access to victim environments.(Citation: PWC Yellow Liderc 2023)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|

