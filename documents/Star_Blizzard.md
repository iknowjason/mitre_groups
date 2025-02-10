# Star Blizzard - G1033

**Created**: 2024-06-14T18:17:18.727Z

**Modified**: 2024-06-14T18:39:26.684Z

**Contributors**: Aung Kyaw Min Naing, @Nolan

## Aliases

Star Blizzard,SEABORGIUM,Callisto Group,TA446,COLDRIVER

## Description

[Star Blizzard](https://attack.mitre.org/groups/G1033) is a cyber espionage and influence group originating in Russia that has been active since at least 2019. [Star Blizzard](https://attack.mitre.org/groups/G1033) campaigns align closely with Russian state interests and have included persistent phishing and credential theft against academic, defense, government, NGO, and think tank organizations in NATO countries, particularly the US and the UK.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023)(Citation: StarBlizzard)(Citation: Google TAG COLDRIVER January 2024)


## Techniques Used


[Star Blizzard](https://attack.mitre.org/groups/G1033) has registered domains using randomized words and with names resembling legitimate organizations.(Citation: CISA Star Blizzard Advisory December 2023)(Citation: StarBlizzard) 
|['enterprise-attack']|enterprise-attack|PRE|T1583.001|Domains|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has bypassed multi-factor authentication on victim email accounts by using session cookies stolen using EvilGinx.(Citation: CISA Star Blizzard Advisory December 2023)
|['enterprise-attack']|enterprise-attack|SaaS, IaaS, Office Suite|T1550.004|Web Session Cookie|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has remotely accessed victims' email accounts to steal messages and attachments.(Citation: CISA Star Blizzard Advisory December 2023)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1114.002|Remote Email Collection|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has identified ways to engage targets by researching potential victims' interests and social or professional contacts.(Citation: CISA Star Blizzard Advisory December 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1589|Gather Victim Identity Information|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has sent emails with malicious .pdf files to spread malware.(Citation: Google TAG COLDRIVER January 2024)
|['enterprise-attack']|enterprise-attack|macOS, Windows, Linux|T1566.001|Spearphishing Attachment|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has registered impersonation email accounts to spoof experts in a particular field or individuals and organizations affiliated with the intended target.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023)(Citation: Google TAG COLDRIVER January 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1585.002|Email Accounts|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has used EvilGinx to steal the session cookies of victims directed to
 phishing domains.(Citation: CISA Star Blizzard Advisory December 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Office Suite|T1539|Steal Web Session Cookie|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has uploaded malicious payloads to cloud storage sites.(Citation: Google TAG COLDRIVER January 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1608.001|Upload Malware|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has lured targets into opening malicious .pdf files to deliver malware.(Citation: Google TAG COLDRIVER January 2024)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.002|Malicious File|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has sent emails to establish rapport with targets eventually sending messages with links to credential-stealing sites.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023)(Citation: StarBlizzard)(Citation: Google TAG COLDRIVER January 2024)

|['enterprise-attack']|enterprise-attack|PRE|T1598.003|Spearphishing Link|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has incorporated the open-source EvilGinx framework into their spearphishing activity.(Citation: CISA Star Blizzard Advisory December 2023)(Citation: StarBlizzard) 
|['enterprise-attack']|enterprise-attack|PRE|T1588.002|Tool|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has sent emails to establish rapport with targets eventually sending messages with attachments containing links to credential-stealing sites.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023)(Citation: StarBlizzard)(Citation: Google TAG COLDRIVER January 2024)

|['enterprise-attack']|enterprise-attack|PRE|T1598.002|Spearphishing Attachment|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has used compromised email accounts to conduct spearphishing against
 contacts of the original victim.(Citation: CISA Star Blizzard Advisory December 2023)

|['enterprise-attack']|enterprise-attack|PRE|T1586.002|Email Accounts|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has used stolen credentials to sign into victim email accounts.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023) 
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has established fraudulent profiles on professional networking sites to conduct reconnaissance.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1585.001|Social Media Accounts|



[Star Blizzard](https://attack.mitre.org/groups/G1033) has used open-source research to identify information about victims to use in targeting.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023)
|['enterprise-attack']|enterprise-attack|PRE|T1593|Search Open Websites/Domains|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has used JavaScript to redirect victim traffic from an adversary controlled server to a server hosting the Evilginx phishing framework.(Citation: StarBlizzard) 
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux|T1059.007|JavaScript|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has used HubSpot and MailerLite marketing platform services to hide the true sender of phishing emails.(Citation: StarBlizzard) 
|['enterprise-attack']|enterprise-attack|PRE|T1583|Acquire Infrastructure|


[Star Blizzard](https://attack.mitre.org/groups/G1033) has abused email forwarding rules to monitor the activities of a victim, steal information, and maintain persistent access after compromised credentials are reset.(Citation: Microsoft Star Blizzard August 2022)(Citation: CISA Star Blizzard Advisory December 2023)
|['enterprise-attack']|enterprise-attack|Windows, macOS, Linux, Office Suite|T1114.003|Email Forwarding Rule|

