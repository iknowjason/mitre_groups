# Akira - G1024

**Created**: 2024-02-20T23:59:25.966Z

**Modified**: 2024-10-03T10:32:50.221Z

**Contributors**: 

## Aliases

Akira,GOLD SAHARA,PUNK SPIDER

## Description

[Akira](https://attack.mitre.org/groups/G1024) is a ransomware variant and ransomware deployment entity active since at least March 2023.(Citation: Arctic Wolf Akira 2023) [Akira](https://attack.mitre.org/groups/G1024) uses compromised credentials to access single-factor external access mechanisms such as VPNs for initial access, then various publicly-available tools and techniques for lateral movement.(Citation: Arctic Wolf Akira 2023)(Citation: Secureworks GOLD SAHARA) [Akira](https://attack.mitre.org/groups/G1024) operations are associated with "double extortion" ransomware activity, where data is exfiltrated from victim environments prior to encryption, with threats to publish files if a ransom is not paid. Technical analysis of [Akira](https://attack.mitre.org/software/S1129) ransomware indicates multiple overlaps with and similarities to [Conti](https://attack.mitre.org/software/S0575) malware.(Citation: BushidoToken Akira 2023)

## Techniques Used


[Akira](https://attack.mitre.org/groups/G1024) will exfiltrate victim data using applications such as [Rclone](https://attack.mitre.org/software/S1040).(Citation: Secureworks GOLD SAHARA)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1567.002|Exfiltration to Cloud Storage|


[Akira](https://attack.mitre.org/groups/G1024) has accessed and downloaded information stored in SharePoint instances as part of data gathering and exfiltration activity.(Citation: Secureworks GOLD SAHARA)
|['enterprise-attack']|enterprise-attack|Windows, Office Suite|T1213.002|Sharepoint|


[Akira](https://attack.mitre.org/groups/G1024) deletes administrator accounts in victim networks prior to encryption.(Citation: Secureworks GOLD SAHARA)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, IaaS, Office Suite|T1531|Account Access Removal|


[Akira](https://attack.mitre.org/groups/G1024) uses the built-in [Nltest](https://attack.mitre.org/software/S0359) utility or tools such as [AdFind](https://attack.mitre.org/software/S0552) to enumerate Active Directory trusts in victim environments.(Citation: Arctic Wolf Akira 2023) 
|['enterprise-attack']|enterprise-attack|Windows|T1482|Domain Trust Discovery|


[Akira](https://attack.mitre.org/groups/G1024) engages in double-extortion ransomware, exfiltrating files then encrypting them, in order to prompt victims to pay a ransom.(Citation: BushidoToken Akira 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Office Suite|T1657|Financial Theft|


[Akira](https://attack.mitre.org/groups/G1024) uses valid account information to remotely access victim networks, such as VPN credentials.(Citation: Secureworks GOLD SAHARA)(Citation: Arctic Wolf Akira 2023)
|['enterprise-attack']|enterprise-attack|Windows, SaaS, IaaS, Linux, macOS, Containers, Network, Office Suite, Identity Provider|T1078|Valid Accounts|


[Akira](https://attack.mitre.org/groups/G1024) uses software such as Advanced IP Scanner and MASSCAN to identify remote hosts within victim networks.(Citation: Arctic Wolf Akira 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1018|Remote System Discovery|


[Akira](https://attack.mitre.org/groups/G1024) encrypts files in victim environments as part of ransomware operations.(Citation: BushidoToken Akira 2023)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, IaaS|T1486|Data Encrypted for Impact|


[Akira](https://attack.mitre.org/groups/G1024) uses legitimate utilities such as AnyDesk and PuTTy for maintaining remote access to victim environments.(Citation: Secureworks GOLD SAHARA)(Citation: Arctic Wolf Akira 2023)
|['enterprise-attack']|enterprise-attack|Linux, Windows, macOS|T1219|Remote Access Software|


[Akira](https://attack.mitre.org/groups/G1024) uses utilities such as WinRAR to archive data prior to exfiltration.(Citation: Secureworks GOLD SAHARA)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1560.001|Archive via Utility|


[Akira](https://attack.mitre.org/groups/G1024) uses compromised VPN accounts for initial access to victim networks.(Citation: Secureworks GOLD SAHARA)
|['enterprise-attack']|enterprise-attack|Windows, Linux, Containers, macOS|T1133|External Remote Services|

