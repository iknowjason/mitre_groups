# Mustard Tempest - G1020

**Created**: 2023-12-06T19:00:11.581Z

**Modified**: 2024-03-25T21:23:15.556Z

**Contributors**: 

## Aliases

Mustard Tempest,DEV-0206,TA569,GOLD PRELUDE,UNC1543

## Description

[Mustard Tempest](https://attack.mitre.org/groups/G1020) is an initial access broker that has operated the [SocGholish](https://attack.mitre.org/software/S1124) distribution network since at least 2017. [Mustard Tempest](https://attack.mitre.org/groups/G1020) has partnered with [Indrik Spider](https://attack.mitre.org/groups/G0119) to provide access for the download of additional malware including LockBit, [WastedLocker](https://attack.mitre.org/software/S0612), and remote access tools.(Citation: Microsoft Ransomware as a Service)(Citation: Microsoft Threat Actor Naming July 2023)(Citation: Secureworks Gold Prelude Profile)(Citation: SocGholish-update)

## Techniques Used


[Mustard Tempest](https://attack.mitre.org/groups/G1020) has posted false advertisements including for software packages and browser updates in order to distribute malware.(Citation: Microsoft Ransomware as a Service)
|['enterprise-attack']|enterprise-attack|PRE|T1583.008|Malvertising|


[Mustard Tempest](https://attack.mitre.org/groups/G1020) has hosted payloads on acquired second-stage servers for periods of either days, weeks, or months.(Citation: SentinelOne SocGholish Infrastructure November 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1608.001|Upload Malware|


[Mustard Tempest](https://attack.mitre.org/groups/G1020) has sent victims emails containing links to compromised websites.(Citation: SocGholish-update)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, SaaS, Identity Provider, Office Suite|T1566.002|Spearphishing Link|


[Mustard Tempest](https://attack.mitre.org/groups/G1020) has used the filename `AutoUpdater.js` to mimic legitimate update files and has also used the Cyrillic homoglyph characters С `(0xd0a1)` and а `(0xd0b0)`, to produce the filename `Сhrome.Updаte.zip`.(Citation: Red Canary SocGholish March 2024)(Citation: SocGholish-update)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Containers|T1036.005|Match Legitimate Name or Location|


[Mustard Tempest](https://attack.mitre.org/groups/G1020) operates a global network of compromised websites that redirect into a traffic distribution system (TDS) to select victims for a fake browser update page.(Citation: Secureworks Gold Prelude Profile)(Citation: SocGholish-update)(Citation: SentinelOne SocGholish Infrastructure November 2022)(Citation: Red Canary SocGholish March 2024)
|['enterprise-attack']|enterprise-attack|PRE|T1584.001|Domains|


[Mustard Tempest](https://attack.mitre.org/groups/G1020) has poisoned search engine results to return fake software updates in order to distribute malware.(Citation: Microsoft Ransomware as a Service)(Citation: SocGholish-update)
|['enterprise-attack']|enterprise-attack|PRE|T1608.006|SEO Poisoning|


[Mustard Tempest](https://attack.mitre.org/groups/G1020) has injected malicious JavaScript into compromised websites to infect victims via drive-by download.(Citation: SocGholish-update)(Citation: SentinelOne SocGholish Infrastructure November 2022)(Citation: Red Canary SocGholish March 2024)(Citation: Secureworks Gold Prelude Profile)
|['enterprise-attack']|enterprise-attack|PRE|T1608.004|Drive-by Target|


[Mustard Tempest](https://attack.mitre.org/groups/G1020) has used drive-by downloads for initial infection, often using fake browser updates as a lure.(Citation: SocGholish-update)(Citation: SentinelOne SocGholish Infrastructure November 2022)(Citation: Red Canary SocGholish March 2024)(Citation: Secureworks Gold Prelude Profile)
|['enterprise-attack']|enterprise-attack|Windows, Linux, macOS, Identity Provider|T1189|Drive-by Compromise|


[Mustard Tempest](https://attack.mitre.org/groups/G1020) has deployed secondary payloads and third stage implants to compromised hosts.(Citation: Microsoft Ransomware as a Service)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows, Network|T1105|Ingress Tool Transfer|


[Mustard Tempest](https://attack.mitre.org/groups/G1020) has acquired servers to host second-stage payloads that remain active for a period of either days, weeks, or months.(Citation: SentinelOne SocGholish Infrastructure November 2022)
|['enterprise-attack']|enterprise-attack|PRE|T1583.004|Server|


[Mustard Tempest](https://attack.mitre.org/groups/G1020) has lured users into downloading malware through malicious links in fake advertisements and spearphishing emails.(Citation: Microsoft Ransomware as a Service)(Citation: SocGholish-update)
|['enterprise-attack']|enterprise-attack|Linux, macOS, Windows|T1204.001|Malicious Link|


[Mustard Tempest](https://attack.mitre.org/groups/G1020) has used implants to perform system reconnaissance on targeted systems.(Citation: Microsoft Ransomware as a Service)
|['enterprise-attack']|enterprise-attack|Windows, IaaS, Linux, macOS, Network|T1082|System Information Discovery|

