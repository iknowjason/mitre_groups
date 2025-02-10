# APT-C-23 - G1028

**Created**: 2024-03-26T18:38:00.759Z

**Modified**: 2024-04-16T15:31:48.747Z

**Contributors**: Sittikorn Sangrattanapitak

## Aliases

APT-C-23,Mantis,Arid Viper,Desert Falcon,TAG-63,Grey Karkadann,Big Bang APT,Two-tailed Scorpion

## Description

[APT-C-23](https://attack.mitre.org/groups/G1028) is a threat group that has been active since at least 2014.(Citation: symantec_mantis) [APT-C-23](https://attack.mitre.org/groups/G1028) has primarily focused its operations on the Middle East, including Israeli military assets. [APT-C-23](https://attack.mitre.org/groups/G1028) has developed mobile spyware targeting Android and iOS devices since 2017.(Citation: welivesecurity_apt-c-23)

## Techniques Used


[APT-C-23](https://attack.mitre.org/groups/G1028) can collect the victim’s phone number, device information, IMSI, etc.(Citation: checkpoint_hamas_android_malware) 
|['mobile-attack']|mobile-attack, enterprise-attack|Android, iOS|T1422|System Network Configuration Discovery|


[APT-C-23](https://attack.mitre.org/groups/G1028) sends malicious links to victims to download the masqueraded application.(Citation: sophos_android_apt_spyware)(Citation: checkpoint_hamas_android_malware) 
|['mobile-attack']|mobile-attack, enterprise-attack|Android, iOS|T1660|Phishing|


[APT-C-23](https://attack.mitre.org/groups/G1028) has masqueraded malware as legitimate applications.(Citation: welivesecurity_apt-c-23)(Citation: checkpoint_hamas_android_malware)(Citation: sophos_android_apt_spyware)
|['mobile-attack']|mobile-attack, enterprise-attack|Android, iOS|T1655.001|Match Legitimate Name or Location|

