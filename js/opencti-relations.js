/*
 * Relations autorisées entre types d'entités dans OpenCTI 6.7.7.
 * Fichier généré par tools/gen-relations.py depuis database/stix.ts : ne pas éditer.
 * Clé « Source_Cible » → types de relation possibles (related-to et revoked-by
 * sont toujours autorisés et ne figurent pas ici).
 */
(function (root) {
  'use strict';
  const OD = (root.OD = root.OD || {});
  OD.relationsMapping = { version: '6.7.7', mapping: {
"Administrative-Area_Administrative-Area": [
"derived-from"
],
"Artifact_Artifact": [
"derived-from"
],
"Artifact_Attack-Pattern": [
"uses"
],
"Artifact_Domain-Name": [
"communicates-with"
],
"Artifact_IPv4-Addr": [
"communicates-with"
],
"Artifact_IPv6-Addr": [
"communicates-with"
],
"Artifact_Narrative": [
"uses"
],
"Attack-Pattern_Administrative-Area": [
"targets"
],
"Attack-Pattern_Attack-Pattern": [
"derived-from",
"subtechnique-of"
],
"Attack-Pattern_City": [
"targets"
],
"Attack-Pattern_Country": [
"targets"
],
"Attack-Pattern_Event": [
"targets"
],
"Attack-Pattern_Individual": [
"targets"
],
"Attack-Pattern_Malware": [
"delivers",
"uses"
],
"Attack-Pattern_Organization": [
"targets"
],
"Attack-Pattern_Position": [
"targets"
],
"Attack-Pattern_Region": [
"targets"
],
"Attack-Pattern_Sector": [
"targets"
],
"Attack-Pattern_System": [
"targets"
],
"Attack-Pattern_Tool": [
"uses"
],
"Attack-Pattern_Vulnerability": [
"targets"
],
"Campaign_Administrative-Area": [
"originates-from",
"targets"
],
"Campaign_Attack-Pattern": [
"uses"
],
"Campaign_Campaign": [
"derived-from"
],
"Campaign_Channel": [
"uses"
],
"Campaign_City": [
"originates-from",
"targets"
],
"Campaign_Country": [
"originates-from",
"targets"
],
"Campaign_Event": [
"targets"
],
"Campaign_Individual": [
"targets"
],
"Campaign_Infrastructure": [
"compromises",
"uses"
],
"Campaign_Intrusion-Set": [
"attributed-to"
],
"Campaign_Malware": [
"uses"
],
"Campaign_Narrative": [
"uses"
],
"Campaign_Organization": [
"targets"
],
"Campaign_Position": [
"originates-from",
"targets"
],
"Campaign_Region": [
"originates-from",
"targets"
],
"Campaign_Sector": [
"targets"
],
"Campaign_System": [
"targets"
],
"Campaign_Threat-Actor-Group": [
"attributed-to"
],
"Campaign_Threat-Actor-Individual": [
"attributed-to"
],
"Campaign_Tool": [
"uses"
],
"Campaign_Vulnerability": [
"targets"
],
"Channel_Channel": [
"derived-from"
],
"Channel_Individual": [
"obs_belongs-to"
],
"Channel_Intrusion-Set": [
"obs_belongs-to"
],
"Channel_Organization": [
"obs_belongs-to"
],
"Channel_Threat-Actor-Group": [
"obs_belongs-to"
],
"Channel_Threat-Actor-Individual": [
"obs_belongs-to"
],
"City_Administrative-Area": [
"located-at"
],
"City_City": [
"derived-from"
],
"City_Country": [
"located-at"
],
"City_Region": [
"located-at"
],
"Country_Country": [
"derived-from"
],
"Country_Region": [
"located-at"
],
"Course-Of-Action_Attack-Pattern": [
"mitigates"
],
"Course-Of-Action_Course-Of-Action": [
"derived-from"
],
"Course-Of-Action_Indicator": [
"investigates",
"mitigates"
],
"Course-Of-Action_Malware": [
"mitigates",
"remediates"
],
"Course-Of-Action_Tool": [
"mitigates"
],
"Course-Of-Action_Vulnerability": [
"mitigates",
"remediates"
],
"Domain-Name_Domain-Name": [
"derived-from",
"obs_resolves-to"
],
"Domain-Name_IPv4-Addr": [
"obs_resolves-to"
],
"Domain-Name_IPv6-Addr": [
"obs_resolves-to"
],
"Domain-Name_Individual": [
"obs_belongs-to"
],
"Domain-Name_Narrative": [
"uses"
],
"Domain-Name_Organization": [
"obs_belongs-to"
],
"Event_Event": [
"derived-from"
],
"Hostname_Artifact": [
"drops"
],
"Hostname_Attack-Pattern": [
"uses"
],
"Hostname_Domain-Name": [
"communicates-with"
],
"Hostname_Hostname": [
"derived-from"
],
"Hostname_IPv4-Addr": [
"communicates-with",
"obs_resolves-to"
],
"Hostname_IPv6-Addr": [
"communicates-with",
"obs_resolves-to"
],
"Hostname_StixFile": [
"drops"
],
"IPv4-Addr_Administrative-Area": [
"located-at"
],
"IPv4-Addr_Autonomous-System": [
"obs_belongs-to"
],
"IPv4-Addr_City": [
"located-at"
],
"IPv4-Addr_Country": [
"located-at"
],
"IPv4-Addr_IPv4-Addr": [
"derived-from"
],
"IPv4-Addr_Individual": [
"obs_belongs-to"
],
"IPv4-Addr_Mac-Addr": [
"obs_resolves-to"
],
"IPv4-Addr_Organization": [
"obs_belongs-to"
],
"IPv4-Addr_Position": [
"located-at"
],
"IPv4-Addr_Region": [
"located-at"
],
"IPv6-Addr_Administrative-Area": [
"located-at"
],
"IPv6-Addr_Autonomous-System": [
"obs_belongs-to"
],
"IPv6-Addr_City": [
"located-at"
],
"IPv6-Addr_Country": [
"located-at"
],
"IPv6-Addr_IPv6-Addr": [
"derived-from"
],
"IPv6-Addr_Individual": [
"obs_belongs-to"
],
"IPv6-Addr_Mac-Addr": [
"obs_resolves-to"
],
"IPv6-Addr_Organization": [
"obs_belongs-to"
],
"IPv6-Addr_Position": [
"located-at"
],
"IPv6-Addr_Region": [
"located-at"
],
"Incident_Administrative-Area": [
"originates-from",
"targets"
],
"Incident_Attack-Pattern": [
"uses"
],
"Incident_Campaign": [
"attributed-to"
],
"Incident_Channel": [
"uses"
],
"Incident_City": [
"originates-from",
"targets"
],
"Incident_Country": [
"originates-from",
"targets"
],
"Incident_Event": [
"targets"
],
"Incident_Incident": [
"derived-from"
],
"Incident_Individual": [
"targets"
],
"Incident_Infrastructure": [
"compromises",
"uses"
],
"Incident_Intrusion-Set": [
"attributed-to"
],
"Incident_Malware": [
"uses"
],
"Incident_Narrative": [
"uses"
],
"Incident_Organization": [
"targets"
],
"Incident_Position": [
"originates-from",
"targets"
],
"Incident_Region": [
"originates-from",
"targets"
],
"Incident_Sector": [
"targets"
],
"Incident_System": [
"targets"
],
"Incident_Threat-Actor-Group": [
"attributed-to"
],
"Incident_Threat-Actor-Individual": [
"attributed-to"
],
"Incident_Tool": [
"uses"
],
"Incident_Vulnerability": [
"targets"
],
"Indicator_Artifact": [
"based-on"
],
"Indicator_Attack-Pattern": [
"indicates"
],
"Indicator_Autonomous-System": [
"based-on"
],
"Indicator_Bank-Account": [
"based-on"
],
"Indicator_Campaign": [
"indicates"
],
"Indicator_Credential": [
"based-on"
],
"Indicator_Cryptocurrency-Wallet": [
"based-on"
],
"Indicator_Cryptographic-Key": [
"based-on"
],
"Indicator_Directory": [
"based-on"
],
"Indicator_Domain-Name": [
"based-on"
],
"Indicator_Email-Addr": [
"based-on"
],
"Indicator_Email-Message": [
"based-on"
],
"Indicator_Email-Mime-Part-Type": [
"based-on"
],
"Indicator_Hostname": [
"based-on"
],
"Indicator_IPv4-Addr": [
"based-on"
],
"Indicator_IPv6-Addr": [
"based-on"
],
"Indicator_Incident": [
"indicates"
],
"Indicator_Indicator": [
"derived-from"
],
"Indicator_Infrastructure": [
"indicates"
],
"Indicator_Intrusion-Set": [
"indicates"
],
"Indicator_Mac-Addr": [
"based-on"
],
"Indicator_Malware": [
"indicates"
],
"Indicator_Media-Content": [
"based-on"
],
"Indicator_Mutex": [
"based-on"
],
"Indicator_Network-Traffic": [
"based-on"
],
"Indicator_Observed-Data": [
"based-on"
],
"Indicator_Payment-Card": [
"based-on"
],
"Indicator_Persona": [
"based-on"
],
"Indicator_Phone-Number": [
"based-on"
],
"Indicator_Process": [
"based-on"
],
"Indicator_Software": [
"based-on"
],
"Indicator_StixFile": [
"based-on"
],
"Indicator_Text": [
"based-on"
],
"Indicator_Threat-Actor-Group": [
"indicates"
],
"Indicator_Threat-Actor-Individual": [
"indicates"
],
"Indicator_Tool": [
"indicates"
],
"Indicator_Tracking-Number": [
"based-on"
],
"Indicator_Url": [
"based-on"
],
"Indicator_User-Account": [
"based-on"
],
"Indicator_User-Agent": [
"based-on"
],
"Indicator_Vulnerability": [
"indicates"
],
"Indicator_Windows-Registry-Key": [
"based-on"
],
"Indicator_Windows-Registry-Value-Type": [
"based-on"
],
"Indicator_X509-Certificate": [
"based-on"
],
"Indicator_uses": [
"indicates"
],
"Individual_Administrative-Area": [
"located-at"
],
"Individual_City": [
"located-at"
],
"Individual_Country": [
"located-at"
],
"Individual_Individual": [
"derived-from",
"part-of"
],
"Individual_Media-Content": [
"publishes"
],
"Individual_Organization": [
"part-of"
],
"Individual_Position": [
"located-at"
],
"Individual_Region": [
"located-at"
],
"Infrastructure_Administrative-Area": [
"located-at"
],
"Infrastructure_Artifact": [
"consists-of"
],
"Infrastructure_Attack-Pattern": [
"detects"
],
"Infrastructure_Autonomous-System": [
"consists-of"
],
"Infrastructure_Bank-Account": [
"consists-of"
],
"Infrastructure_City": [
"located-at"
],
"Infrastructure_Country": [
"located-at"
],
"Infrastructure_Credential": [
"consists-of"
],
"Infrastructure_Cryptocurrency-Wallet": [
"consists-of"
],
"Infrastructure_Cryptographic-Key": [
"consists-of"
],
"Infrastructure_Directory": [
"consists-of"
],
"Infrastructure_Domain-Name": [
"communicates-with",
"consists-of"
],
"Infrastructure_Email-Addr": [
"consists-of"
],
"Infrastructure_Email-Message": [
"consists-of"
],
"Infrastructure_Email-Mime-Part-Type": [
"consists-of"
],
"Infrastructure_Hostname": [
"consists-of"
],
"Infrastructure_IPv4-Addr": [
"communicates-with",
"consists-of"
],
"Infrastructure_IPv6-Addr": [
"communicates-with",
"consists-of"
],
"Infrastructure_Infrastructure": [
"communicates-with",
"consists-of",
"controls",
"derived-from",
"uses"
],
"Infrastructure_Mac-Addr": [
"consists-of"
],
"Infrastructure_Malware": [
"controls",
"delivers",
"hosts"
],
"Infrastructure_Media-Content": [
"consists-of"
],
"Infrastructure_Mutex": [
"consists-of"
],
"Infrastructure_Network-Traffic": [
"consists-of"
],
"Infrastructure_Observed-Data": [
"consists-of"
],
"Infrastructure_Payment-Card": [
"consists-of"
],
"Infrastructure_Persona": [
"consists-of"
],
"Infrastructure_Phone-Number": [
"consists-of"
],
"Infrastructure_Position": [
"located-at"
],
"Infrastructure_Process": [
"consists-of"
],
"Infrastructure_Region": [
"located-at"
],
"Infrastructure_Software": [
"consists-of",
"hosts"
],
"Infrastructure_StixFile": [
"consists-of"
],
"Infrastructure_Text": [
"consists-of"
],
"Infrastructure_Tool": [
"hosts"
],
"Infrastructure_Tracking-Number": [
"consists-of"
],
"Infrastructure_Url": [
"communicates-with",
"consists-of"
],
"Infrastructure_User-Account": [
"consists-of"
],
"Infrastructure_User-Agent": [
"consists-of"
],
"Infrastructure_Vulnerability": [
"has"
],
"Infrastructure_Windows-Registry-Key": [
"consists-of"
],
"Infrastructure_Windows-Registry-Value-Type": [
"consists-of"
],
"Infrastructure_X509-Certificate": [
"consists-of"
],
"Intrusion-Set_Administrative-Area": [
"originates-from",
"targets"
],
"Intrusion-Set_Attack-Pattern": [
"uses"
],
"Intrusion-Set_Channel": [
"uses"
],
"Intrusion-Set_City": [
"originates-from",
"targets"
],
"Intrusion-Set_Country": [
"originates-from",
"targets"
],
"Intrusion-Set_Event": [
"targets"
],
"Intrusion-Set_Individual": [
"targets"
],
"Intrusion-Set_Infrastructure": [
"compromises",
"hosts",
"owns",
"uses"
],
"Intrusion-Set_Intrusion-Set": [
"derived-from"
],
"Intrusion-Set_Malware": [
"uses"
],
"Intrusion-Set_Narrative": [
"uses"
],
"Intrusion-Set_Organization": [
"targets"
],
"Intrusion-Set_Position": [
"originates-from",
"targets"
],
"Intrusion-Set_Region": [
"originates-from",
"targets"
],
"Intrusion-Set_Sector": [
"targets"
],
"Intrusion-Set_StixFile": [
"uses"
],
"Intrusion-Set_System": [
"targets"
],
"Intrusion-Set_Threat-Actor-Group": [
"attributed-to"
],
"Intrusion-Set_Threat-Actor-Individual": [
"attributed-to"
],
"Intrusion-Set_Tool": [
"uses"
],
"Intrusion-Set_Vulnerability": [
"targets"
],
"Malware_Administrative-Area": [
"originates-from",
"targets"
],
"Malware_Attack-Pattern": [
"uses"
],
"Malware_City": [
"originates-from",
"targets"
],
"Malware_Country": [
"originates-from",
"targets"
],
"Malware_Domain-Name": [
"communicates-with"
],
"Malware_Event": [
"targets"
],
"Malware_IPv4-Addr": [
"communicates-with"
],
"Malware_IPv6-Addr": [
"communicates-with"
],
"Malware_Individual": [
"targets"
],
"Malware_Infrastructure": [
"beacons-to",
"exfiltrates-to",
"targets",
"uses"
],
"Malware_Intrusion-Set": [
"authored-by"
],
"Malware_Malware": [
"controls",
"derived-from",
"downloads",
"drops",
"uses",
"variant-of"
],
"Malware_Organization": [
"targets"
],
"Malware_Position": [
"originates-from",
"targets"
],
"Malware_Region": [
"originates-from",
"targets"
],
"Malware_Sector": [
"targets"
],
"Malware_StixFile": [
"downloads",
"drops"
],
"Malware_System": [
"targets"
],
"Malware_Threat-Actor-Group": [
"authored-by"
],
"Malware_Threat-Actor-Individual": [
"authored-by"
],
"Malware_Tool": [
"downloads",
"drops",
"uses"
],
"Malware_Url": [
"communicates-with"
],
"Malware_Vulnerability": [
"exploits",
"targets"
],
"Media-Content_Individual": [
"authored-by"
],
"Media-Content_Media-Content": [
"derived-from"
],
"Media-Content_Organization": [
"authored-by"
],
"Media-Content_User-Account": [
"authored-by"
],
"Narrative_Narrative": [
"derived-from"
],
"Organization_Organization": [
"derived-from"
],
"Position_Administrative-Area": [
"located-at"
],
"Position_City": [
"located-at"
],
"Position_Country": [
"located-at"
],
"Position_Position": [
"derived-from"
],
"Position_Region": [
"located-at"
],
"Region_Region": [
"derived-from",
"located-at"
],
"Sector_Administrative-Area": [
"located-at"
],
"Sector_City": [
"located-at"
],
"Sector_Country": [
"located-at"
],
"Sector_Position": [
"located-at"
],
"Sector_Region": [
"located-at"
],
"Sector_Sector": [
"derived-from",
"part-of"
],
"SecurityPlatform_Attack-Pattern": [
"should-cover"
],
"Software_Software": [
"derived-from"
],
"Software_Vulnerability": [
"has",
"remediates"
],
"StixFile_Attack-Pattern": [
"uses"
],
"StixFile_Domain-Name": [
"communicates-with"
],
"StixFile_IPv4-Addr": [
"communicates-with"
],
"StixFile_IPv6-Addr": [
"communicates-with"
],
"StixFile_Narrative": [
"uses"
],
"StixFile_StixFile": [
"derived-from",
"downloads",
"drops"
],
"StixFile_Vulnerability": [
"targets"
],
"System_Administrative-Area": [
"located-at"
],
"System_City": [
"located-at"
],
"System_Country": [
"located-at"
],
"System_Organization": [
"obs_belongs-to"
],
"System_Position": [
"located-at"
],
"System_Region": [
"located-at"
],
"System_System": [
"derived-from"
],
"System_Vulnerability": [
"has"
],
"Text_Narrative": [
"uses"
],
"Text_Text": [
"derived-from"
],
"Threat-Actor-Group_Administrative-Area": [
"located-at",
"targets"
],
"Threat-Actor-Group_Attack-Pattern": [
"uses"
],
"Threat-Actor-Group_Campaign": [
"participates-in"
],
"Threat-Actor-Group_Channel": [
"uses"
],
"Threat-Actor-Group_City": [
"located-at",
"targets"
],
"Threat-Actor-Group_Country": [
"located-at",
"targets"
],
"Threat-Actor-Group_Event": [
"targets"
],
"Threat-Actor-Group_Individual": [
"attributed-to",
"impersonates",
"targets"
],
"Threat-Actor-Group_Infrastructure": [
"compromises",
"hosts",
"owns",
"uses"
],
"Threat-Actor-Group_Malware": [
"uses"
],
"Threat-Actor-Group_Narrative": [
"uses"
],
"Threat-Actor-Group_Organization": [
"attributed-to",
"impersonates",
"targets"
],
"Threat-Actor-Group_Position": [
"located-at",
"targets"
],
"Threat-Actor-Group_Region": [
"located-at",
"targets"
],
"Threat-Actor-Group_Sector": [
"targets"
],
"Threat-Actor-Group_StixFile": [
"uses"
],
"Threat-Actor-Group_System": [
"targets"
],
"Threat-Actor-Group_Threat-Actor-Group": [
"cooperates-with",
"derived-from",
"part-of"
],
"Threat-Actor-Group_Threat-Actor-Individual": [
"cooperates-with",
"derived-from"
],
"Threat-Actor-Group_Tool": [
"uses"
],
"Threat-Actor-Group_Vulnerability": [
"targets"
],
"Threat-Actor-Individual_Administrative-Area": [
"located-at",
"targets"
],
"Threat-Actor-Individual_Attack-Pattern": [
"uses"
],
"Threat-Actor-Individual_Campaign": [
"participates-in"
],
"Threat-Actor-Individual_Channel": [
"uses"
],
"Threat-Actor-Individual_City": [
"located-at",
"targets"
],
"Threat-Actor-Individual_Country": [
"located-at",
"targets"
],
"Threat-Actor-Individual_Event": [
"targets"
],
"Threat-Actor-Individual_Individual": [
"attributed-to",
"impersonates",
"targets"
],
"Threat-Actor-Individual_Infrastructure": [
"compromises",
"hosts",
"owns",
"uses"
],
"Threat-Actor-Individual_Malware": [
"uses"
],
"Threat-Actor-Individual_Narrative": [
"uses"
],
"Threat-Actor-Individual_Organization": [
"attributed-to",
"impersonates",
"targets"
],
"Threat-Actor-Individual_Position": [
"located-at",
"targets"
],
"Threat-Actor-Individual_Region": [
"located-at",
"targets"
],
"Threat-Actor-Individual_Sector": [
"targets"
],
"Threat-Actor-Individual_StixFile": [
"uses"
],
"Threat-Actor-Individual_System": [
"targets"
],
"Threat-Actor-Individual_Tool": [
"uses"
],
"Threat-Actor-Individual_Vulnerability": [
"targets"
],
"Tool_Administrative-Area": [
"targets"
],
"Tool_Attack-Pattern": [
"uses"
],
"Tool_City": [
"targets"
],
"Tool_Country": [
"targets"
],
"Tool_Event": [
"targets"
],
"Tool_Individual": [
"targets"
],
"Tool_Infrastructure": [
"targets",
"uses"
],
"Tool_Malware": [
"delivers",
"drops"
],
"Tool_Organization": [
"targets"
],
"Tool_Position": [
"targets"
],
"Tool_Region": [
"targets"
],
"Tool_Sector": [
"targets"
],
"Tool_System": [
"targets"
],
"Tool_Tool": [
"derived-from"
],
"Tool_Vulnerability": [
"has",
"targets"
],
"Url_Narrative": [
"uses"
],
"Url_Url": [
"derived-from"
],
"User-Account_Media-Content": [
"publishes"
],
"User-Account_User-Account": [
"derived-from"
],
"Vulnerability_Vulnerability": [
"derived-from"
],
"targets_Administrative-Area": [
"located-at"
],
"targets_City": [
"located-at"
],
"targets_Country": [
"located-at"
],
"targets_Position": [
"located-at"
],
"targets_Region": [
"located-at"
]
} };
})(typeof window !== 'undefined' ? window : globalThis);
