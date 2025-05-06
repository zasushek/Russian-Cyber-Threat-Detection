# Threat Profile

Four Russian hacking groups, deemed the most significant in our assessment, were selected for further analysis and threat profiling. These groups are currently active, target various sectors, and possess substantial resources due to their (likely) government funding.

Selected groups:

- [G0007 - APT28](https://attack.mitre.org/groups/G0007/)
- [G0016 - APT29](https://attack.mitre.org/groups/G0016/)
- [G0034 - APT44](https://attack.mitre.org/groups/G0034/)
- [G0010 - Turla](https://attack.mitre.org/groups/G0010/)

## APT28

**Aliases:** Sofacy, Fancy Bear, STRONTIUM, Sednit

1. **Motivation:**
   APT28 is a Russian cyberthreat group associated with the GRU military intelligence (Unit 26165). Operational since at least 2004, it conducts cyberespionage campaigns targeting governments, military entities, and international organizations (e.g., NATO).
2. **Technical Capabilities:**
   APT28 frequently employs spearphishing (emails with malicious Office documents or links) as an initial attack vector. Subsequent tactics include credential dumping from memory (e.g., LSASS via Mimikatz or custom implants), network scanning, and reconnaissance (e.g., living off the land using Windows net commands and PowerShell). The group’s arsenal includes custom malware, such as the CHOPSTICK/X-Agent trojan family for remote control and data theft, ADVSTORESHELL/CORESHELL backdoors, Zebrocy (a modular malware suite used in spearphishing), and LoJax, the first known UEFI-targeting malware for persistent infection. APT28 also misuses legitimate administrative tools (e.g., PowerShell, certutil.exe for decoding/downloads, PsExec/Scheduled Tasks for lateral movement). Historically, it has leveraged open-source frameworks like Metasploit/Koadic (e.g., for DDE code injection) and network sniffing tools (e.g., Responder for NTLM hash capture).
3. **Notable Campaigns:**
   - U.S. election hack (2016)
   - Attacks on anti-doping organizations (2017–2018)
   - Operation “Nearest Neighbor” (2020)
   - Campaigns targeting Ukraine and Georgia (2014–2022)
4. **Threat Assessment:**
   APT28 poses a direct, high-level threat to government, military, and geopolitically significant organizations. Its motivations include cyberespionage and influencing geopolitical processes, with intentions encompassing sensitive data theft and potential leaks for disinformation. APT28’s technical capabilities are advanced, demonstrated by custom malware development (e.g., LoJax rootkit, droppers, trojans) and zero-day exploit usage. Its consistent activity over decades and successful attacks against high-security targets (e.g., DNC, MS Office 365 phishing campaigns) underscore its potency.

## APT29

**Aliases:** Cozy Bear, The Dukes, NOBELIUM

1. **Motivation:**
   APT29 is an elite Russian APT group linked to the Foreign Intelligence Service (SVR). Active since at least 2008, it is known for sophisticated cyberespionage campaigns targeting government institutions (especially foreign ministries), international organizations, and NATO-aligned research/academic sectors.
2. **Technical Capabilities:**
   APT29 employs techniques similar to APT28 but emphasizes cloud service attacks and advanced detection evasion. Spearphishing (often via malicious links) is a common initial vector, followed by extensive PowerShell use for post-exploitation. APT29 is renowned for its Duke malware family (e.g., MiniDuke, CozyDuke, CloudDuke, CosmicDuke, FatDuke) deployed across attack phases. In the SolarWinds attack, it introduced SUNBURST, TEARDROP, and Raindrop backdoors. Its arsenal includes FoggyWeb (an AD FS server backdoor) and open-source tools like Cobalt Strike (used in later SolarWinds stages). APT29 employs Mimikatz for credential dumping, AdFind and BloodHound for enumeration, and custom tools for manipulating Azure/Office 365 environments (e.g., AADInternals scripts). The group excels at covering tracks, removing tools, and disabling logging (e.g., Auditpol) to evade detection.
3. **Notable Campaigns:**
   - SolarWinds operation (2020)
   - Healthcare sector attacks (2020)
   - Operation Ghost (2019)
   - Breaches of think tanks and foreign ministries (2016–2021)
4. **Threat Assessment:**
   APT29 represents a direct, high-priority threat to government, diplomatic, defense, and strategically valuable sectors (e.g., energy, pharmaceuticals). Its advanced technical capabilities enable it to bypass robust defenses (e.g., supply chain attacks, sophisticated backdoors) and operate covertly for extended periods. APT29’s state-sponsored cyberespionage focuses on high-value intelligence targets, avoiding indiscriminate ransomware attacks.

## APT44

**Aliases:** Sandworm Team, Quedagh, BlackEnergy, Voodoo Bear, Telebots

1. **Motivation:**
   APT44, widely known as Sandworm Team, is a highly destructive Russian APT group tied to GRU military intelligence. Active since at least 2009, it is notorious for sabotage-focused cyberattacks, primarily targeting Ukraine and Western institutions.
2. **Technical Capabilities:**
   APT44 specializes in wiper malware and industrial control system (ICS) tools. Its prominent tools include BlackEnergy, Industroyer/CrashOverride, and NotPetya. It also uses Mimikatz for credential theft (e.g., in NotPetya), custom PowerShell scripts for malware propagation (e.g., TankTrap), backdoor implants (e.g., Exaramel, derived from Industroyer), and Metasploit for DLL injection during privilege escalation. APT44 frequently uses living-off-the-land techniques, including PsExec for distributing KillDisk (2015) and Windows tools (schtasks, net use) for lateral movement in energy sector attacks (2016).
3. **Notable Campaigns:**
   - BlackEnergy (Ukraine, 2015)
   - CrashOverride (Ukraine, 2016)
   - NotPetya (June 2017)
   - Olympic Destroyer (2018)
4. **Threat Assessment:**
   APT44/Sandworm is among the most dangerous threats (high priority), particularly for critical infrastructure sectors (energy, transportation, communications) and in the context of Russia-related conflicts. Its intentions extend beyond espionage to large-scale system destruction and service disruption for military or political sabotage. Sandworm’s technical expertise in niche areas (ICS, IoT) is unmatched, with unparalleled experience in energy grid attacks.

## Turla

**Aliases:** Venomous Bear, Snake, IRON HUNTER

1. **Motivation:**
   Turla is a long-standing Russian APT group linked to the Federal Security Service (FSB). Active since at least 2004, it has targeted over 50 countries, specializing in targeted cyberespionage against government, diplomatic (embassies, foreign ministries), research, and military entities.
2. **Technical Capabilities:**
   Turla is known for unique, self-developed malware, including Snake (Uroburos), ComRAT (Agent.BTZ variant), and Carbon (Cobra). Beyond its proprietary tools, Turla uses Meterpreter (Metasploit) for DLL injection, Mimikatz, and Responder for network sniffing. A distinctive tactic is “piggybacking,” where Turla hijacks other APTs’ infrastructure. For example, in 2018, it repurposed servers from Iran’s OilRig (APT34) for its modified malware. Turla’s techniques prioritize stealth: its malware often operates in memory (fileless), communication is tunneled via legitimate services (OneDrive, Gmail), and modular components (e.g., file theft, keylogging) complicate analysis. Turla sustains infections for years, updating tools to remain undetected.
3. **Notable Campaigns:**
   - Epic Turla (2014)
   - Satellite attacks (2007–2015)
   - WhiteBear (2016–2017)
   - Poisoned Watering Holes (2019)
   - Crutch (2020)
4. **Threat Assessment:**
   Turla poses a direct, high-level threat to government, diplomatic, and military sectors with information critical to Russian security. Its purely intelligence-driven motives focus on acquiring sensitive data, not destruction. Turla’s technical capabilities, particularly in evasion and custom malware, are exceptional. Its ability to conduct covert, long-term operations with unique tools makes it a formidable adversary.
