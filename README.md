# 🛡️ SPL Detection Rules for Russian APT Groups

This repository contains a curated set of **test detection rules written in Splunk Processing Language (SPL)**, aimed at identifying the TTPs (Tactics, Techniques, and Procedures) associated with prominent **Russian APT groups**.

> ⚠️ **Disclaimer**: These are experimental rules created for educational and research purposes. All detection methods were developed and evaluated in a controlled virtual lab environment.

---

## 🎯 Targeted Threat Groups

The rules are based on threat intelligence and behaviors attributed to the following Russian state-sponsored APT groups:

- **APT28 (Fancy Bear)**  
  Known for credential harvesting and spear-phishing attacks.

- **APT29 (Cozy Bear)**  
  Focuses on stealthy, long-term espionage operations.

- **APT44 (Sandworm Team)**  
  Associated with disruptive cyberattacks and malware such as NotPetya.

- **Turla (Snake Group)**  
  Renowned for sophisticated backdoors and satellite-based C2.

---

## 🧪 Project Scope

- ✅ Creation of SPL-based detection rules for known TTPs
- ✅ Mapping detections to **MITRE ATT&CK** framework
- ✅ Deployment and testing in a virtual environment
- ✅ Use of synthetic logs and simulated APT behavior using tools like **Atomic Red Team**

---

## 👥 Authors

|                 [<img src="https://github.com/zasushek.png?size=100" width="100"/>](https://github.com/zasushek)                 |                 [<img src="https://github.com/Adamcalkins.png?size=100" width="100"/>](https://github.com/Adamcalkins)                 |
| :------------------------------------------------------------------------------------------------------------------------------: | :------------------------------------------------------------------------------------------------------------------------------------: |
| **[zasushek](https://github.com/zasushek)**<br/>Cybersecurity Enthusiast and Master's Student<br/>Threat Detection & Red Teaming | **[Adamcalkins](https://github.com/Adamcalkins)**<br/>Cybersecurity Enthusiast and Master's Student<br/>Threat Detection & Red Teaming |

---

## 📁 Project Structure

```
├── SPL_Rules/                      # Folder with all SPL detection rules
│   ├── Abusing_Accessibility_Features.md
│   ├── Adding_Program_to_Startup_Folder.md
│   ├── Archive_Collected_Data_Archive_via_Utility.md
│   ├── Checking_Group_Policies_and_Permissions.md
│   ├── Clearing_Logs_with_Wevtutil.md
│   ├── Command_and_Scripting_Interpreter_Visual_Basic.md
│   ├── Disabling_Security_Related_Services_Windows_Defender.md
│   ├── PowerShell_Profile_Modification.md
│   ├── Recording_or_Taking_Screenshots.md
│   ├── Scheduled_Task.md
│   ├── Suspicious_Certutil_Use.md
│   ├── Suspicious_Use_Of_CMD_For_Command_Execution.md
│   ├── Suspicious_Use_of_Net_Function.md
│   ├── Suspicious_WMI_Use.md
│   ├── Using_PowerShell_for_Script_Execution.md
│   ├── Using_Registry_Commands_For_Information_Gathering.md
│
├── Threat_Profile_PL.md           # Polish-language threat profile (APT-focused)
├── Threat_Profile.md              # English-language threat profile
├── LICENSE                        # Licensing information
└── README.md                      # Project overview and documentation
```

---

## 🧠 Tech Stack

- **Splunk** for detection rule development and search
- **Sysmon** and **Windows Event Logs** as primary data sources
- **Atomic Red Team** to simulate APT techniques
- **MITRE ATT&CK Navigator** for mapping techniques to coverage

---

> 🔐 _Securing the world, one rule at a time._
