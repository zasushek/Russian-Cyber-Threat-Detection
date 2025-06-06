# PowerShell Profile Modification

| MITRE ID  | Tactic                            |
| --------- | --------------------------------- |
| T1546.013 | Privilege Escalation, Persistence |

```spl
index=* (EventCode=11 OR EventCode=13)
(TargetFilename="*PowerShell_profile.ps1" OR TargetFilename="*\\profile.ps1" OR TargetObject="*PowerShell_profile.ps1" OR TargetObject="*\\profile.ps1")
| eval action=case(EventCode=11, "Created", EventCode=13, "Modified", true(), "Other")
| eval suspicious_process=if(match(Image, "(?i)(powershell.exe|cmd.exe|cscript.exe|wscript.exe|mshta.exe|rundll32.exe)"), "YES", "NO")
| eval profile_scope=if(like(TargetFilename, "%System32%"), "SYSTEM", "USER")
| eval suspicious_location=if(like(TargetFilename, "%Temp%") OR like(TargetFilename, "%AppData%"), "YES", "NO")
| eval risk=case(
        suspicious_process="YES" AND profile_scope="SYSTEM", "HIGH",
        suspicious_process="YES", "MODERATE",
        suspicious_location="YES", "MODERATE",
        true(), "LOW"
)
| where risk!="LOW"
| table _time, host, User, Image, TargetFilename, action, suspicious_process, suspicious_location, profile_scope, risk
| sort -_time
```
