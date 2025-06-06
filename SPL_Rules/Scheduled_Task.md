# Scheduled Task

| MITRE ID  | Tactic                                       |
| --------- | -------------------------------------------- |
| T1053.005 | Execution, Persistence, Privilege Escalation |

```spl
(
  index=* EventCode=1
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\at.exe")
  (CommandLine="*schtasks*" OR CommandLine="*Register-ScheduledTask*" OR CommandLine="*New-ScheduledTask*" OR CommandLine="*/create*" OR CommandLine="*/change*")
)
| eval is_suspicious_path=if(match(CommandLine, "(AppData|Temp|Downloads|Users\\\\Public|ProgramData)"), "YES", "NO")
| eval is_suspicious_exec=if(match(CommandLine, "(.ps1|.cmd|.vbs|.bat|.exe|.js|.py|powershell|cmd|mshta|cscript|regsvr32|rundll32|wmic|certutil|bitsadmin|javaw)"), "YES", "NO")
| eval suspicious_parent=if(lower(ParentImage) LIKE "%svchost.exe" OR lower(ParentImage) LIKE "%taskeng.exe", "YES", "NO")
| where is_suspicious_path="YES" OR is_suspicious_exec="YES" OR suspicious_parent="YES"
| table _time, host, User, Image, ParentImage, CommandLine, is_suspicious_path, is_suspicious_exec, suspicious_parent
| sort -_time
```
