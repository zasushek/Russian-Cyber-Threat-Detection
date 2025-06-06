# Adding Program to Startup Folder

| MITRE ID  | Tactic                            |
| --------- | --------------------------------- |
| T1547.001 | Persistence, Privilege Escalation |

```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 
(TargetObject="*\\User Shell Folders\\Startup*" 
 OR TargetObject="*\\CurrentVersion\\Run*" 
 OR TargetObject="*\\CurrentVersion\\RunOnce*")
| eval is_suspicious_path=if(like(Details, "%AppData%") OR like(Details, "%Temp%") OR like(Details, "%\\Public\\%"), "YES", "NO")
| where lower(Image) like "%powershell.exe" OR lower(Image) like "%cmd.exe" OR lower(Image) like "%reg.exe" OR lower(Image) like "%mshta.exe"
| table _time, User, Image, TargetObject, Image, Details, is_suspicious_path
```
