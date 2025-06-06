# Abusing Accessibility Features

| MITRE ID  | Tactic                            |
| --------- | --------------------------------- |
| T1546.008 | Privilege Escalation, Persistence |

```spl
index=*
(
  (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
  OR
  (source="WinEventLog:Security" EventCode=4688)
)
| where (
    like(lower(CommandLine), "%sethc.exe%")
    OR like(lower(CommandLine), "%utilman.exe%")
    OR like(lower(CommandLine), "%osk.exe%")
    OR like(lower(CommandLine), "%narrator.exe%")
    OR like(lower(CommandLine), "%magnify.exe%")
    OR like(lower(CommandLine), "%atbroker.exe%")
    OR like(lower(CommandLine), "%displayswitch.exe%")
)
| eval abuse_type="T1546.008 - Accessibility Feature Abuse"
| eval suspicious_parent=if(match(ParentImage,"(?i)(cmd|powershell|wscript|cscript|rundll32)"), "YES", "NO")
| where NOT match(ParentImage,"(?i)(sethc.exe|utilman.exe|osk.exe|narrator.exe|magnify.exe|atbroker.exe|displayswitch.exe)")
| table _time, host, User, suspicious_parent, ParentImage, Image, CommandLine, abuse_type
| sort - _time
```
