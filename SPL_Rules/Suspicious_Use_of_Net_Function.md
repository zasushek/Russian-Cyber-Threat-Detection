# Suspicious Use of Net Function

| MITRE ID  | Tactic           |
| --------- | ---------------- |
| T1021.002 | Lateral Movement |

```spl
index=* AND source="WinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode=1
| where lower(ParentImage) LIKE "%cmd.exe" OR lower(ParentImage) LIKE "%powershell.exe"
| where like(CommandLine, "%net use%") OR like(CommandLine, "%net share%")
| bin _time span=5m
| stats count by User, ParentImage, Image, _time
| eval suspicious_command=if(count > 3, "high", "normal")
| where suspicious_command="high"
| sort -_time
```
