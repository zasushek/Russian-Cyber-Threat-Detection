# Suspicious Use of CMD for Command Execution

| MITRE ID  | Tactic    |
| --------- | --------- |
| T1059.003 | Execution |

```spl
index=*
(
  (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1") 
  OR 
  (source="WinEventLog:Security" EventCode="4688")
)
AND (CommandLine="cmd.exe" OR Image="*\\cmd.exe")
| eval suspicious=if(
  like(CommandLine, "%/c%") 
  OR like(CommandLine, "%/k%") 
  OR match(CommandLine, ".+\.bat")
  OR match(CommandLine, ".+\.vbs")
  OR match(CommandLine, ".+\.cmd"),
  "YES","NO"
  )
| eval suspicious_parent=if(match(ParentImage, "(?i)(winword|excel|outlook|wscript|cscript|rundll32|regsrv32|mshta|powershell|teams|zoom|java|python|iexplore|chrome|firefox|explorer)"), "YES", "NO")
| eval risk_level=case(
  like(CommandLine, "%.bat%") OR like(CommandLine, "%.vbs%"), "HIGH",
  like(CommandLine, "%/c%"), "MODERATE",
  true(), "LOW"
  )
| where suspicious="YES"
| where NOT like(ParentImage, "%splunk%")
| where NOT like(CommandLine, "%OneDrive%")
| table _time, host, User, ParentImage, Image, CommandLine, risk_level, suspicious_parent
| sort -_time
```
