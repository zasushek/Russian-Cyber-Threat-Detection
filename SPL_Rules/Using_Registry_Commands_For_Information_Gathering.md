# Using Registry Commands for Information Gathering

| MITRE ID | Tactic    |
| -------- | --------- |
| T1012    | Discovery |

```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(
  (Image="*\\reg.exe" AND CommandLine="*query*")
  OR
  (Image="*\\powershell.exe" AND (CommandLine="*Get-Item*" OR CommandLine="*Get-ChildItem*" (CommandLine="*HKLM:*" OR CommandLine="*HKCU:*")))
)
| bin _time span=1m
| eval ExecutingProcess=mvindex(split(Image, "\\"), -1)
| stats count by _time, host, User, ExecutingProcess
| where count > 10
| rename count as RegistryQueryCount
| sort -_time
```
