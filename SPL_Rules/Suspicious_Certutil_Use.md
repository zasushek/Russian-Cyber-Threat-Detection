#Suspicious Certutil Use

| MITRE ID | Tactic          |
| -------- | --------------- |
| T1140    | Defense Evasion |

```spl
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\certutil.exe"
(CommandLine="*-decode*" OR CommandLine="*decodehex*" OR CommandLine="*base64*" OR CommandLine="*hex*")
| table _time host user Image CommandLine ProcessId

| join certutil_pid type=inner [
    search index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
    (TargetFilename="*.exe" OR TargetFilename="*.bat" OR TargetFilename="*.ps1" OR TargetFilename="*.dll" OR TargetFilename="*.scr")
    | table _time host ProcessId TargetFilename
]

| eval Action="Certutil decode followed by file creation"
| table _time host user Image CommandLine TargetFilename Action
| sort -_time
```
