# Command and Scripting Interpreter: Visual Basic

| MITRE ID  | Tactic    |
| --------- | --------- |
| T1059.005 | Execution |

```spl
index=*
(
  source="wineventlog:microsoft-windows-sysmon/operational"
  AND
  (
    (EventCode=1 AND (
       Image="*\\cscript.exe" OR
       Image="*\\wscript.exe" OR
       CommandLine="*.vbs*"   OR
       CommandLine="*.vba*"   OR
       CommandLine="*.vbe*"
    ))
    OR
    (EventCode=7 AND (
       ImageLoaded="*vbscript.dll" OR
       ImageLoaded="*vba7.dll"    OR
       ImageLoaded="*vbe6.dll"
    ))
  )
)
| table _time, host, user, EventCode, Image, ImageLoaded, CommandLine
| sort - _time
```
