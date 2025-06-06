# Recording or Taking Screenshots

| MITRE ID | Tactic     |
| -------- | ---------- |
| T1113    | Collection |

```spl
(
    index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    AND (
        CommandLine="*screencap*" OR
        CommandLine="*screen*" OR
        CommandLine="*copyfromscreen*" OR
        CommandLine="*xwd*" OR
        CommandLine="*PrintWindow*" OR
        CommandLine="*SnippingTool*" OR
        CommandLine="*nircmd*" OR
        CommandLine="*ffmpeg*" OR
        CommandLine="*save*" AND (CommandLine="*.jpg*" OR CommandLine="*.png*")
    )
)
OR
(
    index=* source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
    AND (
        Message="*CopyFromScreen*" OR
        Message="*Add-Type*" AND Message="*System.Drawing*" OR
        Message="*screenshot*" OR
        Message="*bitmap*" OR
        Message="*Save*"
    )
)
| table _time host user EventCode Image CommandLine Message
| sort -time
```
