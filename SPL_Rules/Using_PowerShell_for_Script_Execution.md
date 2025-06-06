# Using PowerShell for Script Execution

| MITRE ID  | Tactic    |
| --------- | --------- |
| T1059.001 | Execution |

```spl
(index=* source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
    AND (
        Message="*-EncodedCommand*"
        OR Message="*Invoke-Expression*"
        OR Message="*IEX*"
        OR Message="*DownloadFile*"
    )
)
OR
(index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
    AND (
        ImageLoaded="*System.Management.Automation.dll*"
        OR ImageLoaded="*powershell.exe*"
    )
)
OR
(index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1"
      OR (
         source="WinEventLog:Security"
         EventCode="4688"
    )
    Image="powershell.exe" AND ParentImage!="explorer.exe"
)
OR
(index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="1"
       OR (
       source="WinEventLog:Security"
       EventCode="4688"
    )
    Image="wsmprovhost.exe" AND ParentImage="svchost.exe"
)
OR
(index=* source="Wineventlog:Microsoft-Windows-Powershell/operational"  EventCode="4104"
       AND (
       Image="powershell.exe"
       AND (CommandLine="-enc" OR CommandLine="-ep bypass" OR CommandLine="-noni*")
    )
)
| eval cmd=coalesce(CommandLine, Message)
| eval proc=coalesce(Image, ProcessName)
| eval parent=coalesce(ParentImage, ParentProcessName)

| table _time host user cmd proc parent
| sort -_time
```
