# Using WMI for Payload Execution on System Events

| MITRE ID  | Tactic                            |
| --------- | --------------------------------- |
| T1546.003 | Privilege Escalation, Persistence |

```spl
(
    index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    AND (
        CommandLine="*Register-WmiEvent*" OR CommandLine="*wmic*" OR CommandLine="*mofcomp*"
        OR (
            ParentImage="C:\\Windows\\System32\\WmiPrvSE.exe"
            AND (
                Image="*cmd.exe" OR Image="*powershell.exe" OR Image="*mofcomp.exe"
            )
        )
    )
)
OR
(
    index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
    AND TargetFilename="*.mof"
    AND NOT like(TargetFilename, "C:\\Windows\\System32\\wbem%")
)
OR
(
    index=* source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
    AND Message="*Register-WmiEvent*"
)
OR
(
    index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
    AND (EventCode=19 OR EventCode=20 OR EventCode=21)
)
| eval Action=case(
    EventCode=1 AND isnotnull(CommandLine), "Suspicious WMI command",
    EventCode=1 AND isnotnull(ParentImage), "Suspicious WMI child process",
    EventCode=11, "Suspicious MOF file created",
    EventCode=4104, "PowerShell WMI persistence",
    EventCode=19, "WMI Filter created",
    EventCode=20, "WMI Consumer created",
    EventCode=21, "WMI Binding created"
)
| table _time, host, Action, Image, CommandLine, ParentImage, Message, EventCode, source
| sort -_time
```
