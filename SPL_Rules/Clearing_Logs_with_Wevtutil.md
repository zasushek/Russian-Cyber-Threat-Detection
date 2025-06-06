# Clearing Logs with Wevtutil

| MITRE ID  | Tactic          |
| --------- | --------------- |
| T1070.001 | Defense Evasion |

```spl
(
    index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    (
        (CommandLine="*wevtutil*" AND CommandLine="* cl *" AND (
            CommandLine="*System*" OR
            CommandLine="*Security*" OR
            CommandLine="*Setup*" OR
            CommandLine="*Application*"
        ))
        OR CommandLine="*Clear-EventLog*"
        OR CommandLine="*Limit-EventLog*"
        OR (CommandLine="*Remove-Item*" AND CommandLine="*.evtx*")
        OR CommandLine="*Remove-EventLog*"
    )
)
OR
(
    index=* source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
    (
        Message="*Clear-EventLog*"
        OR Message="*Limit-EventLog*"
        OR (Message="*Remove-Item*" AND Message="*.evtx*")
        OR Message="*Remove-EventLog*"
    )
)
OR
(
    index=* source="WinEventLog:Security" EventCode IN (1102, 4907)
)
OR
(
    index=* source="WinEventLog:System" EventCode=104
)
| table _time, host, user, Image, CommandLine, EventCode, source, Message
```
