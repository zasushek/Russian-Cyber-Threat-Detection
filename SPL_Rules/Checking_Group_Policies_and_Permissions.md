# Checking Group Policies and Permissions

| MITRE ID | Tactic    |
| -------- | --------- |
| T1615    | Discovery |

```spl
(index=* source="WinEventLog:Security" EventCode=4661 AND ObjectName="*groupPolicyContainer*")
OR
(index=* source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
    AND (
        Message="*Get-DomainGPO*"
        OR Message="*Get-DomainGPOLocalGroup*"
        OR Message="*gpresult*"
        OR Message="*GPO*"
    )
)
OR
(index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    AND (
        CommandLine="*gpresult*"
        OR CommandLine="*Get-DomainGPO*"
        OR CommandLine="*GPO*"
    )
)
OR
(index=* source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
    AND (
        Message="*Set-GPRegistryValue*"
        OR Message="*New-GPO*"
        OR Message="*Set-GPPermission*"
    )
)
| eval command=coalesce(CommandLine, Message)
| eval image_proc=if(EventCode=1, Image, null())
| table _time host user EventCode source command image_proc
| sort -_time
```
