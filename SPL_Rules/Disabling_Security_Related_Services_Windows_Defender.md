# Disabling Security-Related Services (Windows Defender)

| MITRE ID  | Tactic          |
| --------- | --------------- |
| T1562.001 | Defense Evasion |

```spl
index=* EventCode=13
(TargetObject="*\\Policies\\Microsoft\\Windows Defender*" AND (TargetObject="*\\DisableAntiVirus" OR TargetObject="*\\DisableAntiSpyware" OR TargetObject="*\\DisableBehaviorMonitoring" OR TargetObject="*\\DisableIntrusionPreventionSystem" OR TargetObject="*\\DisableIOAVProtection" OR TargetObject="*\\DisableOnAccessProtection" OR TargetObject="*\\DisableRealtimeMonitoring" OR TargetObject="*\\DisableRoutinelyTakingAction" OR TargetObject="*\\DisableScanOnRealtimeEnable" OR TargetObject="*\\DisableScriptScanning" OR TargetObject="*\\DisableEnhancedNotifications" OR TargetObject="*\\DisableBlockAtFirstSeen"))
| eval IsDisabled=if(match(Details, "0x00000001"), "YES", "NO")
| eval DisabledComponent=mvindex(split(TargetObject, "\\"), -1)
| eval ExecutingProcess=mvindex(split(Image, "\\"), -1)
| where IsDisabled="YES"
| table _time, host, User, ExecutingProcess, DisabledComponent, IsDisabled, ProcessId, ProcessGuid
```
