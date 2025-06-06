# Archive Collected Data: Archive via Utility

| MITRE ID  | Tactic     |
| --------- | ---------- |
| T1560.001 | Collection |

```spl
index=*
(
  ( sourcetype="wineventlog:microsoft-windows-sysmon/operational"
    AND EventCode=1
    AND (
      Image="*\\7z.exe"      OR
      Image="*\\rar.exe"     OR
      Image="*\\WinRAR.exe"  OR
      Image="*\\zip.exe"     OR
      Image="*\\tar.exe"     OR
      CommandLine="* a *"
    )
  )
  OR
  ( sourcetype="wineventlog:microsoft-windows-sysmon/operational"
    AND EventCode=11
    AND (
      TargetFilename="*.zip"  OR
      TargetFilename="*.rar"  OR
      TargetFilename="*.7z"   OR
      TargetFilename="*.tar"  OR
      TargetFilename="*.gz"
    )
  )
)
| table _time, host, user, source, EventCode, Image, CommandLine
| sort - _time
```
