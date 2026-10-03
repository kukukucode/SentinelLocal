function Read-SentinelBaseline {
    param([string]$Root)
    $baseline=Get-Content -LiteralPath (Join-Path $Root 'state\integrity-baseline.json') -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $expected=@(Get-SentinelCriticalFileNames);$seen=@{}
    if(@($baseline.Files).Count -ne $expected.Count) {throw 'Integrity baseline has missing or extra files.'}
    foreach($entry in @($baseline.Files)) {
        $name=[string]$entry.Name
        if($name -notin $expected -or $seen.ContainsKey($name)) {throw 'Integrity baseline has an unknown or duplicate name.'}
        $seen[$name]=$true
        if([string]$entry.Path -ine (Join-Path $Root $name) -or [string]$entry.SHA256 -notmatch '^[A-Fa-f0-9]{64}$') {throw ('Invalid integrity baseline path or hash: '+$name)}
    }
    return $baseline
}
function New-SentinelMonitoringTaskSettings {
    # Task Scheduler otherwise stops all three components when AC is unplugged
    # and refuses starts while on battery. Protection must continue on laptops.
    return New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
}
function Test-SentinelTaskDefinition {
    param($Task,[string]$Root,[string]$TaskName)
    $scripts=@{'SentinelLocal Watcher'='Watcher.ps1';'SentinelLocal Response Worker'='ResponseWorker.ps1';'SentinelLocal Integrity Monitor'='IntegrityMonitor.ps1'}
    if(-not $Task -or -not $scripts.ContainsKey($TaskName)) {return $false}
    if(-not $Task.Settings) {return $false}
    foreach($name in @('DisallowStartIfOnBatteries','StopIfGoingOnBatteries')) {
        $value=$Task.Settings.$name
        if($value -isnot [bool] -or $value) {return $false}
    }
    $actions=@($Task.Actions);$triggers=@($Task.Triggers)
    if($actions.Count -ne 1 -or $triggers.Count -ne 1) {return $false}
    $arguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Root "{1}"' -f (Join-Path $Root $scripts[$TaskName]),$Root
    if([string]$actions[0].Execute -ine (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -or [string]$actions[0].Arguments -cne $arguments -or [string]$actions[0].WorkingDirectory) {return $false}
    $principal=$Task.Principal
    if([string]$principal.UserId -notin @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -or [string]$principal.RunLevel -notin @('Highest','1') -or [string]$principal.LogonType -notin @('ServiceAccount','5')) {return $false}
    $trigger=$triggers[0]
    if([string]$trigger.CimClass.CimClassName -ne 'MSFT_TaskBootTrigger' -or -not $trigger.Enabled -or $trigger.StartBoundary -or $trigger.EndBoundary -or [string]$trigger.Delay -notin @('','PT0S') -or $trigger.Repetition.Interval -or $trigger.Repetition.Duration) {return $false}
    return $true
}
