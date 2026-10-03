param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-evaluation-readiness-tests-'+[guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'tools\evaluation\Readiness.ps1')
if(Test-Path -LiteralPath $ScratchRoot) { throw 'Test directory already exists; refusing to overwrite.' }
[void](New-Item -ItemType Directory -Path $ScratchRoot)
$results=[Collections.Generic.List[object]]::new()
$now=[datetimeoffset]'2026-10-03T00:00:00Z'
function Assert([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message } }
function Run-Test([string]$Name,[scriptblock]$Body) {
    try { & $Body;$results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'});Write-Host ('PASS '+$Name) }
    catch { $results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message});Write-Host ('FAIL '+$Name+': '+$_.Exception.Message) -ForegroundColor Red }
}
function Get-EvaluationRuntimeProcess([int]$ProcessIdValue) {
    if($script:ProcessError) { throw 'Process access denied (fixture)' }
    return $script:Processes[$ProcessIdValue]
}
function Get-EvaluationCurrentTime { return $script:ClockTime }
function Get-EvaluationRuntimeTask([string]$Name) {
    if($script:AdvanceProbeClock -and $Name -eq 'SentinelLocal Watcher') {
        $script:ClockTime=$script:ClockTime.AddSeconds(20)
        $script:AdvanceProbeClock=$false
    }
    return $script:Tasks[$Name]
}
function Get-EvaluationDefenderState { return $script:Defender }
function Get-EvaluationSysmonService { if($script:SysmonError){throw 'Sysmon stopped (fixture)'};return @('Sysmon64') }
function Get-EvaluationEventChannel([string]$Name) {
    if($script:ChannelError -or ($script:SysmonError -and $Name -like '*Sysmon*')) { throw 'Event channel access denied (fixture)' }
    $script:Channels.Add($Name)
    return [pscustomobject]@{Name=$Name;Enabled=$true;LatestRecordId=$null;RecordCount=0}
}
function Fixture([string]$Name) {
    $root=Join-Path $ScratchRoot $Name
    [void](New-Item -ItemType Directory -Path (Join-Path $root 'state'),(Join-Path $root 'logs'))
    Copy-Item -LiteralPath (Join-Path $repo 'config\Config.json') -Destination (Join-Path $root 'Config.json')
    foreach($file in @('Common.ps1','Watcher.ps1','ResponseWorker.ps1','IntegrityMonitor.ps1')) { Set-Content -LiteralPath (Join-Path $root $file) -Value "throw 'Installed payload must not execute during a read-only preflight.'" -Encoding UTF8 }
    $script:Processes=@{};$script:Tasks=@{};$script:ProcessError=$false;$script:ChannelError=$false;$script:SysmonError=$false
    $script:ClockTime=$now;$script:AdvanceProbeClock=$false
    $script:Channels=[Collections.Generic.List[string]]::new()
    $script:Defender=[pscustomobject]@{Mode='Normal';Antivirus=$true;RealTime=$true;Behavior=$true;EngineVersion='Fixture';SignatureVersion='Fixture'}
    $components=@(
        @{Task='SentinelLocal Watcher';Script='Watcher.ps1';File='watcher-heartbeat.json';PidField='WatcherProcessId';PidValue=101;Status='Running'},
        @{Task='SentinelLocal Response Worker';Script='ResponseWorker.ps1';File='response-worker-heartbeat.json';PidField='ResponseWorkerProcessId';PidValue=102;Status='Idle'},
        @{Task='SentinelLocal Integrity Monitor';Script='IntegrityMonitor.ps1';File='integrity-monitor-heartbeat.json';PidField='IntegrityMonitorProcessId';PidValue=103;Status='Running'}
    )
    foreach($component in $components) {
        $heartbeat=[ordered]@{Version='1.2.1';Status=$component.Status;LastUpdated=$now.AddSeconds(-1).ToString('o')}
        $heartbeat[$component.PidField]=$component.PidValue
        Write-SentinelAtomicJson (Join-Path $root ('state\'+$component.File)) $heartbeat
        $powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $arguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Root "{1}"' -f (Join-Path $root $component.Script),$root
        $script:Processes[$component.PidValue]=[pscustomobject]@{ProcessId=$component.PidValue;ExecutablePath=$powershell;CommandLine='"'+$powershell+'" '+$arguments;CreationDate=$now.AddMinutes(-1).UtcDateTime}
        $script:Tasks[$component.Task]=[pscustomobject]@{
            State='Running';Settings=[pscustomobject]@{Enabled=$true;DisallowStartIfOnBatteries=$false;StopIfGoingOnBatteries=$false}
            Actions=@([pscustomobject]@{Execute=$powershell;Arguments=$arguments;WorkingDirectory=''})
            Principal=[pscustomobject]@{UserId='SYSTEM';RunLevel='Highest';LogonType='ServiceAccount'}
            Triggers=@([pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='MSFT_TaskBootTrigger'};Enabled=$true;StartBoundary='';EndBoundary='';Delay='';Repetition=[pscustomobject]@{Interval='';Duration=''}})
        }
    }
    Assert (Write-SentinelJsonLine -Path (Join-Path $root 'logs\alerts.jsonl') -Data ([ordered]@{Type='SyntheticReadinessProbe'})) 'Fixture log append failed'
    return $root
}
function Snapshot([string]$Root) {
    return @((Get-ChildItem -LiteralPath $Root -Recurse -File | Sort-Object FullName | ForEach-Object { $_.FullName+'|'+(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }) -join "`n")
}
function Set-Heartbeat([string]$Root,[string]$Field,$Value) {
    $path=Join-Path $Root 'state\watcher-heartbeat.json'
    $data=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $data.$Field=$Value
    Write-SentinelAtomicJson $path $data
}
function Invoke-ReadinessCli([string]$Root,[string]$OutputDirectory) {
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Root "{1}" -OutputDirectory "{2}"' -f (Join-Path $repo 'tools\evaluation\Test-SentinelEvaluationReadiness.ps1'),$Root,$OutputDirectory
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info
    try {
        [void]$process.Start();$out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(30000)) { $process.Kill();throw 'Readiness CLI exceeded the test timeout.' }
        return [pscustomobject]@{ExitCode=$process.ExitCode;Output=$out.GetAwaiter().GetResult();Error=$err.GetAwaiter().GetResult()}
    } finally { $process.Dispose() }
}

Run-Test 'Missing installation stays unready without manufacturing trial rates' {
    $missing=Join-Path $ScratchRoot 'not-installed'
    $report=Get-SentinelEvaluationReadiness $missing $now
    Assert (-not $report.ReadyForBenignTrials -and -not $report.PerformanceMeasured -and $report.ReadOnly) 'Missing installation became measured or ready'
    Assert (-not (Test-Path -LiteralPath $missing) -and -not $report.PSObject.Properties['Sources']) 'Preflight wrote installation data or manufactured rates'
}
Run-Test 'Healthy fixture passes without executing installed scripts or rewriting files' {
    $root=Fixture 'healthy';$before=Snapshot $root
    $report=Get-SentinelEvaluationReadiness $root $now
    Assert $report.ReadyForBenignTrials (($report.Checks | Where-Object { $_.State -ne 'Pass' } | ConvertTo-Json -Depth 6) -join '')
    Assert ((Snapshot $root) -eq $before) 'Read-only preflight changed installation data'
    Assert ($report.Environment.ConfigSHA256 -eq (Get-FileHash (Join-Path $root 'Config.json')).Hash) 'Configuration provenance differs from input'
    Assert (-not $report.PerformanceMeasured -and $script:Channels.Count -eq 1) 'Readiness was presented as measured performance or disabled Sysmon was queried'
}
Run-Test 'Stale, future and stopped heartbeat states do not pass' {
    $root=Fixture 'stale';Set-Heartbeat $root LastUpdated ($now.AddMinutes(-10).ToString('o'))
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Stale heartbeat accepted'
    Set-Heartbeat $root LastUpdated ($now.AddMinutes(10).ToString('o'))
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Future heartbeat accepted'
    Set-Heartbeat $root LastUpdated ($now.ToString('o'));Set-Heartbeat $root Status 'Stopped'
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Stopped heartbeat accepted'
}
Run-Test 'Live probes use each read time when heartbeats update after report start' {
    $root=Fixture 'advancing-clock'
    foreach($name in @('response-worker-heartbeat.json','integrity-monitor-heartbeat.json')) {
        $path=Join-Path $root ('state\'+$name)
        $heartbeat=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $heartbeat.LastUpdated=$now.AddSeconds(15).ToString('o')
        Write-SentinelAtomicJson $path $heartbeat
    }
    $before=Snapshot $root;$script:AdvanceProbeClock=$true
    $report=Get-SentinelEvaluationReadiness -Root $root
    Assert $report.ReadyForBenignTrials 'A heartbeat refreshed during a slow probe was mistaken for future data.'
    Assert ($report.CapturedAt -eq $now.ToString('o')) 'Report start time changed.'
    $check=$report.Checks | Where-Object Name -eq 'IntegrityMonitor heartbeat/process'
    Assert ($check.Value.AgeSeconds -eq 5 -and $check.Value.CheckedAt -eq $now.AddSeconds(20).ToString('o')) 'Heartbeat did not use its own check time.'
    Assert ((Snapshot $root) -eq $before) 'Clock handling mutated the installation.'
    $frozen=Get-SentinelEvaluationReadiness -Root $root -Now $now
    Assert (-not $frozen.ReadyForBenignTrials) 'Explicit test time was ignored.'
}
Run-Test 'Live probes continue to reject genuinely future and stale timestamps with evidence' {
    $root=Fixture 'live-invalid-time';Set-Heartbeat $root LastUpdated ($now.AddSeconds(10).ToString('o'))
    $report=Get-SentinelEvaluationReadiness -Root $root
    $check=$report.Checks | Where-Object Name -eq 'Watcher heartbeat/process'
    Assert (-not $report.ReadyForBenignTrials -and $check.Value -like '*AgeSeconds=-10.000*' -and $check.Value -like '*CheckedAt=*') 'A genuinely future heartbeat passed or lacked timing evidence.'
    Set-Heartbeat $root LastUpdated ($now.AddMinutes(-10).ToString('o'))
    $report=Get-SentinelEvaluationReadiness -Root $root
    $check=$report.Checks | Where-Object Name -eq 'Watcher heartbeat/process'
    Assert (-not $report.ReadyForBenignTrials -and $check.Value -like '*AgeSeconds=600.000*') 'A stale heartbeat passed.'
}
Run-Test 'Heartbeat version and timestamp must match the measurement configuration' {
    $root=Fixture 'version';Set-Heartbeat $root Version '0.0.0'
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Wrong-version heartbeat accepted'
    Set-Heartbeat $root Version '1.2.1';Set-Heartbeat $root LastUpdated '2026-10-03T00:00:00'
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Naive heartbeat timestamp accepted'
}
Run-Test 'PID reuse wrong executable and wrong installation root cannot satisfy runtime proof' {
    $root=Fixture 'pid'
    $script:Processes[101].CreationDate=$now.UtcDateTime
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Process created after heartbeat accepted'
    $script:Processes[101].CreationDate=$now.AddMinutes(-1).UtcDateTime
    $script:Processes[101].ProcessId=999
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Wrong process identity accepted'
    $script:Processes[101].ProcessId=101;$script:Processes[101].ExecutablePath='C:\Other\powershell.exe'
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Wrong executable accepted'
    $script:Processes[101].ExecutablePath=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $script:Processes[101].CommandLine='powershell.exe -File "C:\Other\Watcher.ps1" -Root "C:\Other"'
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Wrong root accepted'
}
Run-Test 'Disabled or modified tasks and a busy worker require a clean baseline' {
    $root=Fixture 'task';$script:Tasks['SentinelLocal Watcher'].Settings.Enabled=$false
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Disabled task accepted'
    $script:Tasks['SentinelLocal Watcher'].Settings.Enabled=$true;$script:Tasks['SentinelLocal Watcher'].Actions[0].Execute='C:\Other\powershell.exe'
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Modified task accepted'
    $root=Fixture 'battery-task';$script:Tasks['SentinelLocal Watcher'].Settings.StopIfGoingOnBatteries=$true
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Battery-stopped monitoring accepted as a measurement baseline'
    $root=Fixture 'busy';$path=Join-Path $root 'state\response-worker-heartbeat.json'
    $heartbeat=Get-Content $path -Raw | ConvertFrom-Json;$heartbeat.Status='Busy';Write-SentinelAtomicJson $path $heartbeat
    $report=Get-SentinelEvaluationReadiness $root $now
    Assert (-not $report.ReadyForBenignTrials) 'Busy worker accepted as baseline'
    $check=$report.Checks | Where-Object Name -eq 'ResponseWorker heartbeat/process'
    Assert ($check.Value -like '*status is "Busy"*') 'Busy status was not identified in diagnostics.'
}
Run-Test 'Access errors remain unverified instead of clean results' {
    $root=Fixture 'access';$script:ProcessError=$true;$script:ChannelError=$true
    $report=Get-SentinelEvaluationReadiness $root $now
    Assert (-not $report.ReadyForBenignTrials -and @($report.Checks | Where-Object { $_.State -eq 'Unverified' }).Count -ge 4) 'Access failures became passes'
}
Run-Test 'Missing or tampered logs and pending transactions remain unchanged and unready' {
    $root=Fixture 'pending';$log=Join-Path $root 'logs\alerts.jsonl';$checkpoint=Get-SentinelChainPath $log
    Write-SentinelAtomicJson ($checkpoint+'.pending') ([ordered]@{Synthetic='Pending'})
    $before=Snapshot $root;$report=Get-SentinelEvaluationReadiness $root $now
    Assert (-not $report.ReadyForBenignTrials -and (Snapshot $root) -eq $before) 'Pending transaction was repaired or accepted'
    $root=Fixture 'deleted-log';Remove-Item -LiteralPath (Join-Path $root 'logs\alerts.jsonl')
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Deleted log became clean'
    $root=Fixture 'modified-log';Add-Content -LiteralPath (Join-Path $root 'logs\alerts.jsonl') -Value '{}'
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Tampered log became clean'
}
Run-Test 'Legacy checkpoints are not migrated by diagnostics' {
    $root=Fixture 'legacy';$checkpoint=Get-SentinelChainPath (Join-Path $root 'logs\alerts.jsonl')
    $data=Get-Content $checkpoint -Raw | ConvertFrom-Json;$data.Schema=1;Write-SentinelAtomicJson $checkpoint $data
    $before=Snapshot $root
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials -and (Snapshot $root) -eq $before) 'Legacy checkpoint was migrated or accepted'
}
Run-Test 'Passive Defender and enabled but unreadable Sysmon prevent readiness' {
    $root=Fixture 'defender';$script:Defender.Mode='Passive'
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Passive Defender accepted'
    $script:Defender.Mode='Normal';$path=Join-Path $root 'Config.json'
    $config=Get-Content $path -Raw | ConvertFrom-Json;$config.Sysmon.Enabled=$true;Write-SentinelAtomicJson $path $config
    $script:SysmonError=$true
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Unreadable required Sysmon channel accepted'
}
Run-Test 'Enabled Sysmon requires the running source and Watcher mode acknowledgement' {
    $root=Fixture 'sysmon-source';$path=Join-Path $root 'Config.json'
    $config=Get-Content $path -Raw | ConvertFrom-Json;$config.Sysmon.Enabled=$true;Write-SentinelAtomicJson $path $config
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Old CIM-only Watcher passed as Sysmon.'
    $path=Join-Path $root 'state\watcher-heartbeat.json';$heartbeat=Get-Content $path -Raw | ConvertFrom-Json
    $heartbeat | Add-Member NoteProperty ProcessMonitorMode Sysmon;Write-SentinelAtomicJson $path $heartbeat
    Assert (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials 'Healthy Sysmon source rejected.'
    $script:SysmonError=$true
    Assert (-not (Get-SentinelEvaluationReadiness $root $now).ReadyForBenignTrials) 'Stopped source accepted.'
}
Run-Test 'CLI writes an unready report outside the installation and returns exit code two' {
    $output=Join-Path $ScratchRoot 'cli-report';$missing=Join-Path $ScratchRoot 'cli-not-installed'
    $invocation=Invoke-ReadinessCli $missing $output
    Assert ($invocation.ExitCode -eq 2) ('Unready CLI returned a successful measurement status: '+$invocation.Error)
    Assert ($invocation.Output -match 'Checks requiring attention:' -and $invocation.Output -match 'Value\s*:') 'CLI concealed the reason for an unready check.'
    $report=Get-Content (Join-Path $output 'readiness.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert (-not $report.ReadyForBenignTrials -and -not $report.PerformanceMeasured -and -not (Test-Path $missing)) 'CLI invented results or modified the monitored root'
    $invocation=Invoke-ReadinessCli $missing $output
    Assert ($invocation.ExitCode -eq 1) 'CLI overwrote an existing diagnostic'
    $invocation=Invoke-ReadinessCli $missing (Join-Path $missing 'reports')
    Assert ($invocation.ExitCode -eq 1 -and -not (Test-Path $missing)) 'CLI wrote into the monitored root'
}
Run-Test 'A junction cannot redirect diagnostic output into the monitored installation' {
    $root=Fixture 'junction-target';$alias=Join-Path $ScratchRoot 'junction-alias'
    [void](New-Item -ItemType Junction -Path $alias -Target $root -ErrorAction Stop)
    $before=Snapshot $root
    $invocation=Invoke-ReadinessCli $root (Join-Path $alias 'diagnostic-output')
    Assert ($invocation.ExitCode -eq 1 -and -not (Test-Path (Join-Path $root 'diagnostic-output')) -and (Snapshot $root) -eq $before) 'Junction output changed the monitored installation'
}

$results.ToArray() | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ScratchRoot 'test-results.json') -Encoding UTF8
$failed=@($results | Where-Object { -not $_.Passed }).Count
Write-Host ('Evaluation readiness tests: '+($results.Count-$failed)+' passed; '+$failed+' failed. Results: '+$ScratchRoot)
if($failed) { exit 1 }
exit 0
