# Load reviewed repository code only. Never import scripts from the monitored installation.
$evaluationRepo=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $evaluationRepo 'src\Common.ps1')

function Get-EvaluationRuntimeProcess([int]$ProcessIdValue) {
    return Get-CimInstance Win32_Process -Filter ("ProcessId="+$ProcessIdValue) -ErrorAction Stop
}
function Get-EvaluationRuntimeTask([string]$Name) {
    return Get-ScheduledTask -TaskName $Name -TaskPath '\' -ErrorAction Stop
}
function Get-EvaluationDefenderState {
    $value=Get-MpComputerStatus -ErrorAction Stop
    return [pscustomobject]@{Mode=[string]$value.AMRunningMode;Antivirus=$value.AntivirusEnabled;RealTime=$value.RealTimeProtectionEnabled;Behavior=$value.BehaviorMonitorEnabled;EngineVersion=[string]$value.AMEngineVersion;SignatureVersion=[string]$value.AntivirusSignatureVersion}
}
function Get-EvaluationEventChannel([string]$Name) {
    $channel=Get-WinEvent -ListLog $Name -ErrorAction Stop
    if(-not $channel.IsEnabled) { throw 'Required event channel is disabled.' }
    try { $last=Get-WinEvent -LogName $Name -MaxEvents 1 -ErrorAction Stop }
    catch { if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }; $last=$null }
    return [pscustomobject]@{Name=$Name;Enabled=$true;LatestRecordId=$(if($last){$last.RecordId}else{$null});RecordCount=$channel.RecordCount}
}

function Get-EvaluationLogAccess([string]$Root) {
    $directory=Join-Path $Root 'logs'
    $logs=@(Get-ChildItem -LiteralPath $directory -File -Filter '*.jsonl' -ErrorAction Stop)
    $chainDirectory=Join-Path $Root 'state\log-chain'
    $checkpoints=@(Get-ChildItem -LiteralPath $chainDirectory -File -Filter '*.jsonl.state' -ErrorAction Stop)
    $names=@(@($logs.Name)+@($checkpoints | ForEach-Object { $_.Name.Substring(0,$_.Name.Length-6) }) | Sort-Object -Unique)
    if(-not $names.Count) { throw 'No JSONL stream/checkpoint is available; log collection has not been demonstrated.' }
    $streams=@(foreach($name in $names) {
        $path=Join-Path $directory $name
        $mutex=$null
        try {
            $mutex=Enter-SentinelLogLock $path
            $statePath=Get-SentinelChainPath $path
            if(Test-Path -LiteralPath ($statePath+'.pending')) { throw 'Pending log transaction; retry after the writer finishes. Diagnostics will not repair it.' }
            $checkpoint=Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if($checkpoint.Schema -ne 2) { throw 'A schema 2 checkpoint is required; diagnostics will not migrate legacy state.' }
            $snapshot=Get-SentinelLogSnapshot $path
            if(-not (Test-SentinelSnapshotMatches $snapshot $checkpoint)) { throw ('Checkpoint mismatch for '+$name) }
            [pscustomobject]@{Name=$name;LineCount=$snapshot.LineCount;ByteLength=$snapshot.ByteLength}
        } finally { if($mutex) { $mutex.ReleaseMutex();$mutex.Dispose() } }
    })
    if(@($streams | Where-Object { $_.LineCount -gt 0 }).Count -eq 0) { throw 'Only empty logs are available; log collection has not been demonstrated.' }
    return $streams
}

function Get-SentinelEvaluationReadiness([string]$Root='C:\ProgramData\SentinelLocal',[datetimeoffset]$Now=[datetimeoffset]::Now) {
    $rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\')
    $checks=[Collections.Generic.List[object]]::new()
    function Probe([string]$Name,[scriptblock]$Read,[scriptblock]$Judge,[string]$NextStep) {
        try {
            $value=& $Read
            $state=if(& $Judge $value){'Pass'}else{'Fail'}
            $checks.Add([pscustomobject]@{Name=$Name;State=$state;Value=$value;NextStep=$NextStep})
        } catch { $checks.Add([pscustomobject]@{Name=$Name;State='Unverified';Value=$_.Exception.Message;NextStep=$NextStep}) }
    }
    Probe 'Installed layout' {
        $missing=@(foreach($name in @('Config.json','Common.ps1','Watcher.ps1','ResponseWorker.ps1','IntegrityMonitor.ps1')) {
            if(-not (Test-Path -LiteralPath (Join-Path $rootPath $name) -PathType Leaf -ErrorAction Stop)) { $name }
        })
        [pscustomobject]@{MissingFiles=$missing}
    } {param($value) $value.MissingFiles.Count -eq 0} 'Use the reviewed Bootstrap installation procedure before measuring.'
    $config=$null
    Probe 'Configuration' {
        $bytes=[IO.File]::ReadAllBytes((Join-Path $rootPath 'Config.json'))
        $candidate=[Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xfeff) | ConvertFrom-Json -ErrorAction Stop
        Assert-SentinelConfig $candidate
        if(-not $candidate.SelfDefense.Enabled) { throw 'Integrity Monitor must be enabled for this measurement preflight.' }
        $algorithm=[Security.Cryptography.SHA256]::Create()
        try { $hash=([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-','') } finally { $algorithm.Dispose() }
        [pscustomobject]@{Configuration=$candidate;SHA256=$hash}
    } {param($value) [bool]$value.Configuration.Version} 'Review Config.json and keep the tested configuration fixed during a run.'
    $configCheck=$checks | Where-Object { $_.Name -eq 'Configuration' }
    $metadata=$null
    if($configCheck.State -eq 'Pass') {
        $config=$configCheck.Value.Configuration
        $metadata=[pscustomobject]@{SentinelVersion=[string]$config.Version;ConfigSHA256=$configCheck.Value.SHA256;SysmonEnabled=[bool]$config.Sysmon.Enabled;WindowsVersion=[Environment]::OSVersion.VersionString;PowerShellVersion=$PSVersionTable.PSVersion.ToString()}
        $configCheck.Value=$metadata
    }
    $components=@(
        @{Name='Watcher';Script='Watcher.ps1';Task='SentinelLocal Watcher';File='watcher-heartbeat.json';PidField='WatcherProcessId';Stale=$(if($config){$config.HeartbeatStaleSeconds}else{0});Statuses=@('Running')},
        @{Name='ResponseWorker';Script='ResponseWorker.ps1';Task='SentinelLocal Response Worker';File='response-worker-heartbeat.json';PidField='ResponseWorkerProcessId';Stale=$(if($config){$config.ResponseWorkerHeartbeatStaleSeconds}else{0});Statuses=@('Idle')},
        @{Name='IntegrityMonitor';Script='IntegrityMonitor.ps1';Task='SentinelLocal Integrity Monitor';File='integrity-monitor-heartbeat.json';PidField='IntegrityMonitorProcessId';Stale=$(if($config){$config.SelfDefense.HeartbeatStaleSeconds}else{0});Statuses=@('Running')}
    )
    foreach($component in $components) {
        Probe ($component.Name+' heartbeat/process') {
            if(-not $config) { throw 'Configuration could not be verified.' }
            $heartbeat=Get-Content -LiteralPath (Join-Path $rootPath ('state\'+$component.File)) -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if([string]$heartbeat.Version -cne [string]$config.Version) { throw 'Heartbeat version differs from configuration.' }
            if([string]$heartbeat.Status -cnotin $component.Statuses) { throw 'Component is stopped, busy or in an unsupported state; wait for a healthy idle baseline.' }
            if([string]$heartbeat.LastUpdated -notmatch '(Z|[+-]\d{2}:\d{2})$') { throw 'Heartbeat needs an explicit timezone.' }
            $updated=[datetimeoffset]::Parse([string]$heartbeat.LastUpdated,[Globalization.CultureInfo]::InvariantCulture)
            $age=($Now-$updated).TotalSeconds
            if($age -lt -5 -or $age -gt [int]$component.Stale) { throw 'Heartbeat is stale or unexpectedly in the future.' }
            $pidValue=$heartbeat.($component.PidField)
            if(($pidValue -isnot [int] -and $pidValue -isnot [long]) -or $pidValue -le 0) { throw 'Invalid heartbeat process ID.' }
            $process=Get-EvaluationRuntimeProcess $pidValue
            $scriptPath=Join-Path $rootPath $component.Script
            $expected='-File\s+"'+[regex]::Escape($scriptPath)+'"\s+-Root\s+"'+[regex]::Escape($rootPath)+'"\s*$'
            $powershell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
            if(-not $process -or [int]$process.ProcessId -ne $pidValue -or [string]$process.ExecutablePath -ine $powershell -or [string]$process.CommandLine -notmatch $expected) { throw 'Heartbeat PID does not identify the expected component and installation root.' }
            if(-not $process.CreationDate) { throw 'Process creation time is unavailable.' }
            $created=[datetimeoffset]([datetime]$process.CreationDate).ToUniversalTime()
            if($created -gt $updated) { throw 'Process was created after its heartbeat; possible PID reuse.' }
            [pscustomobject]@{ProcessId=$pidValue;ProcessCreatedAt=$created.ToString('o');AgeSeconds=[math]::Round($age,3);Status=[string]$heartbeat.Status;LastUpdated=[string]$heartbeat.LastUpdated}
        } {param($value) $true} 'Check the installed task, process and fresh heartbeat; a heartbeat file alone is insufficient.'
        Probe ($component.Name+' task') {
            $task=Get-EvaluationRuntimeTask $component.Task
            [pscustomobject]@{DefinitionValid=(Test-SentinelTaskDefinition $task $rootPath $component.Task);State=[string]$task.State;Enabled=$task.Settings.Enabled}
        } {param($value) $value.DefinitionValid -and $value.Enabled -and $value.State -eq 'Running'} 'Confirm the expected enabled SYSTEM startup task is running.'
    }
    Probe 'Sentinel JSONL logs/checkpoints' { @(Get-EvaluationLogAccess $rootPath) } {param($value) @($value).Count -gt 0} 'Check access and the completed log transactions; this diagnostic does not repair or rewrite logs.'
    Probe 'Defender active protection' { Get-EvaluationDefenderState } {param($value) $value.Mode -eq 'Normal' -and $value.Antivirus -and $value.RealTime -and $value.Behavior} 'Confirm Defender active protection and record its versions before the run.'
    Probe 'Defender event channel' { Get-EvaluationEventChannel 'Microsoft-Windows-Windows Defender/Operational' } {param($value) $value.Enabled} 'Read access to the enabled channel is required; inaccessible is not zero detections.'
    if($config -and $config.Sysmon.Enabled) {
        Probe 'Sysmon event channel' { Get-EvaluationEventChannel 'Microsoft-Windows-Sysmon/Operational' } {param($value) $value.Enabled} 'When Sysmon monitoring is enabled, its event channel must also be readable.'
    }
    return [pscustomobject]@{
        Schema=1;CapturedAt=$Now.ToString('o');Root=$rootPath;ReadOnly=$true;PerformanceMeasured=$false
        ReadyForBenignTrials=(@($checks | Where-Object { $_.State -ne 'Pass' }).Count -eq 0)
        Environment=$metadata;Checks=$checks.ToArray()
    }
}
