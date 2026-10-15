function Read-SentinelSysmon {
    param([string]$Root,$Config,[scriptblock]$ScoreProcess,[scriptblock]$QueueResponse,[ValidateRange(1,60)][int]$MaximumProcessingSeconds=10,$RecordedBatch,[scriptblock]$AfterEvent)
    if(-not $Config.Sysmon.Enabled) {return}
    $deferred=$null -ne $RecordedBatch
    $cursorPath=Join-Path $Root $(if($deferred){'state\sysmon-analysis-cursor.json'}else{'state\sysmon-cursor.json'});$cachePath=Join-Path $Root 'state\sysmon-correlations.json'
    $cursor=0L;$time='';$cache=@{}
    if(Test-Path -LiteralPath $cursorPath) {
        $saved=Get-Content -LiteralPath $cursorPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        $cursor=[long]$saved.RecordId;$time=[string]$saved.TimeCreated
    }
    if(Test-Path -LiteralPath $cachePath) {
        $saved=Get-Content -LiteralPath $cachePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        if(@($saved.Processes).Count -gt 1000) {throw 'Sysmon correlation cache limit exceeded.'}
        foreach($row in @($saved.Processes)) {if($row.Process.ProcessGuid){$cache[[string]$row.Process.ProcessGuid]=$row}}
    }
    $batch=if($deferred){$RecordedBatch}else{Get-SentinelEventBatch -LogName 'Microsoft-Windows-Sysmon/Operational' -Cursor $cursor -CursorTime $time -Ids @(1,3,4,16,19,20,21,22,25,255) -BatchSize ([int]$Config.EventBatchSize)}
    if($batch.Reset) {
        if(-not (Write-SentinelJsonLine (Join-Path $Root 'logs\alerts.jsonl') ([ordered]@{Type='EventLogCursorReset';Severity='HIGH';Log='Sysmon';PreviousCursor=$cursor}))) {throw 'Cannot persist Sysmon cursor reset.'}
        $cache=@{};Write-SentinelAtomicJson $cachePath ([ordered]@{Processes=@()})
        Write-SentinelAtomicJson $cursorPath ([ordered]@{RecordId=0L;TimeCreated=''})
    }
    $processingStarted=Get-SentinelSysmonMonotonicSeconds
    foreach($event in @($batch.Events)) {
        $data=Get-SentinelEventData $event
        if(-not $deferred -and -not (Write-SentinelJsonLine (Join-Path $Root 'logs\sysmon-events.jsonl') ([ordered]@{Type='SysmonEvent';EventId=$event.Id;RecordId=$event.RecordId;EventTime=$event.TimeCreated.ToString('o');Data=$data}))) {throw 'Cannot persist Sysmon event.'}
        # Expire by event time and bound cardinality; never correlate by a reused PID.
        $cutoff=([datetime]$event.TimeCreated).AddHours(-1)
        foreach($key in @($cache.Keys)) {if([datetimeoffset]::Parse([string]$cache[$key].SeenAt).LocalDateTime -lt $cutoff){$cache.Remove($key)}}
        if($event.Id -eq 1) {
            $process=ConvertFrom-SentinelSysmonProcess $data
            $complete=$process.ProcessId -gt 0 -and [IO.Path]::IsPathRooted($process.ExecutablePath) -and $process.CommandLine -and $process.ProcessGuid -and $process.ObservedSHA256
            if(-not $deferred -and -not (Write-SentinelJsonLine (Join-Path $Root 'logs\process-events.jsonl') ([ordered]@{Type='ProcessCreated';Source='Sysmon';RecordId=$event.RecordId;EventTime=$event.TimeCreated.ToString('o');MetadataComplete=[bool]$complete;Process=$process}))) {throw 'Cannot persist recorded process identity.'}
            $score=& $ScoreProcess $process
            if($score.Score -ge [int]$Config.ScorePolicy.DefenderCustomScan -and -not (Test-SentinelException -Path $process.ExecutablePath -Config $Config)) {& $QueueResponse $process.ExecutablePath $process.ProcessId $score $process}
            if($score.Score -gt 0 -and $Config.ScanReferencedScripts) {
                $scriptScore=[pscustomobject]@{Score=[math]::Max($score.Score,[int]$Config.ScorePolicy.DefenderCustomScan);Reasons=@($score.Reasons)+@('Referenced script static scan')}
                foreach($target in @(Get-SentinelScriptTargets -ExecutablePath $process.ExecutablePath -CommandLine $process.CommandLine)) {if(-not (Test-SentinelException -Path $target -Config $Config)){& $QueueResponse $target 0 $scriptScore $null}}
                $decoded=Save-SentinelDecodedCommand -Root $Root -CommandLine $process.CommandLine -ExecutablePath $process.ExecutablePath
                if($decoded) {& $QueueResponse $decoded 0 $scriptScore $null}
            }
            # Zero-score metadata is already durable; cache correlation candidates only.
            if($process.ProcessGuid -and $score.Score -gt 0) {
                $cache[$process.ProcessGuid]=[pscustomobject]@{Process=$process;BaseScore=[int]$score.Score;Reasons=@($score.Reasons);NetworkSeen=$false;DnsSeen=$false;SeenAt=$event.TimeCreated.ToString('o')}
            }
        } elseif($event.Id -in @(3,22)) {
            $guid=[string]$data.ProcessGuid
            if($guid -and $cache.ContainsKey($guid)) {
                $row=$cache[$guid]
                if([int]$row.BaseScore -gt 0) {
                    $flag=if($event.Id -eq 3){'NetworkSeen'}else{'DnsSeen'}
                    # Idempotent on retries: at most one boost per event type.
                    $row.$flag=$true
                    $boost=0;if($row.NetworkSeen){$boost+=5};if($row.DnsSeen){$boost+=5}
                    $score=[pscustomobject]@{Score=([int]$row.BaseScore+$boost);Reasons=@($row.Reasons)+@('ProcessGuid-correlated Sysmon network/DNS context')}
                    if($score.Score -ge [int]$Config.ScorePolicy.DefenderCustomScan) {
                        if(-not (Write-SentinelJsonLine (Join-Path $Root 'logs\alerts.jsonl') ([ordered]@{Type='SysmonCorrelatedActivity';Severity='MEDIUM';ProcessGuid=$guid;EventId=$event.Id;Score=$score.Score;Data=$data}))) {throw 'Cannot persist correlation alert.'}
                        & $QueueResponse $row.Process.ExecutablePath $row.Process.ProcessId $score $row.Process
                    }
                }
            }
        } elseif($event.Id -eq 255) {
            if(-not (Write-SentinelJsonLine (Join-Path $Root 'logs\alerts.jsonl') ([ordered]@{Type='SysmonTelemetryError';Severity='HIGH';RecordId=$event.RecordId;EventTime=$event.TimeCreated.ToString('o');Data=$data;Reason='Provider reported a telemetry error; do not assume complete process observation.'}))) {throw 'Cannot persist Sysmon telemetry error.'}
        } elseif($event.Id -in @(19,20,21,25)) {
            $kind=if($event.Id -eq 25){'SysmonProcessTampering'}else{'SysmonWmiPersistence'}
            if(-not (Write-SentinelJsonLine (Join-Path $Root 'logs\alerts.jsonl') ([ordered]@{Type=$kind;Severity='HIGH';EventId=$event.Id;RecordId=$event.RecordId;Data=$data;Reason='Suspicious telemetry requires review; no heuristic process termination.'}))) {throw 'Cannot persist Sysmon detection.'}
            $score=[pscustomobject]@{Score=[int]$Config.ScorePolicy.HighRisk;Reasons=@($kind)}
            if($event.Id -eq 25 -and $data.Image) {
                $row=if($data.ProcessGuid -and $cache.ContainsKey([string]$data.ProcessGuid)){$cache[[string]$data.ProcessGuid]}else{$null}
                if($row -and $row.Process.ExecutablePath -ieq [string]$data.Image) {& $QueueResponse $data.Image $row.Process.ProcessId $score $row.Process}
                else {& $QueueResponse $data.Image 0 $score $null}
            } elseif($event.Id -eq 20 -and $data.Destination) {
                foreach($target in @(Get-SentinelPersistenceTargets ([string]$data.Destination))) {if(Test-Path -LiteralPath $target -PathType Leaf){& $QueueResponse $target 0 $score $null}}
            }
        }
        if($cache.Count -gt 1000) {
            foreach($row in @($cache.Values | Sort-Object SeenAt | Select-Object -First ($cache.Count-1000))) {$cache.Remove([string]$row.Process.ProcessGuid)}
        }
        # Save correlation before cursor. A queue/log failure leaves this durable event retryable.
        Write-SentinelAtomicJson $cachePath ([ordered]@{Processes=@($cache.Values)})
        Write-SentinelAtomicJson $cursorPath ([ordered]@{RecordId=[long]$event.RecordId;TimeCreated=$event.TimeCreated.ToString('o')})
        if($AfterEvent){& $AfterEvent $event}
        # Yield only after this event is fully durable. A large backlog must not
        # monopolize the Watcher loop and starve heartbeat/Defender/health work.
        # One event (or the source query) can still exceed the cooperative budget.
        if((Get-SentinelSysmonMonotonicSeconds)-$processingStarted -ge $MaximumProcessingSeconds){break}
    }
}

function Get-SentinelSysmonMonotonicSeconds {
    return [double][Diagnostics.Stopwatch]::GetTimestamp()/[Diagnostics.Stopwatch]::Frequency
}

function Assert-SentinelSysmonDataPath {
    param([string]$Path)
    $ancestor=[IO.Path]::GetFullPath($Path)
    Assert-SentinelLogPath $ancestor
}

function Get-SentinelSysmonQueueState {
    param([string]$Root)
    $directory=Join-Path $Root 'state\sysmon-analysis'
    Assert-SentinelSysmonDataPath $directory
    $mutex=Enter-SentinelLogLock (Join-Path $Root 'state\sysmon-analysis.queue')
    try{
    $count=0L;$bytes=0L;$oldest=$null;$units=0
    foreach($lane in @('pending','processing')){
        $path=Join-Path $directory $lane
        Assert-SentinelSysmonDataPath $path
        if(-not (Test-Path -LiteralPath $path)){continue}
        foreach($file in @(Get-ChildItem -LiteralPath $path -Filter '*.json' -File -ErrorAction Stop)){
            if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 64MB -or $file.Name -cnotmatch '^\d{20}-[A-F0-9]{24}\.json$'){throw 'Unsafe or oversized analysis request refused.'}
            $unit=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            Assert-SentinelSysmonQueueUnit $unit
            $units++
            $count+=@($unit.Events).Count-[int]$unit.NextIndex;$bytes+=$file.Length
            if($unit.NextIndex -lt @($unit.Events).Count){$at=[datetimeoffset]$unit.Events[[int]$unit.NextIndex].TimeCreated;if($null -eq $oldest -or $at -lt $oldest){$oldest=$at}}
            elseif(@($unit.Events).Count -eq 0 -and $unit.Reset){$at=[datetimeoffset]$unit.QueuedAt;if($null -eq $oldest -or $at -lt $oldest){$oldest=$at}}
        }
    }
    [pscustomobject]@{PendingEvents=$count;Units=$units;Bytes=$bytes;OldestEventAt=$oldest}
    }finally{$mutex.ReleaseMutex();$mutex.Dispose()}
}

function Assert-SentinelSysmonQueueUnit {
    param($Unit)
    if($Unit.Schema -ne 1 -or $null -eq $Unit.NextIndex -or $Unit.NextIndex -lt 0 -or $Unit.NextIndex -gt @($Unit.Events).Count -or @($Unit.Events).Count -gt 1000 -or (@($Unit.Events).Count -eq 0 -and -not $Unit.Reset)){throw 'Invalid analysis queue unit.'}
    foreach($row in @($Unit.Events)){
        if($row.Id -notin @(1,3,4,16,19,20,21,22,25,255) -or [long]$row.RecordId -le 0 -or -not $row.Xml){throw 'Invalid recorded analysis event.'}
        [void][datetimeoffset]::Parse([string]$row.TimeCreated)
    }
}

function Get-SentinelSysmonAnalysisProcess {
    param([int]$ProcessIdValue)
    Get-CimInstance Win32_Process -Filter ('ProcessId='+$ProcessIdValue) -ErrorAction Stop
}

function Test-SentinelSysmonAnalysisIdentity {
    param([string]$Root,$Heartbeat,$Process)
    $expected='-File\s+"'+[regex]::Escape((Join-Path $Root 'Watcher.ps1'))+'"\s+-Root\s+"'+[regex]::Escape($Root)+'"\s+-AnalysisOnly\s*$'
    return $Process -and [int]$Heartbeat.ProcessId -gt 0 -and [int]$Process.ProcessId -eq [int]$Heartbeat.ProcessId -and
        $Process.ExecutablePath -ieq (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -and
        $Process.CommandLine -match $expected -and $Process.CreationDate -and
        ([datetimeoffset]([datetime]$Process.CreationDate).ToUniversalTime()) -le [datetimeoffset]$Heartbeat.LastUpdated
}

function Get-SentinelSysmonBacklog {
    param([string]$Root,$Config)
    $at=[datetimeoffset]::Now
    try{
        $sourceState=Get-SentinelSysmonSourceState
        if(-not $sourceState.Running -or -not $sourceState.ChannelEnabled){throw 'Sysmon service is stopped or its event channel is disabled; recorded events do not establish active capture.'}
        $cursor=0L;$time='';$cursorPath=Join-Path $Root 'state\sysmon-cursor.json'
        if(Test-Path -LiteralPath $cursorPath){$saved=Get-Content -LiteralPath $cursorPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop;$cursor=[long]$saved.RecordId;$time=[string]$saved.TimeCreated}
        $batch=Get-SentinelEventBatch -LogName 'Microsoft-Windows-Sysmon/Operational' -Cursor $cursor -CursorTime $time -Ids @(1,3,4,16,19,20,21,22,25,255) -BatchSize 1000
        $queue=Get-SentinelSysmonQueueState $Root
        $source=@($batch.Events);$oldest=if($source.Count){[datetimeoffset]$source[0].TimeCreated}else{$null}
        $sourceAge=if($oldest){($at-$oldest).TotalSeconds}else{0.0}
        $analysisAge=if($queue.OldestEventAt){($at-$queue.OldestEventAt).TotalSeconds}else{0.0}
        $beat=Get-Content -LiteralPath (Join-Path $Root 'state\sysmon-analysis-heartbeat.json') -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $process=Get-SentinelSysmonAnalysisProcess ([int]$beat.ProcessId)
        $age=($at-[datetimeoffset]$beat.LastUpdated).TotalSeconds
        if($beat.Version -ne $Config.Version -or $beat.Status -ne 'Running' -or $age -lt -5 -or $age -gt 120 -or -not (Test-SentinelSysmonAnalysisIdentity $Root $beat $process)){throw 'Analysis heartbeat/process identity is unavailable, stale or incorrect.'}
        if($sourceAge -lt -5 -or $analysisAge -lt -5){throw 'Source/queue event time is unexpectedly in the future.'}
        $status=if($batch.Reset){'Discontinuity'}elseif($sourceAge -gt 120 -or $analysisAge -gt 120){'Delayed'}else{'Healthy'}
        [pscustomobject]@{CheckedAt=$at.ToString('o');Status=$status;CursorRecordId=$cursor;SourcePendingEvents=$source.Count;SourceCountIsLowerBound=($source.Count -eq 1000);SourceOldestEventAt=$(if($oldest){$oldest.ToString('o')}else{$null});SourceOldestWaitSeconds=$sourceAge;AnalysisPendingEvents=$queue.PendingEvents;AnalysisBytes=$queue.Bytes;AnalysisOldestEventAt=$(if($queue.OldestEventAt){$queue.OldestEventAt.ToString('o')}else{$null});AnalysisOldestWaitSeconds=$analysisAge;AnalysisProcessId=[int]$beat.ProcessId;IngestionEventsPerSecond=(Get-SentinelRecentBatchRate $Root 'ingestion');AnalysisEventsPerSecond=(Get-SentinelRecentBatchRate $Root 'analysis');Error=$null}
    }catch{
        [pscustomobject]@{CheckedAt=$at.ToString('o');Status='Unverified';CursorRecordId=$null;SourcePendingEvents=$null;SourceCountIsLowerBound=$null;SourceOldestEventAt=$null;SourceOldestWaitSeconds=$null;AnalysisPendingEvents=$null;AnalysisBytes=$null;AnalysisOldestEventAt=$null;AnalysisOldestWaitSeconds=$null;AnalysisProcessId=$null;Error=$_.Exception.Message}
    }
}

function Get-SentinelSysmonSourceState {
    $services=@(Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Where-Object Status -eq Running)
    $channel=Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
    [pscustomobject]@{Running=($services.Count -gt 0);ChannelEnabled=[bool]$channel.IsEnabled}
}

function Get-SentinelRecentBatchRate {
    param([string]$Root,[ValidateSet('ingestion','analysis')][string]$Phase)
    try{
        $value=Get-Content -LiteralPath (Join-Path $Root ('state\sysmon-'+$Phase+'-metrics.json')) -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $age=([datetimeoffset]::Now-[datetimeoffset]$value.LastUpdated).TotalSeconds
        if($age -ge -5 -and $age -le 120 -and $value.Seconds -gt 0 -and $value.Events -ge 0){return [math]::Round($value.Events/$value.Seconds,2)}
    }catch{}
    return $null
}

function Get-SentinelContentSignatureStatus {
    param([string]$Path)
    # Deny writes/deletes while binding the status to actual file bytes. Neither
    # a recorded hash nor a path/mtime is sufficient to reuse a trust decision.
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        $sha=[Security.Cryptography.SHA256]::Create()
        try{$hash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','')}finally{$sha.Dispose()}
        $key=[IO.Path]::GetFullPath($Path).ToLowerInvariant()+'|'+$hash
        if(-not $script:SentinelSignatureCache){$script:SentinelSignatureCache=@{}}
        $entry=$script:SentinelSignatureCache[$key];$now=[datetimeoffset]::Now
        if($entry -and ($now-$entry.At).TotalSeconds -ge 0 -and ($now-$entry.At).TotalSeconds -le 15){return $entry.Status}
        $status=(Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop).Status
        if($script:SentinelSignatureCache.Count -ge 256){$script:SentinelSignatureCache.Clear()}
        $script:SentinelSignatureCache[$key]=[pscustomobject]@{At=$now;Status=$status}
        return $status
    }finally{$stream.Dispose()}
}

function Stop-SentinelSysmonAnalyzer {
    param([string]$Root)
    # A child may still be starting and have no heartbeat. Enumerate only the
    # exact designated command, then bind a handle and birth time before kill.
    foreach($process in @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction Stop)){
        $identity=[pscustomobject]@{ProcessId=[int]$process.ProcessId;LastUpdated=[datetimeoffset]::Now.ToString('o')}
        if(-not (Test-SentinelSysmonAnalysisIdentity $Root $identity $process)){continue}
        $native=$null
        try{
            $native=Get-Process -Id ([int]$process.ProcessId) -ErrorAction Stop
            [void]$native.Handle
            if([math]::Abs(($native.StartTime.ToUniversalTime()-([datetime]$process.CreationDate).ToUniversalTime()).TotalMilliseconds) -gt 1){throw 'Analyzer PID changed during shutdown.'}
            $native.Kill();if(-not $native.WaitForExit(5000)){throw 'Analyzer did not exit; deployment refused.'}
        }catch [Microsoft.PowerShell.Commands.ProcessCommandException]{
            # An already exited helper is safe; do not suppress other failures.
            if(Get-Process -Id ([int]$process.ProcessId) -ErrorAction SilentlyContinue){throw}
        }finally{if($native){$native.Dispose()}}
    }
}
function Receive-SentinelSysmonBatch {
    param([string]$Root,$Config)
    if(-not $Config.Sysmon.Enabled){return}
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $cursorPath=Join-Path $Root 'state\sysmon-cursor.json';$cursor=0L;$time=''
    if(Test-Path -LiteralPath $cursorPath){$saved=Get-Content -LiteralPath $cursorPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop;$cursor=[long]$saved.RecordId;$time=[string]$saved.TimeCreated}
    $limit=[math]::Min([int]$Config.EventBatchSize,[math]::Min(1000,[int]$Config.Resources.MaxQueueCount))
    $batch=Get-SentinelEventBatch -LogName 'Microsoft-Windows-Sysmon/Operational' -Cursor $cursor -CursorTime $time -Ids @(1,3,4,16,19,20,21,22,25,255) -BatchSize $limit
    if($batch.Reset){
        if(-not (Write-SentinelJsonLine (Join-Path $Root 'logs\alerts.jsonl') ([ordered]@{Type='EventLogCursorReset';Severity='HIGH';Log='Sysmon';PreviousCursor=$cursor}))){throw 'Cannot persist source discontinuity.'}
    }
    $events=@($batch.Events)
    if(-not $events.Count -and -not $batch.Reset){return}
    $queue=Get-SentinelSysmonQueueState $Root
    if($queue.PendingEvents+$events.Count -gt [int]$Config.Resources.MaxQueueCount -or $queue.Units -ge [int]$Config.Resources.MaxQueueCount){throw 'Sysmon analysis event capacity reached; source cursor retained.'}
    Assert-SentinelStorage -Root $Root -Config $Config
    $raw=@();$identities=@();$recorded=@()
    foreach($event in $events){
        $data=Get-SentinelEventData $event
        $raw+=@([ordered]@{Type='SysmonEvent';EventId=$event.Id;RecordId=$event.RecordId;EventTime=$event.TimeCreated.ToString('o');Data=$data})
        if($event.Id -eq 1){
            $process=ConvertFrom-SentinelSysmonProcess $data
            $complete=$process.ProcessId -gt 0 -and [IO.Path]::IsPathRooted($process.ExecutablePath) -and $process.CommandLine -and $process.ProcessGuid -and $process.ObservedSHA256
            $identities+=@([ordered]@{Type='ProcessCreated';Source='Sysmon';RecordId=$event.RecordId;EventTime=$event.TimeCreated.ToString('o');MetadataComplete=[bool]$complete;Process=$process})
        }
        if($event.Id -eq 255){if(-not (Write-SentinelJsonLine (Join-Path $Root 'logs\alerts.jsonl') ([ordered]@{Type='SysmonTelemetryError';Severity='HIGH';RecordId=$event.RecordId;EventTime=$event.TimeCreated.ToString('o');Data=$data}))){throw 'Cannot persist provider error.'}}
        $recorded+=@([ordered]@{Id=$event.Id;RecordId=[long]$event.RecordId;TimeCreated=$event.TimeCreated.ToString('o');Xml=$event.ToXml()})
    }
    $unit=[ordered]@{Schema=1;Reset=[bool]$batch.Reset;QueuedAt=[datetimeoffset]::Now.ToString('o');NextIndex=0;Events=$recorded}
    $unitBytes=3+[Text.Encoding]::UTF8.GetByteCount(($unit | ConvertTo-Json -Depth 20 -Compress))
    if($queue.Bytes+$unitBytes -gt [math]::Min(64MB,[long]$Config.Resources.MaxLogFileMB*1MB)){throw 'Sysmon analysis byte capacity reached; source cursor retained.'}
    if($raw.Count -and -not (Write-SentinelJsonBatch (Join-Path $Root 'logs\sysmon-events.jsonl') $raw)){throw 'Cannot persist source batch.'}
    if($identities.Count -and -not (Write-SentinelJsonBatch (Join-Path $Root 'logs\process-events.jsonl') $identities)){throw 'Cannot persist process batch.'}
    # Publish work only after evidence is durable, and acknowledge the source
    # only after evaluation work is durable. Replays are deliberately at-least-once.
    $identity=if($events.Count){$events[0].RecordId.ToString()+'|'+$events[0].TimeCreated.ToString('o')+'|'+$events[-1].RecordId}else{'reset|'+$cursor+'|'+$time}
    $key=(Get-SentinelStringHash $identity).Substring(0,24)
    $directory=Join-Path $Root 'state\sysmon-analysis'
    Assert-SentinelSysmonDataPath $directory
    $mutex=Enter-SentinelLogLock (Join-Path $Root 'state\sysmon-analysis.queue')
    try{
        $existing=@(foreach($lane in @('pending','processing')){$path=Join-Path $directory $lane;if(Test-Path -LiteralPath $path){Get-ChildItem -LiteralPath $path -Filter ('*-'+$key+'.json') -File -ErrorAction Stop}})
        if(-not $existing.Count){
            $sequencePath=Join-Path $directory 'sequence.json';$sequence=0L
            if(-not (Test-Path -LiteralPath $sequencePath) -and $queue.Units -gt 0){throw 'Analysis sequence missing while durable work exists.'}
            if(Test-Path -LiteralPath $sequencePath){$sequence=[long](Get-Content -LiteralPath $sequencePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop).Sequence}
            if($sequence -lt 0 -or $sequence -eq [long]::MaxValue){throw 'Invalid analysis sequence.'}
            $sequence++;Write-SentinelAtomicJson $sequencePath ([ordered]@{Sequence=$sequence})
            $name=('{0:D20}-{1}.json' -f $sequence,$key)
            Write-SentinelAtomicJson (Join-Path $directory ('pending\'+$name)) $unit
        }
    }finally{$mutex.ReleaseMutex();$mutex.Dispose()}
    $lastId=if($events.Count){[long]$events[-1].RecordId}else{0L};$lastTime=if($events.Count){$events[-1].TimeCreated.ToString('o')}else{''}
    Write-SentinelAtomicJson $cursorPath ([ordered]@{RecordId=$lastId;TimeCreated=$lastTime})
    Write-SentinelAtomicJson (Join-Path $Root 'state\sysmon-ingestion-metrics.json') ([ordered]@{LastUpdated=[datetimeoffset]::Now.ToString('o');Events=$events.Count;Seconds=$timer.Elapsed.TotalSeconds;AnalysisPendingAtLeast=($queue.PendingEvents+$events.Count);SourceRecordId=$lastId})
}

function Invoke-SentinelPendingSysmonAnalysis {
    param([string]$Root,$Config,[scriptblock]$ScoreProcess,[scriptblock]$QueueResponse,[scriptblock]$Progress)
    $directory=Join-Path $Root 'state\sysmon-analysis'
    Assert-SentinelSysmonDataPath $directory
    $queueMutex=Enter-SentinelLogLock (Join-Path $Root 'state\sysmon-analysis.queue')
    try{
    foreach($lane in @('pending','processing')){Assert-SentinelSysmonDataPath (Join-Path $directory $lane)}
    New-Item -ItemType Directory -Path (Join-Path $directory 'pending'),(Join-Path $directory 'processing') -Force | Out-Null
    $file=Get-ChildItem -LiteralPath (Join-Path $directory 'processing') -Filter '*.json' -File | Sort-Object Name | Select-Object -First 1
    if(-not $file){
        $file=Get-ChildItem -LiteralPath (Join-Path $directory 'pending') -Filter '*.json' -File | Sort-Object Name | Select-Object -First 1
        if(-not $file){return $false}
        if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 64MB){throw 'Reparse or oversized analysis request refused.'}
        $destination=Join-Path $directory ('processing\'+$file.Name)
        Move-Item -LiteralPath $file.FullName -Destination $destination -ErrorAction Stop
        $file=Get-Item -LiteralPath $destination
    }
    if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 64MB){throw 'Reparse or oversized analysis request refused.'}
    $unit=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    Assert-SentinelSysmonQueueUnit $unit
    }finally{$queueMutex.ReleaseMutex();$queueMutex.Dispose()}
    $events=@(for($i=[int]$unit.NextIndex;$i -lt @($unit.Events).Count;$i++){
        $row=$unit.Events[$i]
        $event=[pscustomobject]@{Id=[int]$row.Id;RecordId=[long]$row.RecordId;TimeCreated=([datetimeoffset]$row.TimeCreated).LocalDateTime;Xml=[string]$row.Xml;QueueIndex=$i}
        $event | Add-Member ScriptMethod ToXml {$this.Xml};$event
    })
    $startedIndex=[int]$unit.NextIndex;$timer=[Diagnostics.Stopwatch]::StartNew()
    Read-SentinelSysmon -Root $Root -Config $Config -ScoreProcess $ScoreProcess -QueueResponse $QueueResponse -MaximumProcessingSeconds 5 -RecordedBatch ([pscustomobject]@{Reset=($unit.Reset -and $unit.NextIndex -eq 0);Events=$events}) -AfterEvent {
        param($completed)
        $unit.NextIndex=[int]$completed.QueueIndex+1
        $progressMutex=Enter-SentinelLogLock (Join-Path $Root 'state\sysmon-analysis.queue')
        try{Write-SentinelAtomicJson $file.FullName $unit}finally{$progressMutex.ReleaseMutex();$progressMutex.Dispose()}
        if($Progress){& $Progress $completed}
    }
    Write-SentinelAtomicJson (Join-Path $Root 'state\sysmon-analysis-metrics.json') ([ordered]@{LastUpdated=[datetimeoffset]::Now.ToString('o');Events=([int]$unit.NextIndex-$startedIndex);Seconds=$timer.Elapsed.TotalSeconds})
    if($unit.NextIndex -eq @($unit.Events).Count){$progressMutex=Enter-SentinelLogLock (Join-Path $Root 'state\sysmon-analysis.queue');try{Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop}finally{$progressMutex.ReleaseMutex();$progressMutex.Dispose()}}
    return $true
}

function Initialize-SentinelProcessMonitor {
    param($Config)
    if(-not $Config.Sysmon.Enabled) {
        Register-CimIndicationEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier 'SentinelLocal.ProcessStart' -ErrorAction Stop | Out-Null
        return 'CIM'
    }
    $services=@(Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Where-Object Status -eq Running)
    $channel=Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
    if(-not $services.Count -or -not $channel.IsEnabled) {throw 'Sysmon process monitoring requires a running service and enabled readable event channel.'}
    return 'Sysmon'
}

function ConvertFrom-SentinelSysmonProcess {
    param($Data)
    $hashMatch=[regex]::Match([string]$Data.Hashes,'(?i)(?:^|,)SHA256=([a-f0-9]{64})(?:,|$)')
    # Only recorded creation data: never query a possibly exited/reused PID here.
    return [pscustomobject]@{
        ProcessId=[int]$Data.ProcessId;ParentProcessId=[int]$Data.ParentProcessId
        ExecutablePath=[string]$Data.Image;Name=[IO.Path]::GetFileName([string]$Data.Image)
        CommandLine=[string]$Data.CommandLine
        CreationDate=([datetime]::Parse([string]$Data.UtcTime,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)).ToUniversalTime().ToString('o')
        ProcessGuid=[string]$Data.ProcessGuid;ParentProcessGuid=[string]$Data.ParentProcessGuid
        ObservedSHA256=if($hashMatch.Success){$hashMatch.Groups[1].Value}else{''}
        IdentitySource='SysmonProcessCreate';LiveIdentityVerified=$false
    }
}
