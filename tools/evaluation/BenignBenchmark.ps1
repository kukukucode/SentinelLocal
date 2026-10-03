. (Join-Path $PSScriptRoot 'BenignObservation.ps1')
. (Join-Path $PSScriptRoot 'Evaluation.ps1')

function Get-SentinelBenchmarkHealth([string]$Root,$Config) {
    $started=[datetimeoffset]::Now;$errors=@();$components=@()
    foreach($spec in @(@('watcher-heartbeat.json','WatcherProcessId','Watcher.ps1',$Config.HeartbeatStaleSeconds),@('response-worker-heartbeat.json','ResponseWorkerProcessId','ResponseWorker.ps1',$Config.ResponseWorkerHeartbeatStaleSeconds),@('integrity-monitor-heartbeat.json','IntegrityMonitorProcessId','IntegrityMonitor.ps1',$Config.SelfDefense.HeartbeatStaleSeconds))){
        try {
            $beat=Get-Content (Join-Path $Root ('state\'+$spec[0])) -Raw -Encoding UTF8 | ConvertFrom-Json
            $pidValue=[int]$beat.($spec[1]);$process=Get-EvaluationRuntimeProcess $pidValue
            $now=[datetimeoffset]::Now;$age=($now-[datetimeoffset]$beat.LastUpdated).TotalSeconds
            $expected='-File\s+"'+[regex]::Escape((Join-Path $Root $spec[2]))+'"\s+-Root\s+"'+[regex]::Escape($Root)+'"\s*$'
            if($beat.Version -ne $Config.Version -or $pidValue -le 0 -or -not $process -or [int]$process.ProcessId -ne $pidValue -or $process.ExecutablePath -ine (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -or $process.CommandLine -notmatch $expected){throw 'Runtime identity differs from expected component.'}
            if(-not $process.CreationDate -or ([datetimeoffset]([datetime]$process.CreationDate).ToUniversalTime()) -gt [datetimeoffset]$beat.LastUpdated){throw 'Runtime creation time does not match heartbeat.'}
            if($age -lt -5 -or $age -gt [int]$spec[3]){throw 'Heartbeat is stale or in the future.'}
            $statuses=if($spec[2] -eq 'ResponseWorker.ps1'){@('Idle','Busy')}else{@('Running')}
            if($beat.Status -notin $statuses){throw 'Component is not running.'}
            if($spec[2] -eq 'Watcher.ps1' -and $beat.ProcessMonitorMode -ne 'Sysmon'){throw 'Watcher process source is not Sysmon.'}
            if($beat.Status -eq 'Busy'){
                $elapsed=($now-[datetimeoffset]$beat.RequestStartedAt).TotalSeconds
                if(-not $beat.RequestStartedAt -or $elapsed -lt -5 -or $elapsed -gt [int]$Config.ResponseTimeoutSeconds){throw 'Worker busy request is invalid or overdue.'}
            }
            $components+=@([pscustomobject]@{Component=$spec[2];ProcessId=$pidValue;Status=$beat.Status;LastUpdated=$beat.LastUpdated;CheckedAt=$now.ToString('o');AgeSeconds=$age})
        }catch{$errors+=@($spec[2]+': '+$_.Exception.Message)}
    }
    try {if((Get-FileHash (Join-Path $Root 'Config.json')).Hash -ne $script:BenchmarkConfigHash){throw 'Configuration changed.'};[void](Get-EvaluationSysmonService)}catch{$errors+=@($_.Exception.Message)}
    return [pscustomobject]@{StartedAt=$started.ToString('o');EndedAt=[datetimeoffset]::Now.ToString('o');Healthy=($errors.Count -eq 0);Components=$components;Errors=$errors}
}

function Get-SentinelBenchmarkSummary($Trials,$Records,[bool]$ObservationValid) {
    $rows=@(foreach($trial in $Trials){
        $candidates=@($Records | Where-Object {
            $_.Type -eq 'ProcessCreated' -and $_.Source -eq 'Sysmon' -and $_.MetadataComplete -and
            $_.Process.ProcessId -eq $trial.ProcessId -and $_.Process.ExecutablePath -ieq $trial.ExecutablePath -and $_.Process.ObservedSHA256 -ieq $trial.SHA256 -and
            [math]::Abs((([datetimeoffset]$_.Process.CreationDate)-([datetimeoffset]$trial.ProcessCreatedAt)).TotalMilliseconds) -le 100 -and
            $_.Process.CommandLine -match ([regex]::Escape([string]$trial.Arguments)+'\s*$') -and
            ([datetimeoffset]$_.Timestamp) -ge ([datetimeoffset]$trial.StartedAt) -and ([datetimeoffset]$_.Timestamp) -le ([datetimeoffset]$trial.ObservationEndedAt)
        })
        # Replayed identical source events do not create multiple processes.
        $unique=@($candidates | Group-Object -Property {([string]$_.RecordId)+'|'+$_.Process.ProcessGuid+'|'+$_.Process.CreationDate+'|'+$_.Process.CommandLine+'|'+$_.Process.ObservedSHA256} | ForEach-Object {$_.Group | Sort-Object Timestamp | Select-Object -First 1})
        $state=if(-not $ObservationValid){'Unverified'}elseif($unique.Count -eq 1){'Captured'}elseif($unique.Count -eq 0){'NotCapturedInWindow'}else{'Ambiguous'}
        $record=if($unique.Count -eq 1){$unique[0]}else{$null}
        [pscustomobject]@{Id=$trial.Id;State=$state;ProcessId=$trial.ProcessId;ProcessGuid=$(if($record){$record.Process.ProcessGuid}else{$null});RecordId=$(if($record){$record.RecordId}else{$null});PersistedAt=$(if($record){$record.Timestamp}else{$null});PersistDelaySeconds=$(if($state -eq 'Captured'){(([datetimeoffset]$record.Timestamp)-([datetimeoffset]$trial.StartedAt)).TotalSeconds}else{$null});SysmonDelaySeconds=$(if($state -eq 'Captured'){(([datetimeoffset]$record.EventTime)-([datetimeoffset]$trial.StartedAt)).TotalSeconds}else{$null})}
    })
    $captured=@($rows | Where-Object State -eq Captured)
    $ambiguous=@($rows | Where-Object State -eq Ambiguous).Count
    $valid=$ObservationValid -and @($Trials).Count -gt 0 -and $ambiguous -eq 0 -and @($captured | ForEach-Object {$_.ProcessGuid} | Sort-Object -Unique).Count -eq $captured.Count
    return [pscustomobject]@{ObservationValid=$valid;TrialCount=@($Trials).Count;CapturedTrials=$captured.Count;NotCapturedTrials=@($rows | Where-Object State -eq NotCapturedInWindow).Count;AmbiguousTrials=$ambiguous;CaptureFraction=$(if($valid){Get-EvaluationRate $captured.Count @($Trials).Count}else{$null});PersistDelaySeconds=$(if($valid){Get-EvaluationLatency @($captured | ForEach-Object {$_.PersistDelaySeconds})}else{Get-EvaluationLatency @()});SysmonDelaySeconds=$(if($valid){Get-EvaluationLatency @($captured | ForEach-Object {$_.SysmonDelaySeconds})}else{Get-EvaluationLatency @()});Trials=$rows;DetectionPerformanceMeasured=$false;AlertReviewRequired=$true;FalsePositiveRate=$null;MalwareDetectionRate=$null;TimeToDetect=$null;AttackCoverage=$null}
}

function Invoke-SentinelBenignBenchmark([string]$Root,[string]$OutputDirectory,[int]$Rounds=10,[int]$ObservationSeconds=120) {
    if($Rounds -lt 1 -or $Rounds -gt 100 -or $ObservationSeconds -lt 60 -or $ObservationSeconds -gt 600){throw 'Rounds must be 1..100 and observation window 60..600 seconds.'}
    $rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\');$output=[IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
    if($output -ieq $rootPath -or $output.StartsWith($rootPath+'\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path $output)){throw 'Choose a new output folder outside the installation.'}
    foreach($candidate in @($rootPath,$output)){
        $ancestor=$candidate
        while($ancestor){if((Test-Path $ancestor) -and ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Benchmark paths must not traverse reparse points.'};$parent=Split-Path -Parent $ancestor;if($parent -eq $ancestor){break};$ancestor=$parent}
    }
    $pre=Wait-SentinelObservationBaseline $rootPath
    if(-not $pre.ReadyForBenignTrials -or -not $pre.Environment.SysmonEnabled){throw 'A healthy, idle, Sysmon-enabled measurement baseline is required.'}
    New-Item -ItemType Directory -Path $output | Out-Null
    Write-SentinelAtomicJson (Join-Path $output 'readiness-before.json') $pre
    $config=Get-Content (Join-Path $rootPath 'Config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $script:BenchmarkConfigHash=$pre.Environment.ConfigSHA256
    $trials=@();$samples=@();$errors=@();$deadline=$null;$lastSample=[datetimeoffset]::MinValue
    $plan=[ordered]@{Rounds=$Rounds;TrialCount=$Rounds*3;ObservationSeconds=$ObservationSeconds;TargetSampleIntervalSeconds=5;MaximumSampleGapSeconds=30;Commands=@(Get-SentinelBenignScenarios);Scope='Fixed Windows commands only; overlapping per-process observation windows. Sampled health is not continuous attestation. No Windows configuration changes.'}
    Write-SentinelAtomicJson (Join-Path $output 'plan.json') $plan
    try {
        for($round=1;$round -le $Rounds;$round++){
            foreach($scenario in Get-SentinelBenignScenarios){
                if(([datetimeoffset]::Now-$lastSample).TotalSeconds -ge 5){$samples+=@(Get-SentinelBenchmarkHealth $rootPath $config);$lastSample=[datetimeoffset]::Now;Write-SentinelAtomicJson (Join-Path $output 'health-samples.json') $samples;if(-not $samples[-1].Healthy){throw 'Runtime health sampling failed.'}}
                $trial=Invoke-SentinelBenignCommand $scenario
                $trial.Id=('round-'+$round+'-'+$scenario.Id)
                $trial | Add-Member NoteProperty ObservationEndedAt (([datetimeoffset]$trial.StartedAt).AddSeconds($ObservationSeconds).ToString('o'))
                $trials+=@($trial);$deadline=[datetimeoffset]$trial.ObservationEndedAt
                Write-SentinelAtomicJson (Join-Path $output 'commands.json') $trials
                Start-Sleep -Seconds 1
            }
            Write-Host ('Benign launches: '+$trials.Count+'/'+$plan.TrialCount)
        }
        $lastProgress=[datetimeoffset]::MinValue
        while([datetimeoffset]::Now -lt $deadline){
            if(([datetimeoffset]::Now-$lastSample).TotalSeconds -ge 5){$samples+=@(Get-SentinelBenchmarkHealth $rootPath $config);$lastSample=[datetimeoffset]::Now;Write-SentinelAtomicJson (Join-Path $output 'health-samples.json') $samples;if(-not $samples[-1].Healthy){throw 'Runtime health sampling failed.'}}
            Start-Sleep -Seconds 1
            if(([datetimeoffset]::Now-$lastProgress).TotalSeconds -ge 15){Write-Host ('Observation tail: '+[math]::Ceiling(($deadline-[datetimeoffset]::Now).TotalSeconds)+' seconds remaining; health samples='+$samples.Count);$lastProgress=[datetimeoffset]::Now}
        }
    }catch{$errors+=@($_.Exception.Message)}
    $samples+=@(Get-SentinelBenchmarkHealth $rootPath $config)
    Write-SentinelAtomicJson (Join-Path $output 'health-samples.json') $samples
    try {$post=Wait-SentinelObservationBaseline $rootPath}
    catch {$errors+=@($_.Exception.Message);$post=[pscustomobject]@{ReadyForBenignTrials=$false;Environment=[pscustomobject]@{ConfigSHA256=$null};Error=$_.Exception.Message}}
    Write-SentinelAtomicJson (Join-Path $output 'readiness-after.json') $post
    $maxGap=0.0
    for($i=0;$i -lt $samples.Count;$i++){
        $duration=(([datetimeoffset]$samples[$i].EndedAt)-([datetimeoffset]$samples[$i].StartedAt)).TotalSeconds;$maxGap=[math]::Max($maxGap,$duration)
        if($i){$gap=(([datetimeoffset]$samples[$i].StartedAt)-([datetimeoffset]$samples[$i-1].StartedAt)).TotalSeconds;$maxGap=[math]::Max($maxGap,$gap)}
    }
    if(-not $post.ReadyForBenignTrials -or $post.Environment.ConfigSHA256 -ne $pre.Environment.ConfigSHA256 -or @($samples | Where-Object {-not $_.Healthy}).Count -or $maxGap -gt 30 -or $trials.Count -ne $plan.TrialCount -or ($deadline -and [datetimeoffset]::Now -lt $deadline)){$errors+=@('Observation baseline, sampling gap, planned commands or final observation window was incomplete.')}
    $snapshot=$null;$records=@();$defenderStatus='Unverified';$native=@();$windowStart=$null;$windowEnd=$null
    if($trials.Count){$windowStart=[datetimeoffset]$trials[0].StartedAt;$windowEnd=[datetimeoffset]$trials[-1].ObservationEndedAt}
    try {
        $snapshot=@(& (Join-Path $evaluationRepo 'scripts\Export-SentinelAudit.ps1') -Root $rootPath -DestinationPath (Join-Path $output 'sentinel'))[0]
        $path=Join-Path $snapshot 'logs\process-events.jsonl'
        if(-not (Get-SentinelLogVerification $path).Valid){throw 'Process snapshot verification failed.'}
        $records=@(Get-Content $path -Encoding UTF8 | ForEach-Object {$_ | ConvertFrom-Json})
        $source=@(Get-Content (Join-Path $snapshot 'logs\sysmon-events.jsonl') -Encoding UTF8 | ForEach-Object {$_ | ConvertFrom-Json})
        if($windowStart -and @($source | Where-Object {$_.EventId -eq 255 -and [datetimeoffset]$_.EventTime -ge $windowStart -and [datetimeoffset]$_.EventTime -le $windowEnd}).Count){throw 'Sysmon reported a provider error in the observation window.'}
        [void](Get-EvaluationEventChannel 'Microsoft-Windows-Windows Defender/Operational')
        if($windowStart){
            try{$native=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';StartTime=$windowStart.LocalDateTime;EndTime=$windowEnd.LocalDateTime} -MaxEvents 10001 -ErrorAction Stop)}catch{if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}}
            if($native.Count -gt 10000){throw 'Defender evidence would be truncated.'}
        }
        $defender=@($native | Sort-Object RecordId | ForEach-Object {[pscustomobject]@{Id=$_.Id;RecordId=$_.RecordId;TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o');Data=(Get-SentinelEventData $_);Xml=$_.ToXml()}})
        Write-SentinelAtomicJson (Join-Path $output 'defender-events.json') $defender;$defenderStatus='ReadSucceeded'
    }catch{$errors+=@($_.Exception.Message)}
    $summary=Get-SentinelBenchmarkSummary $trials $records ($errors.Count -eq 0)
    $packet=[ordered]@{Schema=1;Kind='BenignBenchmarkPacket';CapturedAt=[datetimeoffset]::Now.ToString('o');Root=$rootPath;Environment=$pre.Environment;Plan=$plan;Trials=$trials;Snapshot=$snapshot;DefenderStatus=$defenderStatus;HealthSampleCount=$samples.Count;MaximumSampleGapSeconds=$maxGap;Errors=$errors;Capture=$summary;PerformanceMeasured=$false;ReviewRequired=$true;Scope='Capture fraction and ingestion timing for this fixed benign workload. Alert attribution must be reviewed separately; no malware efficacy or ATT&CK measurement.'}
    Write-SentinelAtomicJson (Join-Path $output 'benchmark.json') $packet
    $lines=@('# SentinelLocal benign capture measurement','',('Valid observation: '+$summary.ObservationValid),('Launches: '+$trials.Count+'/'+$plan.TrialCount),('Captured within window: '+$summary.CapturedTrials+'/'+$summary.TrialCount),('Capture fraction: '+(Format-EvaluationNumber $summary.CaptureFraction -Rate)),('Persist delay median / p95 / maximum (seconds): '+(Format-EvaluationNumber $summary.PersistDelaySeconds.Median)+' / '+(Format-EvaluationNumber $summary.PersistDelaySeconds.P95)+' / '+(Format-EvaluationNumber $summary.PersistDelaySeconds.Maximum)),('Maximum sampling gap (seconds): '+$maxGap),'','Alert attribution: review required. False positive rate, malware detection rate, time-to-detect and ATT&CK coverage: N/A.','Capture/ingestion timing is not detection latency. Sampling does not prove uninterrupted protection.',('Errors: '+($errors -join '; ')))
    [IO.File]::WriteAllLines((Join-Path $output 'summary.md'),$lines,[Text.UTF8Encoding]::new($true))
    return [pscustomobject]$packet
}
