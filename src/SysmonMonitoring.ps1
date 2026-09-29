function Read-SentinelSysmon {
    param([string]$Root,$Config,[scriptblock]$ScoreProcess,[scriptblock]$QueueResponse)
    if(-not $Config.Sysmon.Enabled) {return}
    $cursorPath=Join-Path $Root 'state\sysmon-cursor.json';$cachePath=Join-Path $Root 'state\sysmon-correlations.json'
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
    $batch=Get-SentinelEventBatch -LogName 'Microsoft-Windows-Sysmon/Operational' -Cursor $cursor -CursorTime $time -Ids @(1,3,19,20,21,22,25) -BatchSize ([int]$Config.EventBatchSize)
    if($batch.Reset) {
        if(-not (Write-SentinelJsonLine (Join-Path $Root 'logs\alerts.jsonl') ([ordered]@{Type='EventLogCursorReset';Severity='HIGH';Log='Sysmon';PreviousCursor=$cursor}))) {throw 'Cannot persist Sysmon cursor reset.'}
        $cache=@{};Write-SentinelAtomicJson $cachePath ([ordered]@{Processes=@()})
        Write-SentinelAtomicJson $cursorPath ([ordered]@{RecordId=0L;TimeCreated=''})
    }
    foreach($event in @($batch.Events)) {
        $data=Get-SentinelEventData $event
        if(-not (Write-SentinelJsonLine (Join-Path $Root 'logs\sysmon-events.jsonl') ([ordered]@{Type='SysmonEvent';EventId=$event.Id;RecordId=$event.RecordId;EventTime=$event.TimeCreated.ToString('o');Data=$data}))) {throw 'Cannot persist Sysmon event.'}
        # Expire by event time and bound cardinality; never correlate by a reused PID.
        $cutoff=([datetime]$event.TimeCreated).AddHours(-1)
        foreach($key in @($cache.Keys)) {if([datetimeoffset]::Parse([string]$cache[$key].SeenAt).LocalDateTime -lt $cutoff){$cache.Remove($key)}}
        if($event.Id -eq 1) {
            $hashMatch=[regex]::Match([string]$data.Hashes,'(?i)(?:^|,)SHA256=([a-f0-9]{64})(?:,|$)')
            $process=[pscustomobject]@{ProcessId=[int]$data.ProcessId;ParentProcessId=[int]$data.ParentProcessId;ExecutablePath=[string]$data.Image;Name=[IO.Path]::GetFileName([string]$data.Image);CommandLine=[string]$data.CommandLine;CreationDate=([datetime]::Parse([string]$data.UtcTime,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)).ToUniversalTime().ToString('o');ProcessGuid=[string]$data.ProcessGuid;ObservedSHA256=if($hashMatch.Success){$hashMatch.Groups[1].Value}else{''}}
            $score=& $ScoreProcess $process
            if($score.Score -ge [int]$Config.ScorePolicy.DefenderCustomScan -and -not (Test-SentinelException -Path $process.ExecutablePath -Config $Config)) {& $QueueResponse $process.ExecutablePath $process.ProcessId $score $process}
            if($score.Score -gt 0 -and $Config.ScanReferencedScripts) {
                $scriptScore=[pscustomobject]@{Score=[math]::Max($score.Score,[int]$Config.ScorePolicy.DefenderCustomScan);Reasons=@($score.Reasons)+@('Referenced script static scan')}
                foreach($target in @(Get-SentinelScriptTargets -ExecutablePath $process.ExecutablePath -CommandLine $process.CommandLine)) {if(-not (Test-SentinelException -Path $target -Config $Config)){& $QueueResponse $target 0 $scriptScore $null}}
                $decoded=Save-SentinelDecodedCommand -Root $Root -CommandLine $process.CommandLine -ExecutablePath $process.ExecutablePath
                if($decoded) {& $QueueResponse $decoded 0 $scriptScore $null}
            }
            if($process.ProcessGuid) {
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
    }
}
