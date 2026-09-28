function Read-SentinelSysmon {
    param([string]$Root,$Config,[scriptblock]$ScoreProcess,[scriptblock]$QueueResponse)
    if (-not $Config.Sysmon.Enabled) { return }
    $cursorPath=Join-Path $Root 'state\sysmon-cursor.json'
    $cursor=0L; $time=''
    if (Test-Path -LiteralPath $cursorPath) {
        $saved=Get-Content -LiteralPath $cursorPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        $cursor=[long]$saved.RecordId; $time=[string]$saved.TimeCreated
    }
    $batch=Get-SentinelEventBatch -LogName 'Microsoft-Windows-Sysmon/Operational' -Cursor $cursor -CursorTime $time -Ids @(1,3,19,20,21,22,25) -BatchSize ([int]$Config.EventBatchSize)
    if ($batch.Reset) {
        if (-not (Write-SentinelJsonLine -Path (Join-Path $Root 'logs\alerts.jsonl') -Data ([ordered]@{Type='EventLogCursorReset';Severity='HIGH';Log='Sysmon';PreviousCursor=$cursor}))) { throw 'Cannot persist Sysmon cursor reset.' }
        Write-SentinelAtomicJson $cursorPath ([ordered]@{RecordId=0L;TimeCreated=''})
    }
    foreach ($event in @($batch.Events)) {
        $data=Get-SentinelEventData $event
        if (-not (Write-SentinelJsonLine -Path (Join-Path $Root 'logs\sysmon-events.jsonl') -Data ([ordered]@{Type='SysmonEvent';EventId=$event.Id;RecordId=$event.RecordId;EventTime=$event.TimeCreated.ToString('o');Data=$data}))) { throw 'Cannot persist Sysmon event.' }
        if ($event.Id -eq 1) {
            $process=[pscustomobject]@{ProcessId=[int]$data.ProcessId;ParentProcessId=[int]$data.ParentProcessId;ExecutablePath=[string]$data.Image;Name=[IO.Path]::GetFileName([string]$data.Image);CommandLine=[string]$data.CommandLine;CreationDate=([datetime]::Parse([string]$data.UtcTime,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)).ToUniversalTime().ToString('o');ProcessGuid=[string]$data.ProcessGuid}
            $score=& $ScoreProcess $process
            if ($score.Score -ge [int]$Config.ScorePolicy.DefenderCustomScan) {
                if (-not (Test-SentinelException -Path $process.ExecutablePath -Config $Config)) { & $QueueResponse $process.ExecutablePath $process.ProcessId $score $process }
            }
            if ($score.Score -gt 0 -and $Config.ScanReferencedScripts) {
                $scriptScore=[pscustomobject]@{Score=[math]::Max($score.Score,[int]$Config.ScorePolicy.DefenderCustomScan);Reasons=@($score.Reasons)+@('Referenced script static scan')}
                foreach ($target in @(Get-SentinelScriptTargets -ExecutablePath $process.ExecutablePath -CommandLine $process.CommandLine)) {
                    if (-not (Test-SentinelException -Path $target -Config $Config)) { & $QueueResponse $target 0 $scriptScore $null }
                }
                $decoded=Save-SentinelDecodedCommand -Root $Root -CommandLine $process.CommandLine -ExecutablePath $process.ExecutablePath
                if ($decoded) { & $QueueResponse $decoded 0 $scriptScore $null }
            }
        }
        Write-SentinelAtomicJson $cursorPath ([ordered]@{RecordId=[long]$event.RecordId;TimeCreated=$event.TimeCreated.ToString('o')})
    }
}
