function Get-SentinelStatus {
    param([string]$Root='C:\ProgramData\SentinelLocal')
    $config=Get-Content -LiteralPath (Join-Path $Root 'Config.json') -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $components=@()
    foreach ($item in @(@{Name='Watcher';File='watcher-heartbeat.json';Stale=[int]$config.HeartbeatStaleSeconds},@{Name='ResponseWorker';File='response-worker-heartbeat.json';Stale=[int]$config.ResponseWorkerHeartbeatStaleSeconds},@{Name='IntegrityMonitor';File='integrity-monitor-heartbeat.json';Stale=[int]$config.SelfDefense.HeartbeatStaleSeconds})) {
        try {
            $heartbeat=Get-Content -LiteralPath (Join-Path $Root ('state\'+$item.File)) -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            $health=Test-SentinelHeartbeat -Heartbeat $heartbeat -StaleSeconds $item.Stale -BusyTimeoutSeconds ([int]$config.ResponseTimeoutSeconds)
            $components += [pscustomobject]@{Component=$item.Name;Healthy=$health.Healthy;Status=$heartbeat.Status;AgeSeconds=$health.AgeSeconds;ProcessAlive=$health.ProcessAlive;CurrentRequest=[string]$heartbeat.CurrentRequest}
        } catch { $components += [pscustomobject]@{Component=$item.Name;Healthy=$false;Status='Unavailable';AgeSeconds=$null;ProcessAlive=$false;CurrentRequest=$_.Exception.Message} }
    }
    $queues=@()
    foreach ($lane in @('high','normal','processing','failed')) {
        $files=@(Get-ChildItem -LiteralPath (Join-Path $Root ('state\response-queue\'+$lane)) -Filter '*.json' -File -ErrorAction SilentlyContinue)
        $oldest=if ($files.Count) { ((Get-Date)-($files | Sort-Object CreationTime | Select-Object -First 1).CreationTime).TotalSeconds } else { 0 }
        $queues += [pscustomobject]@{Queue=$lane;Count=$files.Count;OldestSeconds=[math]::Round($oldest,1);Delayed=($lane -in @('high','normal') -and $oldest -gt [int]$config.QueueWarningSeconds)}
    }
    try {
        $mp=Get-MpComputerStatus -ErrorAction Stop
        $defender=[pscustomobject]@{Mode=[string]$mp.AMRunningMode;AntivirusEnabled=[bool]$mp.AntivirusEnabled;RealTimeProtection=[bool]$mp.RealTimeProtectionEnabled;TamperProtection=[bool]$mp.IsTamperProtected;SignatureAgeDays=[int]$mp.AntivirusSignatureAge;Error=''}
    } catch { $defender=[pscustomobject]@{Mode='Unavailable';AntivirusEnabled=$false;RealTimeProtection=$false;TamperProtection=$null;SignatureAgeDays=$null;Error=$_.Exception.Message} }
    $alerts=@()
    foreach ($name in @('alerts.jsonl','errors.jsonl','defender-health-alerts.jsonl')) {
        $path=Join-Path $Root ('logs\'+$name)
        if (Test-Path -LiteralPath $path) {
            foreach ($line in @(Get-Content -LiteralPath $path -Tail 20 -Encoding UTF8)) {
                try { $alerts += $line | ConvertFrom-Json -ErrorAction Stop } catch { $alerts += [pscustomobject]@{Type='UnreadableLog';Severity='HIGH';Timestamp=(Get-Date).ToString('o');Error=$_.Exception.Message} }
            }
        }
    }
    $logHealth=@(Get-SentinelLogHealth $Root)
    try { $storage=Get-SentinelStorageStatus $Root $config } catch { $storage=[pscustomobject]@{Healthy=$false;Error=$_.Exception.Message} }
    return [pscustomobject]@{Version=$config.Version;ComputerName=$env:COMPUTERNAME;CapturedAt=(Get-Date).ToString('o');Healthy=($storage.Healthy -and @($queues | Where-Object { $_.Queue -eq "failed" -and $_.Count -gt 0 }).Count -eq 0 -and @($components | Where-Object { -not $_.Healthy }).Count -eq 0 -and @($queues | Where-Object Delayed).Count -eq 0 -and @($logHealth | Where-Object { -not $_.Healthy }).Count -eq 0 -and $defender.AntivirusEnabled -and $defender.RealTimeProtection -and $defender.Mode -eq 'Normal');Storage=$storage;Components=$components;Queues=$queues;Logs=$logHealth;Defender=$defender;Alerts=@($alerts | Sort-Object Timestamp -Descending | Select-Object -First 30)}
}
