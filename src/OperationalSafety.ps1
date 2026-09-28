function Assert-SentinelConfig {
    param($Config)
    $ranges=@{
        PollSeconds=@(1,60);PersistencePollSeconds=@(5,3600);DefenderHealthPollSeconds=@(10,3600)
        HeartbeatSeconds=@(1,300);HeartbeatStaleSeconds=@(5,3600);ResponseQueuePollSeconds=@(1,60)
        ResponseQueueMaxAttempts=@(1,20);ResponseWorkerHeartbeatSeconds=@(1,60);ResponseWorkerHeartbeatStaleSeconds=@(2,600)
        EventBatchSize=@(1,10000);ResponseTimeoutSeconds=@(1,3600);NormalResponseTimeoutSeconds=@(1,3600)
        ResponseRetryDelaySeconds=@(1,300);QueueWarningSeconds=@(1,86400);QueueWarningCount=@(1,100000)
        ResponseQueueDedupeSeconds=@(1,86400);ResponseHashDedupeSeconds=@(1,86400);MaxLogDays=@(1,3650)
        DefenderRemediationGraceSeconds=@(1,3600);UnresolvedDefenderDetectionAlertSeconds=@(1,86400);DefenderCorrelationWindowSeconds=@(1,86400)
        HeuristicKillThreshold=@(1,1000);FirewallRuleLifetimeMinutes=@(1,10080);FirewallCleanupSeconds=@(1,3600);ResponseQueueHighScore=@(1,1000)
    }
    foreach($key in $ranges.Keys) {
        $value=$Config.$key
        if(($value -isnot [int] -and $value -isnot [long]) -or [long]$value -lt $ranges[$key][0] -or [long]$value -gt $ranges[$key][1]) { throw ('Invalid configuration: '+$key) }
    }
    if($Config.NormalResponseTimeoutSeconds -gt $Config.ResponseTimeoutSeconds -or $Config.ResponseWorkerHeartbeatSeconds -ge $Config.ResponseWorkerHeartbeatStaleSeconds -or $Config.HeartbeatSeconds -ge $Config.HeartbeatStaleSeconds) { throw 'Invalid timeout/heartbeat relationship.' }
    if($Config.DefenderCorrelationWindowSeconds -le $Config.UnresolvedDefenderDetectionAlertSeconds) { throw 'Defender correlation window must cover unresolved detection alert delay.' }
    foreach($key in @('LogOnlyBelow','DefenderCustomScan','DeepEvidence','HighRisk')) { $value=$Config.ScorePolicy.$key;if(($value -isnot [int] -and $value -isnot [long]) -or $value -lt 0 -or $value -gt 1000) { throw ('Invalid score: '+$key) } }
    if($Config.ScorePolicy.DefenderCustomScan -gt $Config.ScorePolicy.DeepEvidence -or $Config.ScorePolicy.DeepEvidence -gt $Config.ScorePolicy.HighRisk) { throw 'Score thresholds must be ordered.' }
    if([int]$Config.ResponseQueueHighScore -lt [int]$Config.ScorePolicy.HighRisk) { throw 'High queue threshold must cover HighRisk.' }
    foreach($key in @('AutoContainDefenderDetections','AutoStopProcessWhenDefenderConfirms','AutoKillHeuristicProcesses','AutoFirewallBlockOnDefenderConfirmation','ScanReferencedScripts','EnablePtrLookup')) { if($Config.$key -isnot [bool]) { throw ('Expected boolean: '+$key) } }
    foreach($pair in @(@('SelfDefense','Enabled'),@('SelfDefense','IntegrityCheck'),@('SelfDefense','AutoRestartStoppedTasks'),@('DefenderHardening','ApplyOnInstall'),@('DefenderHardening','MonitorExpectedSettings'),@('Sysmon','Enabled'),@('AuditExport','Enabled'))) {
        if($Config.($pair[0]).($pair[1]) -isnot [bool]) { throw ('Expected boolean: '+($pair -join '.')) }
    }
    foreach($key in @('PollSeconds','HeartbeatSeconds','HeartbeatStaleSeconds')) { $value=$Config.SelfDefense.$key;if(($value -isnot [int] -and $value -isnot [long]) -or $value -lt 1 -or $value -gt 3600) { throw ('Invalid SelfDefense interval: '+$key) } }
    if($Config.SelfDefense.HeartbeatSeconds -ge $Config.SelfDefense.HeartbeatStaleSeconds) { throw 'Invalid SelfDefense heartbeat relationship.' }
    $interval=$Config.AuditExport.IntervalSeconds
    if(($interval -isnot [int] -and $interval -isnot [long]) -or $interval -lt 1 -or $interval -gt 86400 -or ($Config.AuditExport.Enabled -and -not ([string]$Config.AuditExport.DestinationPath).Trim())) { throw 'Invalid audit export policy.' }
    if($Config.DefenderHardening.ExpectedProfile -notin @('AuditFirst','RecommendedBlock') -or $Config.DefenderHardening.CloudBlockLevel -notin @('Default','Moderate','High','HighPlus','ZeroTolerance') -or $Config.DefenderHardening.ControlledFolderAccess -notin @('Disabled','Enabled','AuditMode','BlockDiskModificationOnly','AuditDiskModificationOnly') -or $Config.DefenderHardening.ASRMode -notin @('Disabled','Enabled','AuditMode','Warn')) { throw 'Invalid Defender hardening policy.' }
    if(-not $Config.Resources -or -not $Config.Scheduling) { throw 'Resource and scheduling policy required.' }
    foreach($key in @('MaxQueueCount','HighQueueReserve','MinFreeDiskMB','MaxEvidenceMB','MaxLogFileMB','StorageCheckSeconds')) {
        $value=$Config.Resources.$key
        if(($value -isnot [int] -and $value -isnot [long]) -or [long]$value -lt 1 -or [long]$value -gt 1000000) { throw ('Invalid resource policy: '+$key) }
    }
    if($Config.Resources.HighQueueReserve -ge $Config.Resources.MaxQueueCount) { throw 'High queue reserve must be below queue capacity.' }
    foreach($key in @('NormalAgingSeconds','HighBurstLimit')) { $value=$Config.Scheduling.$key; if(($value -isnot [int] -and $value -isnot [long]) -or [long]$value -lt 1 -or [long]$value -gt 86400) { throw ('Invalid scheduling policy: '+$key) } }
    foreach($entry in @($Config.Exceptions)) {
        if($null -eq $entry -or [string]$entry.SHA256 -notmatch '^[A-Fa-f0-9]{64}$' -or -not ([string]$entry.Reason).Trim()) { throw 'Invalid exception identity/reason.' }
        [void][datetimeoffset]::Parse([string]$entry.ExpiresAt)
        if($entry.SignerThumbprint -and [string]$entry.SignerThumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Invalid exception signer thumbprint.' }
    }
}

function Get-SentinelFileIdentity {
    param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { return ('UNRESOLVED-'+[guid]::NewGuid().ToString('N')) } # A failed hash never suppresses a scan.
}

function Test-SentinelCompletedHash {
    param([string]$Path,[string]$RequestHash,$Response)
    if(-not $RequestHash -or $Response.Status -ne 'Completed' -or $Response.File.SHA256 -ne $RequestHash) { return $false }
    try { return ((Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash -eq $RequestHash) }
    catch { return $false }
}

function Get-SentinelStorageStatus {
    param([string]$Root,$Config)
    $free=$null;$errorText=''
    try { $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Root)));$free=[long]$drive.AvailableFreeSpace }
    catch { $errorText=$_.Exception.Message }
    $evidenceBytes=0L
    $evidencePath=Join-Path $Root 'evidence'
    if(Test-Path -LiteralPath $evidencePath) {
        foreach($file in @(Get-ChildItem -LiteralPath $evidencePath -File -Recurse -ErrorAction Stop)) { $evidenceBytes += $file.Length }
    }
    $logOversize=@()
    foreach($file in @(Get-ChildItem -LiteralPath (Join-Path $Root 'logs') -File -ErrorAction SilentlyContinue)) {
        if($Config.Resources -and $file.Length -ge ([long]$Config.Resources.MaxLogFileMB*1MB)) { $logOversize += $file.Name }
    }
    $healthy=$null -ne $free -and $free -ge ([long]$Config.Resources.MinFreeDiskMB*1MB) -and $evidenceBytes -lt ([long]$Config.Resources.MaxEvidenceMB*1MB) -and $logOversize.Count -eq 0
    return [pscustomobject]@{Healthy=[bool]$healthy;FreeBytes=$free;EvidenceBytes=$evidenceBytes;OversizeLogs=$logOversize;Error=$errorText}
}

function Assert-SentinelStorage {
    param([string]$Root,$Config,[switch]$Evidence)
    # Cache only capacity observations, not file hashes or queue identities.
    if(-not $script:SentinelCapacityCache) { $script:SentinelCapacityCache=@{} }
    $key=[IO.Path]::GetFullPath($Root)
    $cached=$script:SentinelCapacityCache[$key]
    if(-not $cached -or ([datetimeoffset]::Now-$cached.At).TotalSeconds -ge [int]$Config.Resources.StorageCheckSeconds) {
        $cached=[pscustomobject]@{At=[datetimeoffset]::Now;State=(Get-SentinelStorageStatus $Root $Config)}
        $script:SentinelCapacityCache[$key]=$cached
    }
    if($null -eq $cached.State.FreeBytes -or $cached.State.FreeBytes -lt ([long]$Config.Resources.MinFreeDiskMB*1MB)) { throw 'Insufficient disk capacity; request/evidence creation refused.' }
    if($Evidence -and $cached.State.EvidenceBytes -ge ([long]$Config.Resources.MaxEvidenceMB*1MB)) { throw 'Evidence capacity reached; response will retry without deleting evidence.' }
}

function Assert-SentinelQueueCapacity {
    param([string]$Root,$Config,[string]$Priority)
    Assert-SentinelStorage $Root $Config
    $count=0
    foreach($lane in @('high','normal','processing')) { $count += @(Get-ChildItem -LiteralPath (Join-Path $Root ('state\response-queue\'+$lane)) -File -Filter '*.json' -ErrorAction SilentlyContinue).Count }
    $limit=[int]$Config.Resources.MaxQueueCount
    if($Priority -ne 'High') { $limit -= [int]$Config.Resources.HighQueueReserve }
    if($count -ge $limit) { throw ('Response queue capacity reached: '+$count+'/'+$limit+'. Event cursors and persistence baseline must not advance.') }
}

function Update-SentinelPersistenceSnapshot {
    param([string]$Root,[object[]]$Current,[scriptblock]$Compare)
    $path=Join-Path $Root 'state\persistence-snapshot.json'
    $previous=@()
    if(Test-Path -LiteralPath $path) {
        $saved=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        if($saved.Schema -ne 1 -or -not $saved.PSObject.Properties['Items']) { throw 'Invalid durable persistence snapshot; refusing to replace it.' }
        $previous=@($saved.Items)
        foreach($item in $previous) { if(-not $item -or $item.Type -notin @('Run','Startup','Task','Service') -or -not $item.Key -or -not $item.PSObject.Properties['Value']) { throw 'Invalid persistence entry; refusing to replace the snapshot.' } }
    }
    & $Compare $previous $Current
    Write-SentinelAtomicJson $path ([ordered]@{Schema=1;CapturedAt=(Get-Date).ToString('o');Items=@($Current)})
}

function Get-SentinelEligibleQueueFile {
    param([string]$QueueRoot,$Config,[int]$HighBurst=0)
    $candidates=@{}
    foreach($lane in @('high','normal')) {
        foreach($file in @(Get-ChildItem -LiteralPath (Join-Path $QueueRoot $lane) -File -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object CreationTime,Name)) {
            try {
                $request=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
                if($request.AvailableAfter -and [datetimeoffset]::Parse([string]$request.AvailableAfter) -gt [datetimeoffset]::Now) { continue }
                $queued=if($request.QueuedAt){[datetimeoffset]::Parse([string]$request.QueuedAt)}else{[datetimeoffset]$file.CreationTime}
            } catch { $queued=[datetimeoffset]$file.CreationTime }
            $candidates[$lane]=[pscustomobject]@{File=$file;Age=([datetimeoffset]::Now-$queued).TotalSeconds};break
        }
    }
    if($candidates.normal -and $HighBurst -ge [int]$Config.Scheduling.HighBurstLimit -and $candidates.normal.Age -ge [int]$Config.Scheduling.NormalAgingSeconds) { return $candidates.normal.File }
    if($candidates.high) { return $candidates.high.File }
    if($candidates.normal) { return $candidates.normal.File }
}

function ConvertTo-SentinelHtml {
    param($Value)
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}
