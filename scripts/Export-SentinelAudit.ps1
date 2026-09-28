param([string]$Root='C:\ProgramData\SentinelLocal',[string]$DestinationPath,[switch]$Watch)
$ErrorActionPreference='Stop'
$commonPath=Join-Path $PSScriptRoot 'Common.ps1'
if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) { $commonPath=Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Common.ps1' }
. $commonPath
function Export-Snapshot {
    param([string]$Destination)
    if (-not $Destination -or -not [IO.Path]::IsPathRooted($Destination)) { throw 'An absolute local folder or UNC destination is required.' }
    $rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    $destinationFull=[IO.Path]::GetFullPath($Destination).TrimEnd('\')+'\'
    if ($destinationFull.StartsWith($rootPath,[StringComparison]::OrdinalIgnoreCase)) { throw 'Export destination must be outside the installation folder.' }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $snapshotId=('{0}-{1}-{2}' -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMddTHHmmssfff'),[guid]::NewGuid().ToString('N'))
    $stage=Join-Path $Destination ('.pending-'+$snapshotId)
    New-Item -ItemType Directory -Path $stage | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stage 'logs'),(Join-Path $stage 'state\log-chain') | Out-Null
    $files=@()
    foreach ($log in @(Get-ChildItem -LiteralPath (Join-Path $Root 'logs') -Filter '*.jsonl' -File -ErrorAction Stop)) {
        $mutex=Enter-SentinelLogLock $log.FullName
        try {
            $checkpoint=Get-SentinelLogCheckpoint $log.FullName
            if (-not (Test-SentinelSnapshotMatches (Get-SentinelLogSnapshot $log.FullName) $checkpoint)) { throw ('Cannot export invalid log: '+$log.Name) }
            Copy-Item -LiteralPath $log.FullName -Destination (Join-Path $stage ('logs\'+$log.Name))
            Write-SentinelAtomicJson (Join-Path $stage ('state\log-chain\'+$log.Name+'.state')) $checkpoint
            $files += [ordered]@{Name=$log.Name;SHA256=(Get-FileHash -LiteralPath $log.FullName -Algorithm SHA256).Hash;Length=$checkpoint.ByteLength;LastHash=$checkpoint.LastHash;LineCount=$checkpoint.LineCount}
        } finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
    }
    foreach ($heartbeatName in @('watcher-heartbeat.json','response-worker-heartbeat.json','integrity-monitor-heartbeat.json')) {
        $path=Join-Path $Root ('state\'+$heartbeatName)
        if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination (Join-Path $stage ('state\'+$heartbeatName)) }
    }
    $manifest=[ordered]@{Schema=1;ComputerName=$env:COMPUTERNAME;CapturedAt=(Get-Date).ToString('o');Files=$files}
    Write-SentinelAtomicJson (Join-Path $stage 'manifest.json') $manifest
    [IO.Directory]::Move($stage,(Join-Path $Destination $snapshotId))
    Write-Output (Join-Path $Destination $snapshotId)
}
do {
    $config=Get-Content -LiteralPath (Join-Path $Root 'Config.json') -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $destination=if($DestinationPath){$DestinationPath}else{[string]$config.AuditExport.DestinationPath}
    if ($Watch -and (-not $config.AuditExport.Enabled -or [int]$config.AuditExport.IntervalSeconds -lt 30)) { throw 'Enable AuditExport and configure an interval of at least 30 seconds before using -Watch.' }
    try { Export-Snapshot $destination }
    catch { Write-SentinelError -Root $Root -Component AuditExport -Operation Export -Exception $_.Exception; if (-not $Watch) { throw } }
    if ($Watch) { Start-Sleep -Seconds ([int]$config.AuditExport.IntervalSeconds) }
} while ($Watch)
