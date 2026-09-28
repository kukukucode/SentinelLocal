function Get-SentinelDeploymentPath {
    param([string]$Root,[string]$Name)
    if($Name -ne 'state\integrity-baseline.json' -and $Name -notin @(Get-SentinelPackageFiles)) { throw 'Unexpected deployment file.' }
    $base=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    $path=[IO.Path]::GetFullPath((Join-Path $base $Name))
    if(-not $path.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)) { throw 'Deployment path escaped the installation root.' }
    return $path
}

function New-SentinelDeploymentBackup {
    param([string]$Root,[string]$BackupRoot,[hashtable]$Tasks)
    New-Item -ItemType Directory -Path $BackupRoot -ErrorAction Stop | Out-Null
    $entries=@()
    foreach($name in @((Get-SentinelPackageFiles)+@('state\integrity-baseline.json'))) {
        $path=Get-SentinelDeploymentPath $Root $name
        $exists=Test-Path -LiteralPath $path -PathType Leaf
        $hash=''
        if($exists) {
            $destination=Join-Path $BackupRoot $name
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
            Copy-Item -LiteralPath $path -Destination $destination -ErrorAction Stop
            $hash=(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
        }
        $entries += [pscustomobject]@{Name=$name;Existed=$exists;SHA256=$hash}
    }
    Write-SentinelAtomicJson (Join-Path $BackupRoot 'deployment.json') ([ordered]@{Schema=1;CreatedAt=(Get-Date).ToString('o');Files=$entries;Tasks=$Tasks})
}

function Restore-SentinelDeploymentBackup {
    param([string]$Root,[string]$BackupRoot)
    $manifest=Get-Content -LiteralPath (Join-Path $BackupRoot 'deployment.json') -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if($manifest.Schema -ne 1) { throw 'Unsupported deployment backup.' }
    $expected=@((Get-SentinelPackageFiles)+@('state\integrity-baseline.json'))
    if(@($manifest.Files).Count -ne $expected.Count) { throw 'Incomplete deployment backup.' }
    $seen=@{}
    foreach($entry in $manifest.Files) {
        [void](Get-SentinelDeploymentPath $Root $entry.Name)
        if($seen.ContainsKey([string]$entry.Name)) { throw 'Duplicate backup file.' }
        $seen[[string]$entry.Name]=$true
        if($entry.Existed -and (Get-FileHash -LiteralPath (Join-Path $BackupRoot $entry.Name) -Algorithm SHA256 -ErrorAction Stop).Hash -ne $entry.SHA256) { throw 'Backup hash verification failed; refusing partial restore.' }
    }
    foreach($entry in $manifest.Files) {
        $path=Get-SentinelDeploymentPath $Root $entry.Name
        if($entry.Existed) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $BackupRoot $entry.Name) -Destination $path -Force -ErrorAction Stop
        } elseif(Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
    }
    return $manifest
}

function Stop-SentinelDeploymentTasks {
    param([string]$Root,[int]$TimeoutSeconds=20)
    $names=@('SentinelLocal Watcher','SentinelLocal Response Worker','SentinelLocal Integrity Monitor')
    $childId=0
    try { $heartbeat=Get-Content -LiteralPath (Join-Path $Root 'state\response-worker-heartbeat.json') -Raw -Encoding UTF8 | ConvertFrom-Json;$childId=[int]$heartbeat.ChildProcessId } catch {}
    foreach($name in $names) { if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $name -ErrorAction Stop } }
    $deadline=[datetimeoffset]::Now.AddSeconds($TimeoutSeconds)
    do {
        $running=@(foreach($name in $names) { Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue | Where-Object { [string]$_.State -eq 'Running' } })
        if(-not $running.Count) { break }
        if([datetimeoffset]::Now -ge $deadline) { throw 'Scheduled tasks did not stop; deployment refused.' }
        Start-Sleep -Milliseconds 250
    } while($true)
    if($childId -gt 0) {
        $process=Get-CimInstance Win32_Process -Filter ("ProcessId="+$childId) -ErrorAction Stop
        if($process) {
            $observed=[pscustomobject]@{ExecutablePath=$process.ExecutablePath;CommandLine=$process.CommandLine}
            if(-not (Test-SentinelInternalResponse -Root $Root -ProcessInfo $observed)) { throw 'Response child identity changed; refusing to kill an unrelated process.' }
            Stop-Process -Id $childId -Force -ErrorAction Stop
        }
    }
}

function Wait-SentinelDeploymentReady {
    param([string]$Root,[string]$Version,[datetimeoffset]$StartedAfter,[int]$TimeoutSeconds=90)
    $deadline=[datetimeoffset]::Now.AddSeconds($TimeoutSeconds)
    do {
        $ready=$true
        foreach($name in @('watcher-heartbeat.json','response-worker-heartbeat.json','integrity-monitor-heartbeat.json')) {
            try {
                $heartbeat=Get-Content -LiteralPath (Join-Path $Root ('state\'+$name)) -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
                $health=Test-SentinelHeartbeat $heartbeat 30 180
                if(-not $health.Healthy -or $heartbeat.Version -ne $Version -or [datetimeoffset]::Parse($heartbeat.LastUpdated) -lt $StartedAfter) { $ready=$false }
            } catch { $ready=$false }
        }
        if($ready) { return }
        if([datetimeoffset]::Now -ge $deadline) { throw 'Deployment heartbeat verification timed out; rollback required.' }
        Start-Sleep -Milliseconds 500
    } while($true)
}
