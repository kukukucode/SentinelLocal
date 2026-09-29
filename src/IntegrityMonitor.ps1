param(
    [string]$Root = "C:\ProgramData\SentinelLocal"
)

$ErrorActionPreference = "Stop"
. (Join-Path $Root "Common.ps1")

$config = Get-Content (Join-Path $Root "Config.json") -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$logs = Join-Path $Root "logs"
$state = Join-Path $Root "state"
$alertLog = Join-Path $logs "alerts.jsonl"
$heartbeatPath = Join-Path $state "integrity-monitor-heartbeat.json"
$baselinePath = Join-Path $state "integrity-baseline.json"
$lastAlertStatePath = Join-Path $state "integrity-last-alerts.json"
New-Item $logs,$state -ItemType Directory -Force | Out-Null

$createdNew = $false
$mutex = New-Object System.Threading.Mutex($true, "Global\SentinelLocalIntegrityMonitor", [ref]$createdNew)
if (-not $createdNew) { exit 0 }

$lastAlerts = @{}
if (Test-Path -LiteralPath $lastAlertStatePath) {
    try {
        foreach ($item in @(Get-Content $lastAlertStatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)) {
            if ($item.Key) { $lastAlerts[[string]$item.Key] = [string]$item.Fingerprint }
        }
    } catch {
        Write-SentinelError -Root $Root -Component "IntegrityMonitor" -Operation "Load alert dedupe state" -Exception $_.Exception -Severity "MEDIUM"
    }
}

function Save-LastAlerts {
    try {
        $rows = @($lastAlerts.Keys | ForEach-Object {
            [pscustomobject]@{Key=$_;Fingerprint=[string]$lastAlerts[$_]}
        })
        ConvertTo-Json -InputObject @($rows) -Depth 5 | Set-Content -LiteralPath $lastAlertStatePath -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-SentinelError -Root $Root -Component "IntegrityMonitor" -Operation "Save alert dedupe state" -Exception $_.Exception -Severity "MEDIUM"
    }
}

function Write-GuardianHeartbeat {
    $data = [ordered]@{
        Version=[string]$config.Version
        Status="Running"
        IntegrityMonitorProcessId=[System.Diagnostics.Process]::GetCurrentProcess().Id
        LastUpdated=(Get-Date).ToString("o")
    }
    try {
        Write-SentinelAtomicJson $heartbeatPath $data
    } catch {
        Write-SentinelError -Root $Root -Component "IntegrityMonitor" -Operation "Write heartbeat" -Exception $_.Exception
    }
}

function Alert-Once {
    param(
        [string]$Key,
        [string]$Fingerprint,
        [string]$Type,
        [string]$Severity,
        [hashtable]$Fields
    )

    if ($lastAlerts.ContainsKey($Key) -and $lastAlerts[$Key] -eq $Fingerprint) { return }
    $lastAlerts[$Key] = $Fingerprint

    $data = [ordered]@{
        Type=$Type
        Severity=$Severity
    }
    foreach ($field in $Fields.Keys) { $data[$field] = $Fields[$field] }
    [void](Write-SentinelJsonLine -Path $alertLog -Data $data)
    Save-LastAlerts
}

function Clear-AlertKey {
    param([string]$Key)
    if ($lastAlerts.ContainsKey($Key)) {
        [void]$lastAlerts.Remove($Key)
        Save-LastAlerts
    }
}

function Check-Tasks {
    foreach ($taskName in @("SentinelLocal Watcher","SentinelLocal Response Worker","SentinelLocal Integrity Monitor")) {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if (-not $task) {
            Alert-Once -Key ("TaskMissing|" + $taskName) -Fingerprint "missing" -Type "SentinelSelfDefense" -Severity "CRITICAL" -Fields @{
                Component="ScheduledTask";TaskName=$taskName;Reason="SentinelLocal scheduled task is missing."
            }
            continue
        }

        $definitionOk=Test-SentinelTaskDefinition -Task $task -Root $Root -TaskName $taskName
        $action=@($task.Actions)[0]
        $fingerprint=Get-SentinelStringHash ($task | ConvertTo-Json -Depth 12 -Compress)
        if ([string]$task.State -eq "Disabled" -or -not $definitionOk) {
            Alert-Once -Key ("TaskState|" + $taskName) -Fingerprint $fingerprint -Type "SentinelSelfDefense" -Severity "CRITICAL" -Fields @{
                Component="ScheduledTask";TaskName=$taskName;State=[string]$task.State;Arguments=[string]$action.Arguments
                Reason="SentinelLocal task disabled or action, executable, arguments, principal or startup trigger differs."
            }
            if ($definitionOk -and $config.SelfDefense.AutoRestartStoppedTasks -and [string]$task.State -eq "Disabled") {
                try { Enable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null }
                catch { Write-SentinelError -Root $Root -Component "IntegrityMonitor" -Operation "Re-enable task" -Exception $_.Exception -Context @{TaskName=$taskName} }
            }
        } else {
            Clear-AlertKey ("TaskMissing|" + $taskName)
            Clear-AlertKey ("TaskState|" + $taskName)
        }
    }
}

function Check-Heartbeats {
    $checks = @(
        @{Name="Watcher";Path=(Join-Path $state "watcher-heartbeat.json");Stale=[int]$config.HeartbeatStaleSeconds;Busy=$false},
        @{Name="ResponseWorker";Path=(Join-Path $state "response-worker-heartbeat.json");Stale=[int]$config.ResponseWorkerHeartbeatStaleSeconds;Busy=$true}
    )

    foreach ($check in $checks) {
        $key = "Heartbeat|" + $check.Name
        if (-not (Test-Path -LiteralPath $check.Path)) {
            Alert-Once -Key $key -Fingerprint "missing" -Type "SentinelSelfDefense" -Severity "HIGH" -Fields @{
                Component="Heartbeat";Target=$check.Name;Reason="Heartbeat file is missing."
            }
            continue
        }

        try {
            $heartbeat = Get-Content $check.Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $age = ((Get-Date) - ([datetimeoffset]::Parse([string]$heartbeat.LastUpdated)).LocalDateTime).TotalSeconds
            $processIdValue = if ($heartbeat.WatcherProcessId) { [int]$heartbeat.WatcherProcessId } elseif ($heartbeat.ResponseWorkerProcessId) { [int]$heartbeat.ResponseWorkerProcessId } else { 0 }
            $processAlive = if ($processIdValue -gt 0) { [bool](Get-Process -Id $processIdValue -ErrorAction SilentlyContinue) } else { $false }
            $healthy = $age -le [int]$check.Stale
            $healthy=(Test-SentinelHeartbeat -Heartbeat $heartbeat -StaleSeconds ([int]$check.Stale) -BusyTimeoutSeconds ([int]$config.ResponseTimeoutSeconds)).Healthy

            if (-not $healthy) {
                $fingerprint = "{0}|{1}|{2}" -f [string]$heartbeat.Status,[math]::Floor($age / 30),$processAlive
                Alert-Once -Key $key -Fingerprint $fingerprint -Type "SentinelSelfDefense" -Severity "CRITICAL" -Fields @{
                    Component="Heartbeat";Target=$check.Name;Status=[string]$heartbeat.Status;AgeSeconds=[math]::Round($age,1);ProcessAlive=$processAlive
                    Reason="SentinelLocal component heartbeat is stale or the process is unavailable."
                }
            } else {
                Clear-AlertKey $key
            }
        } catch {
            Alert-Once -Key $key -Fingerprint ("parse|" + $_.Exception.Message) -Type "SentinelSelfDefense" -Severity "HIGH" -Fields @{
                Component="Heartbeat";Target=$check.Name;Reason=("Heartbeat parse failed: " + $_.Exception.Message)
            }
        }
    }
}

function Check-FileIntegrity {
    if (-not $config.SelfDefense.IntegrityCheck) { return }

    if (-not (Test-Path -LiteralPath $baselinePath)) {
        Alert-Once -Key "IntegrityBaseline" -Fingerprint "missing" -Type "SentinelSelfDefense" -Severity "CRITICAL" -Fields @{
            Component="Integrity";Reason="Integrity baseline is missing."
        }
        return
    }

    try {
        $baseline = Read-SentinelBaseline $Root
        Clear-AlertKey "IntegrityBaseline"

        foreach ($entry in @($baseline.Files)) {
            $key = "File|" + [string]$entry.Name
            if (-not (Test-Path -LiteralPath ([string]$entry.Path) -PathType Leaf)) {
                Alert-Once -Key $key -Fingerprint "missing" -Type "SentinelSelfDefense" -Severity "CRITICAL" -Fields @{
                    Component="FileIntegrity";File=[string]$entry.Name;Path=[string]$entry.Path;Reason="Critical SentinelLocal file is missing."
                }
                continue
            }

            $hash = (Get-FileHash -LiteralPath ([string]$entry.Path) -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($hash -ne [string]$entry.SHA256) {
                Alert-Once -Key $key -Fingerprint $hash -Type "SentinelSelfDefense" -Severity "CRITICAL" -Fields @{
                    Component="FileIntegrity";File=[string]$entry.Name;Path=[string]$entry.Path
                    ExpectedSHA256=[string]$entry.SHA256;ActualSHA256=$hash
                    Reason="Critical SentinelLocal file hash changed after the integrity baseline was created."
                }
            } else {
                Clear-AlertKey $key
            }
        }
    } catch {
        Alert-Once -Key "IntegrityCheckError" -Fingerprint $_.Exception.Message -Type "SentinelSelfDefense" -Severity "HIGH" -Fields @{
            Component="Integrity";Reason=("Integrity check failed: " + $_.Exception.Message)
        }
    }
}

$lastHeartbeat = (Get-Date).AddSeconds(-1 * [int]$config.SelfDefense.HeartbeatSeconds)

try {
    while ($true) {
        if (((Get-Date)-$lastHeartbeat).TotalSeconds -ge [int]$config.SelfDefense.HeartbeatSeconds) {
            Write-GuardianHeartbeat
            $lastHeartbeat = Get-Date
        }

        Check-Tasks
        Check-Heartbeats
        Check-FileIntegrity
        foreach ($logCheck in @(Get-SentinelLogHealth $Root)) {
            if (-not $logCheck.Healthy) {
                Alert-Once -Key ('Log|'+$logCheck.Log) -Fingerprint $logCheck.Detail -Type 'LogIntegrityFailure' -Severity 'CRITICAL' -Fields @{Log=$logCheck.Log;Reason=$logCheck.Detail}
            } else { Clear-AlertKey ('Log|'+$logCheck.Log) }
        }
        foreach ($lane in @('high','normal')) {
            $queued=@(Get-ChildItem -LiteralPath (Join-Path $state ('response-queue\'+$lane)) -File -Filter '*.json' -ErrorAction SilentlyContinue)
            $oldest=if($queued.Count){((Get-Date)-($queued | Sort-Object CreationTime | Select-Object -First 1).CreationTime).TotalSeconds}else{0}
            if ($oldest -gt [int]$config.QueueWarningSeconds -or $queued.Count -gt [int]$config.QueueWarningCount) {
                Alert-Once -Key ('Queue|'+$lane) -Fingerprint ([string][math]::Floor($oldest/60)) -Type 'ResponseQueueDelayed' -Severity 'HIGH' -Fields @{Queue=$lane;Count=$queued.Count;OldestSeconds=[math]::Round($oldest,1)}
            } else { Clear-AlertKey ('Queue|'+$lane) }
        }

        Start-Sleep -Seconds ([int]$config.SelfDefense.PollSeconds)
    }
}
finally {
    if ($mutex) {
        try { $mutex.ReleaseMutex() } catch {
            [System.Diagnostics.Debug]::WriteLine("SentinelLocal integrity monitor mutex release failed: " + $_.Exception.Message)
        }
        $mutex.Dispose()
    }
}
