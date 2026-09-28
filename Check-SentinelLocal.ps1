param([string]$Root = "C:\ProgramData\SentinelLocal")

$ErrorActionPreference = "Stop"
try {
    $config = Get-Content (Join-Path $Root "Config.json") -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Host "ERROR: Config.json could not be loaded: $($_.Exception.Message)" -ForegroundColor Red
    return
}

Write-Host "=== SentinelLocal tasks ==="
Get-ScheduledTask -TaskName "SentinelLocal Watcher","SentinelLocal Response Worker","SentinelLocal Integrity Monitor" -ErrorAction SilentlyContinue |
Format-List TaskName,State

Write-Host "=== SentinelLocal processes ==="
$escapedRoot = [regex]::Escape($Root)
Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -and
    $_.CommandLine -match '(Watcher|ResponseWorker|IntegrityMonitor)\.ps1' -and
    $_.CommandLine -match $escapedRoot
} |
Format-List ProcessId,ParentProcessId,ExecutablePath,CommandLine

function Show-Heartbeat {
    param(
        [string]$Title,
        [string]$Path,
        [int]$StaleSeconds,
        [switch]$AllowBusyProcess
    )

    Write-Host "=== $Title ==="
    if (-not (Test-Path $Path)) {
        Write-Host "WARNING: heartbeat file not found." -ForegroundColor Red
        return
    }

    try {
        $heartbeat = Get-Content $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $lastUpdated = [datetimeoffset]::Parse([string]$heartbeat.LastUpdated)
        $age = ((Get-Date) - $lastUpdated.LocalDateTime).TotalSeconds
        $processAlive = $false
        $processIdValue = if ($heartbeat.WatcherProcessId) { [int]$heartbeat.WatcherProcessId } elseif ($heartbeat.ResponseWorkerProcessId) { [int]$heartbeat.ResponseWorkerProcessId } else { 0 }
        if ($processIdValue -gt 0) { $processAlive = [bool](Get-Process -Id $processIdValue -ErrorAction SilentlyContinue) }

        $healthy = $age -le $StaleSeconds
        if ($AllowBusyProcess -and [string]$heartbeat.Status -eq "Busy" -and $processAlive) {
            $healthy = $true
        }

        [pscustomobject]@{
            Status=$heartbeat.Status
            ProcessId=$processIdValue
            CurrentRequest=$heartbeat.CurrentRequest
            LastUpdated=$heartbeat.LastUpdated
            AgeSeconds=[math]::Round($age,1)
            ProcessAlive=$processAlive
            Healthy=$healthy
        } | Format-List

        if (-not $healthy) {
            Write-Host "WARNING: heartbeat is stale or its process is unavailable." -ForegroundColor Red
        }
    } catch {
        Write-Host "ERROR: Heartbeat could not be parsed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Show-Heartbeat -Title "Watcher heartbeat" -Path (Join-Path $Root "state\watcher-heartbeat.json") -StaleSeconds ([int]$config.HeartbeatStaleSeconds)
Show-Heartbeat -Title "Response worker heartbeat" -Path (Join-Path $Root "state\response-worker-heartbeat.json") -StaleSeconds ([int]$config.ResponseWorkerHeartbeatStaleSeconds) -AllowBusyProcess
Show-Heartbeat -Title "Integrity monitor heartbeat" -Path (Join-Path $Root "state\integrity-monitor-heartbeat.json") -StaleSeconds ([int]$config.SelfDefense.HeartbeatStaleSeconds)

Write-Host "=== Integrity baseline ==="
$baseline = Join-Path $Root "state\integrity-baseline.json"
if (Test-Path $baseline) { Write-Host $baseline } else { Write-Host "WARNING: integrity baseline missing." -ForegroundColor Red }

Write-Host "=== Response queue ==="
$queueRoot = Join-Path $Root "state\response-queue"
foreach ($name in @("high","normal","processing","failed")) {
    $dir = Join-Path $queueRoot $name
    $count = if (Test-Path $dir) { @(Get-ChildItem $dir -Filter "*.json" -File -ErrorAction SilentlyContinue).Count } else { 0 }
    [pscustomobject]@{Queue=$name;Count=$count;Path=$dir}
}

Write-Host "=== Defender health ==="
try {
    & (Join-Path $Root "DefenderHealth.ps1") -Root $Root
} catch {
    Write-Host "ERROR: Defender health check failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== Active Defender threats ==="
Get-MpThreat | Where-Object IsActive |
Format-List ThreatName,DidThreatExecute,IsActive,Resources

Write-Host "`n=== Recent Sentinel alerts ==="
$alerts = Join-Path $Root "logs\alerts.jsonl"
if (Test-Path $alerts) { Get-Content $alerts -Tail 10 } else { Write-Host "(none)" }

Write-Host "`n=== Recent Sentinel errors ==="
$errors = Join-Path $Root "logs\errors.jsonl"
if (Test-Path $errors) { Get-Content $errors -Tail 10 } else { Write-Host "(none)" }

Write-Host "`n=== Defender health alerts ==="
$health = Join-Path $Root "logs\defender-health-alerts.jsonl"
if (Test-Path $health) { Get-Content $health -Tail 10 } else { Write-Host "(none)" }

Write-Host "`n=== ASR/CFA/Network Protection event counts ==="
foreach ($fileName in @("asr-events.jsonl","cfa-events.jsonl","network-protection-events.jsonl")) {
    $path=Join-Path $Root "logs\$fileName"
    $count=if(Test-Path $path){(Get-Content $path | Measure-Object -Line).Lines}else{0}
    [pscustomobject]@{Log=$fileName;Events=$count}
}

Write-Host "`n=== SentinelLocal firewall containment rules ==="
$firewallRules = @(Get-NetFirewallRule -Group "SentinelLocal" -ErrorAction SilentlyContinue)
if ($firewallRules.Count -eq 0) {
    Write-Host "(none)"
} else {
    $firewallRules | Select-Object DisplayName,Enabled,Direction,Action,Description | Format-Table -AutoSize
}


Write-Host "`n=== Log hash-chain verification command ==="
Write-Host ("& `"{0}`" -Root `"{1}`"" -f (Join-Path $Root "Verify-SentinelLogs.ps1"),$Root)
