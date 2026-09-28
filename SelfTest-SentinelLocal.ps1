param(
    [string]$Root = "C:\ProgramData\SentinelLocal",
    [switch]$PreStart
)

. (Join-Path $PSScriptRoot 'Common.ps1')
$results = New-Object System.Collections.Generic.List[object]

function Add-Test([string]$Name,[bool]$Passed,[string]$Detail) {
    $results.Add([pscustomobject]@{Test=$Name;Passed=$Passed;Detail=$Detail})
}

try {
    $config = Get-Content (Join-Path $Root "Config.json") -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    Add-Test "Config parse" $true ("Version " + $config.Version)
} catch {
    Add-Test "Config parse" $false $_.Exception.Message
}

if ($config) {
    Add-Test 'Config: response timeouts' ([int]$config.NormalResponseTimeoutSeconds -ge 1 -and [int]$config.ResponseTimeoutSeconds -ge [int]$config.NormalResponseTimeoutSeconds) 'Normal <= High; both positive'
    Add-Test 'Config: fresh progress interval' ([int]$config.ResponseWorkerHeartbeatSeconds -ge 1 -and [int]$config.ResponseWorkerHeartbeatSeconds -lt [int]$config.ResponseWorkerHeartbeatStaleSeconds) 'Heartbeat interval < stale threshold'
    Add-Test 'Config: event batching' ([int]$config.EventBatchSize -ge 1 -and [int]$config.EventBatchSize -le 10000) 'Batch size within 1..10000'
    Add-Test 'Config: retry delay' ([int]$config.ResponseRetryDelaySeconds -ge 1) 'Positive retry delay'
    Add-Test 'Config: queue monitoring' ([int]$config.QueueWarningSeconds -ge 1 -and [int]$config.QueueWarningCount -ge 1) 'Positive backlog thresholds'
    Add-Test "Config: DefenderCorrelationWindowSeconds" ([int]$config.DefenderCorrelationWindowSeconds -gt [int]$config.UnresolvedDefenderDetectionAlertSeconds) ("Value=" + $config.DefenderCorrelationWindowSeconds)
    Add-Test "Config: ResponseQueuePollSeconds" ([int]$config.ResponseQueuePollSeconds -ge 1) ("Value=" + $config.ResponseQueuePollSeconds)
    Add-Test "Config: ResponseQueueMaxAttempts" ([int]$config.ResponseQueueMaxAttempts -ge 1) ("Value=" + $config.ResponseQueueMaxAttempts)
    Add-Test "Config: ResponseQueueHighScore" ([int]$config.ResponseQueueHighScore -ge [int]$config.ScorePolicy.HighRisk) ("Value=" + $config.ResponseQueueHighScore)
    Add-Test "Config: ResponseQueueDedupeSeconds" ([int]$config.ResponseQueueDedupeSeconds -ge 1) ("Value=" + $config.ResponseQueueDedupeSeconds)
    Add-Test "Config: ResponseHashDedupeSeconds" ([int]$config.ResponseHashDedupeSeconds -ge 1) ("Value=" + $config.ResponseHashDedupeSeconds)
    Add-Test "Config: SelfDefense" ([bool]$config.SelfDefense.Enabled) ("Enabled=" + $config.SelfDefense.Enabled)
    Add-Test "Config: FirewallRuleLifetimeMinutes" ([int]$config.FirewallRuleLifetimeMinutes -ge 1) ("Value=" + $config.FirewallRuleLifetimeMinutes)
}

$requiredFiles = @(Get-SentinelPackageFiles)
foreach ($requiredFile in $requiredFiles) {
    $requiredPath = Join-Path $Root $requiredFile
    $exists = Test-Path $requiredPath
    Add-Test ("Installed file: " + $requiredFile) $exists $requiredPath
    if ($exists -and $requiredFile -like '*.ps1') {
        try {
            $tokens = $null
            $parseErrors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($requiredPath,[ref]$tokens,[ref]$parseErrors)
            $detail = if ($parseErrors.Count -eq 0) { "syntax OK" } else { (@($parseErrors | ForEach-Object { $_.Message }) -join "; ") }
            Add-Test ("PowerShell parse: " + $requiredFile) ($parseErrors.Count -eq 0) $detail
        } catch {
            Add-Test ("PowerShell parse: " + $requiredFile) $false $_.Exception.Message
        }
    }
}

foreach ($cmd in @(
    "Get-MpComputerStatus","Get-MpPreference","Start-MpScan","Get-MpThreat","Get-MpThreatDetection",
    "Get-WinEvent","Get-ScheduledTask","Get-NetTCPConnection","Get-NetFirewallRule","New-NetFirewallRule","Remove-NetFirewallRule"
)) {
    $found = [bool](Get-Command $cmd -ErrorAction SilentlyContinue)
    Add-Test ("Cmdlet: " + $cmd) $found $(if($found){"available"}else{"missing"})
}

if (-not $PreStart) {
    foreach ($taskName in @("SentinelLocal Watcher","SentinelLocal Response Worker","SentinelLocal Integrity Monitor")) {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Add-Test ("Task: " + $taskName) ([bool]$task) $(if($task){[string]$task.State}else{"not installed"})
        if ($task) {
            $action = @($task.Actions)[0]
            $rootOk = ([string]$action.Arguments) -match ('(?i)-Root\s+"' + [regex]::Escape($Root) + '"')
            Add-Test ("Task Root argument: " + $taskName) $rootOk ([string]$action.Arguments)
        }
    }

    $watcherHeartbeat = Join-Path $Root "state\watcher-heartbeat.json"
    if (Test-Path $watcherHeartbeat) {
        try {
            $h = Get-Content $watcherHeartbeat -Raw | ConvertFrom-Json
            $age = ((Get-Date) - ([datetimeoffset]::Parse([string]$h.LastUpdated)).LocalDateTime).TotalSeconds
            Add-Test "Watcher heartbeat" ($age -le [int]$config.HeartbeatStaleSeconds) ("AgeSeconds=" + [math]::Round($age,1))
        } catch {
            Add-Test "Watcher heartbeat" $false $_.Exception.Message
        }
    } else {
        Add-Test "Watcher heartbeat" $false "not found"
    }

    $workerHeartbeat = Join-Path $Root "state\response-worker-heartbeat.json"
    if (Test-Path $workerHeartbeat) {
        try {
            $h = Get-Content $workerHeartbeat -Raw | ConvertFrom-Json
            $age = ((Get-Date) - ([datetimeoffset]::Parse([string]$h.LastUpdated)).LocalDateTime).TotalSeconds
            $processAlive = $false
            if ($h.ResponseWorkerProcessId) {
                $processAlive = [bool](Get-Process -Id ([int]$h.ResponseWorkerProcessId) -ErrorAction SilentlyContinue)
            }
            $healthy=(Test-SentinelHeartbeat -Heartbeat $h -StaleSeconds ([int]$config.ResponseWorkerHeartbeatStaleSeconds) -BusyTimeoutSeconds ([int]$config.ResponseTimeoutSeconds)).Healthy
            Add-Test "Response worker heartbeat" $healthy ("Status={0}; AgeSeconds={1}; ProcessAlive={2}" -f $h.Status,[math]::Round($age,1),$processAlive)
        } catch {
            Add-Test "Response worker heartbeat" $false $_.Exception.Message
        }
    } else {
        Add-Test "Response worker heartbeat" $false "not found"
    }

    $integrityHeartbeat = Join-Path $Root "state\integrity-monitor-heartbeat.json"
    if (Test-Path $integrityHeartbeat) {
        try {
            $h = Get-Content $integrityHeartbeat -Raw | ConvertFrom-Json
            $age = ((Get-Date) - ([datetimeoffset]::Parse([string]$h.LastUpdated)).LocalDateTime).TotalSeconds
            Add-Test "Integrity monitor heartbeat" ($age -le [int]$config.SelfDefense.HeartbeatStaleSeconds) ("AgeSeconds=" + [math]::Round($age,1))
        } catch {
            Add-Test "Integrity monitor heartbeat" $false $_.Exception.Message
        }
    } else {
        Add-Test "Integrity monitor heartbeat" $false "not found"
    }

    Add-Test "Integrity baseline" (Test-Path (Join-Path $Root "state\integrity-baseline.json")) (Join-Path $Root "state\integrity-baseline.json")
} else {
    Add-Test "PreStart mode" $true "Runtime task/heartbeat checks intentionally skipped"
}

$results | Format-Table -AutoSize
if (@($results | Where-Object { -not $_.Passed }).Count -gt 0) { exit 1 } else { exit 0 }
