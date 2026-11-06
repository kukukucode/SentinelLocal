param(
    [string]$Root = "C:\ProgramData\SentinelLocal"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

$configPath = Join-Path $Root "Config.json"
try {
    $config = Get-Content $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-SentinelError -Root $Root -Component "ResponseWorker" -Operation "Load config" -Exception $_.Exception
    throw
}

Assert-SentinelConfig $config
Initialize-SentinelNative
$stateDir = Join-Path $Root "state"
$queueRoot = Join-Path $stateDir "response-queue"
$highDir = Join-Path $queueRoot "high"
$normalDir = Join-Path $queueRoot "normal"
$legacyPendingDir = Join-Path $queueRoot "pending"
$processingDir = Join-Path $queueRoot "processing"
$failedDir = Join-Path $queueRoot "failed"
$heartbeatPath = Join-Path $stateDir "response-worker-heartbeat.json"
$hashDedupePath = Join-Path $stateDir "response-hash-dedupe.json"
$alertLog = Join-Path $Root "logs\alerts.jsonl"

New-Item $highDir,$normalDir,$processingDir,$failedDir -ItemType Directory -Force | Out-Null

# v2.4 compatibility: migrate old FIFO pending queue into Normal.
if (Test-Path $legacyPendingDir) {
    foreach ($legacyFile in @(Get-ChildItem $legacyPendingDir -Filter "*.json" -File -ErrorAction SilentlyContinue)) {
        try {
            Move-Item -LiteralPath $legacyFile.FullName -Destination (Join-Path $normalDir $legacyFile.Name) -Force -ErrorAction Stop
        } catch {
            Write-SentinelError -Root $Root -Component "ResponseWorker" -Operation "Migrate legacy pending request" -Exception $_.Exception -Context @{Path=$legacyFile.FullName}
        }
    }
}

$createdNew = $false
$mutex = New-Object System.Threading.Mutex($true, "Global\SentinelLocalResponseWorker", [ref]$createdNew)
if (-not $createdNew) {
    [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
        Type="ResponseWorkerDuplicateStart"
        Severity="MEDIUM"
        Reason="Another SentinelLocal response worker already holds the global mutex."
    }))
    exit 0
}

$hashDedupe = @{};$hashDedupeDisabled=$false
try{
    $saved=Invoke-SentinelNative @{op='journal_open';path=$hashDedupePath;mode='hash';now=[datetimeoffset]::Now.ToString('o');max_age=[Math]::Max([int]$config.ResponseHashDedupeSeconds*4,3600)}
    foreach($entry in @($saved.Rows)){$hashDedupe[[string]$entry.SHA256]=[datetimeoffset]::Parse([string]$entry.LastCompleted)}
}catch{
    $hashDedupe=@{};$hashDedupeDisabled=$true
    Write-SentinelError -Root $Root -Component ResponseWorker -Operation 'Load dedupe journal; persistent reuse disabled and existing evidence preserved' -Exception $_.Exception -Severity HIGH
}

function Save-HashDedupe {
    param([string]$ChangedHash)
    if($hashDedupeDisabled){return}
    try{
        $saved=Invoke-SentinelNative @{op='journal_put';path=$hashDedupePath;key=$ChangedHash;at=$hashDedupe[$ChangedHash].ToString('o');now=[datetimeoffset]::Now.ToString('o');max_age=[Math]::Max([int]$config.ResponseHashDedupeSeconds*4,3600)}
        foreach($key in @($saved.ExpiredKeys)){$hashDedupe.Remove([string]$key)}
    }catch{Write-SentinelError -Root $Root -Component ResponseWorker -Operation 'Append completed hash journal' -Exception $_.Exception -Severity HIGH}
}



function Write-WorkerHeartbeat {
    param([string]$Status,[string]$CurrentRequest = "",[int]$ChildProcessId=0,[string]$RequestStartedAt="")
    $workerProcessId = [System.Diagnostics.Process]::GetCurrentProcess().Id
    $heartbeat = [ordered]@{
        Version=[string]$config.Version
        Status=$Status
        ResponseWorkerProcessId=$workerProcessId
        CurrentRequest=$CurrentRequest
        ChildProcessId=$ChildProcessId
        RequestStartedAt=$RequestStartedAt
        LastUpdated=(Get-Date).ToString("o")
    }
    try {
        Write-SentinelAtomicJson $heartbeatPath $heartbeat
    } catch {
        Write-SentinelError -Root $Root -Component "ResponseWorker" -Operation "Write heartbeat" -Exception $_.Exception
    }
}

function Get-RequestPriority {
    param($Request)
    if ($Request.PSObject.Properties["Priority"] -and [string]$Request.Priority -eq "High") { return "High" }
    if ([int]$Request.Score -ge [int]$config.ResponseQueueHighScore) { return "High" }
    return "Normal"
}

function Get-QueueDirectoryForRequest {
    param($Request)
    if ((Get-RequestPriority $Request) -eq "High") { return $highDir }
    return $normalDir
}

function Set-RequestAttempts {
    param([string]$Path,[int]$Attempts)
    $request = Get-Content $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($request.PSObject.Properties["Attempts"]) { $request.Attempts = $Attempts }
    else { $request | Add-Member -NotePropertyName Attempts -NotePropertyValue $Attempts }
    $availableAfter=[datetimeoffset]::Now.AddSeconds([Math]::Min(300,[int]$config.ResponseRetryDelaySeconds * [Math]::Pow(2,[Math]::Max(0,$Attempts-1)))).ToString('o')
    $request | Add-Member -NotePropertyName AvailableAfter -NotePropertyValue $availableAfter -Force
    Write-SentinelAtomicJson $Path $request
    return $request
}

function Move-ToFailed {
    param([string]$Path,[string]$Reason)
    $destination = Join-Path $failedDir ([IO.Path]::GetFileName($Path))
    Move-Item -LiteralPath $Path -Destination $destination -Force -ErrorAction Stop
    [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
        Type="ResponseRequestFailed"
        Severity="HIGH"
        RequestFile=$destination
        Reason=$Reason
    }))
}

$highBurst=0
function Get-NextRequestFile { Get-SentinelEligibleQueueFile -QueueRoot $queueRoot -Config $config -HighBurst $highBurst }

# Recover interrupted work.
foreach ($processingFile in @(Get-ChildItem $processingDir -Filter "*.json" -File -ErrorAction SilentlyContinue)) {
    try {
        $request = Get-Content $processingFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $attempts = if ($request.PSObject.Properties["Attempts"]) { [int]$request.Attempts + 1 } else { 1 }
        if ($attempts -ge [int]$config.ResponseQueueMaxAttempts) {
            Move-ToFailed -Path $processingFile.FullName -Reason "Interrupted request exceeded the maximum retry count during recovery."
        } else {
            [void](Set-RequestAttempts -Path $processingFile.FullName -Attempts $attempts)
            $request = Get-Content $processingFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $destinationDir = Get-QueueDirectoryForRequest $request
            $destination = Join-Path $destinationDir $processingFile.Name
            Move-Item -LiteralPath $processingFile.FullName -Destination $destination -Force -ErrorAction Stop
            [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                Type="ResponseRequestRecovered"
                Severity="MEDIUM"
                Priority=(Get-RequestPriority $request)
                RequestFile=$destination
                Attempts=$attempts
            }))
        }
    } catch {
        Write-SentinelError -Root $Root -Component "ResponseWorker" -Operation "Recover interrupted request" -Exception $_.Exception -Context @{Path=$processingFile.FullName}
        try { Move-ToFailed -Path $processingFile.FullName -Reason "Could not recover interrupted request." }
        catch { [System.Diagnostics.Debug]::WriteLine("SentinelLocal failed to move a recovery request to failed: " + $_.Exception.Message) }
    }
}

$lastHeartbeat = (Get-Date).AddSeconds(-1 * [int]$config.ResponseWorkerHeartbeatSeconds)
Write-WorkerHeartbeat -Status "Idle"

try {
    while ($true) {
        $requestFile = Get-NextRequestFile

        if ($requestFile) {
            $processingPath = Join-Path $processingDir $requestFile.Name
            try {
                Move-Item -LiteralPath $requestFile.FullName -Destination $processingPath -ErrorAction Stop
            } catch {
                Write-SentinelError -Root $Root -Component "ResponseWorker" -Operation "Claim queued response request" -Exception $_.Exception -Context @{Path=$requestFile.FullName} -Severity "MEDIUM"
                Start-Sleep -Seconds ([int]$config.ResponseQueuePollSeconds)
                continue
            }

            if ($requestFile.Directory.Name -eq 'high') { $highBurst++ } else { $highBurst=0 }
            Write-WorkerHeartbeat -Status "Busy" -CurrentRequest $processingPath

            try {
                $request = Get-Content $processingPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $requestHash = $null
                if ($request.FilePath -and (Test-Path -LiteralPath ([string]$request.FilePath) -PathType Leaf)) {
                    try {
                        $requestHash = (Get-FileHash -LiteralPath ([string]$request.FilePath) -Algorithm SHA256 -ErrorAction Stop).Hash
                    } catch {
                        Write-SentinelError -Root $Root -Component "ResponseWorker" -Operation "Hash request for dedupe" -Exception $_.Exception -Context @{Path=$request.FilePath} -Severity "MEDIUM"
                    }
                }

                $skipByHash = $false
                $hasLiveProcessIdentity = ([int]$request.ProcessIdValue -gt 0)
                if (
                    $requestHash -and $requestHash -ieq [string]$request.ObservedSHA256 -and
                    -not $hasLiveProcessIdentity -and
                    [int]$request.Score -lt [int]$config.ResponseQueueHighScore -and
                    $hashDedupe.ContainsKey($requestHash)
                ) {
                    $hashAge = ([datetimeoffset]::Now - $hashDedupe[$requestHash]).TotalSeconds
                    if ($hashAge -ge 0 -and $hashAge -lt [int]$config.ResponseHashDedupeSeconds) {
                        $skipByHash = $true
                        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                            Type="ResponseHashDeduplicated"
                            RequestId=$request.RequestId
                            SHA256=$requestHash
                            Score=[int]$request.Score
                            AgeSeconds=[math]::Round($hashAge,1)
                            Reason="A persistence/non-process request with the same SHA-256 was recently processed. Live-process requests are never dropped by hash dedupe."
                        }))
                    }
                }

                if (-not $skipByHash) {
                    $timeout=if ((Get-RequestPriority $request) -eq 'High') { [int]$config.ResponseTimeoutSeconds } else { [int]$config.NormalResponseTimeoutSeconds }
                    $responseResult=Invoke-SentinelBoundedResponse -Root $Root -RequestFile $processingPath -TimeoutSeconds $timeout -HeartbeatSeconds ([int]$config.ResponseWorkerHeartbeatSeconds) -Heartbeat {
                        param($childId,$started)
                        Write-WorkerHeartbeat -Status 'Busy' -CurrentRequest $processingPath -ChildProcessId $childId -RequestStartedAt $started
                    }
                    if (Test-SentinelCompletedHash -Path ([string]$request.FilePath) -RequestHash $requestHash -Response $responseResult) {
                        $hashDedupe[$requestHash] = [datetimeoffset]::Now
                        Save-HashDedupe $requestHash
                    }
                }

                Remove-Item -LiteralPath $processingPath -Force -ErrorAction Stop
                [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                    Type="ResponseRequestCompleted"
                    Priority=(Get-RequestPriority $request)
                    RequestFile=$requestFile.Name
                    HashDeduplicated=$skipByHash
                    Outcome=if($skipByHash){'Deduplicated'}else{$responseResult.Status}
                }))
            } catch {
                Write-SentinelError -Root $Root -Component "ResponseWorker" -Operation "Execute response request" -Exception $_.Exception -Context @{Path=$processingPath}

                try {
                    $request = Get-Content $processingPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    $attempts = if ($request.PSObject.Properties["Attempts"]) { [int]$request.Attempts + 1 } else { 1 }
                    if ($attempts -ge [int]$config.ResponseQueueMaxAttempts) {
                        Move-ToFailed -Path $processingPath -Reason ("Response execution failed {0} times." -f $attempts)
                    } else {
                        [void](Set-RequestAttempts -Path $processingPath -Attempts $attempts)
                        $request = Get-Content $processingPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                        $destinationDir = Get-QueueDirectoryForRequest $request
                        $retryPath = Join-Path $destinationDir ([IO.Path]::GetFileName($processingPath))
                        Move-Item -LiteralPath $processingPath -Destination $retryPath -Force -ErrorAction Stop
                        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                            Type="ResponseRequestRetry"
                            Severity="MEDIUM"
                            Priority=(Get-RequestPriority $request)
                            RequestFile=$retryPath
                            Attempts=$attempts
                        }))
                    }
                } catch {
                    Write-SentinelError -Root $Root -Component "ResponseWorker" -Operation "Requeue failed response request" -Exception $_.Exception -Context @{Path=$processingPath}
                    if (Test-Path -LiteralPath $processingPath) {
                        try { Move-ToFailed -Path $processingPath -Reason "Request could not be requeued after a response failure." }
                        catch { [System.Diagnostics.Debug]::WriteLine("SentinelLocal failed to move an unrecoverable response request: " + $_.Exception.Message) }
                    }
                }
            }

            Write-WorkerHeartbeat -Status "Idle"
            $lastHeartbeat = Get-Date
            continue
        }

        if (((Get-Date)-$lastHeartbeat).TotalSeconds -ge [int]$config.ResponseWorkerHeartbeatSeconds) {
            Write-WorkerHeartbeat -Status "Idle"
            $lastHeartbeat = Get-Date
        }

        Start-Sleep -Seconds ([int]$config.ResponseQueuePollSeconds)
    }
}
finally {
    try { Write-WorkerHeartbeat -Status "Stopped" }
    catch { [System.Diagnostics.Debug]::WriteLine("SentinelLocal failed to write the stopped worker heartbeat: " + $_.Exception.Message) }
    if ($mutex) {
        try { $mutex.ReleaseMutex() }
        catch { [System.Diagnostics.Debug]::WriteLine("SentinelLocal response worker mutex release failed: " + $_.Exception.Message) }
        $mutex.Dispose()
    }
}
