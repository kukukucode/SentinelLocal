param(
    [string]$RequestFile = "",
    [string]$FilePath = "",
    [int]$ProcessIdValue = 0,
    [int]$Score = 0,
    [string[]]$Reasons = @(),
    [string]$Root = "C:\ProgramData\SentinelLocal"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

try {
    $config = Get-Content (Join-Path $Root "Config.json") -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-SentinelError -Root $Root -Component "Response" -Operation "Load config" -Exception $_.Exception
    throw
}


$requestId = ""
$requestSource = "Direct"
$observedProcess = $null
$initialConnections = @()

if ($RequestFile) {
    try {
        $request = Get-Content $RequestFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $requestId = [string]$request.RequestId
        $requestSource = [string]$request.Source
        $FilePath = [string]$request.FilePath
        $ProcessIdValue = [int]$request.ProcessIdValue
        $Score = [int]$request.Score
        $Reasons = @($request.Reasons)
        $observedProcess = $request.ObservedProcess
        $initialConnections = @($request.InitialConnections)
    } catch {
        Write-SentinelError -Root $Root -Component "Response" -Operation "Load queued response request" -Exception $_.Exception -Context @{RequestFile=$RequestFile}
        throw
    }
}

if (-not $FilePath) {
    throw "Response requires FilePath directly or through RequestFile."
}

$evidenceRoot = Join-Path $Root "evidence"
$alertLog = Join-Path $Root "logs\alerts.jsonl"
$connLog = Join-Path $Root "logs\connections.csv"
New-Item $evidenceRoot -ItemType Directory -Force | Out-Null

function Get-FileIntel {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop
        $signature = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        return [ordered]@{
            Path=$Path
            SHA256=$hash.Hash
            Size=$item.Length
            Created=$item.CreationTime.ToString("o")
            Modified=$item.LastWriteTime.ToString("o")
            OriginalFilename=$item.VersionInfo.OriginalFilename
            FileDescription=$item.VersionInfo.FileDescription
            CompanyName=$item.VersionInfo.CompanyName
            FileVersion=$item.VersionInfo.FileVersion
            SignatureStatus=[string]$signature.Status
            Signer=if($signature.SignerCertificate){$signature.SignerCertificate.Subject}else{$null}
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Response" -Operation "Collect file intelligence" -Exception $_.Exception -Context @{Path=$Path}
        return $null
    }
}

function Get-ProcessIntel {
    param([int]$ProcessIdValue)
    if ($ProcessIdValue -le 0) { return $null }
    try {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessIdValue" -ErrorAction Stop
        if (-not $process) { return $null }
        return [ordered]@{
            ProcessId=[int]$process.ProcessId
            ParentProcessId=[int]$process.ParentProcessId
            Name=$process.Name
            ExecutablePath=$process.ExecutablePath
            CommandLine=$process.CommandLine
            CreationDate=if($process.CreationDate){([datetime]$process.CreationDate).ToUniversalTime().ToString("o")}else{""}
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Response" -Operation "Collect process intelligence" -Exception $_.Exception -Context @{ProcessId=$ProcessIdValue} -Severity "MEDIUM"
        return $null
    }
}

function Save-ConnectionRows {
    param($Rows)
    foreach ($row in @($Rows)) {
        if (-not $row) { continue }
        try {
            $normalized = [pscustomobject]@{
                Timestamp=if($row.Timestamp){[string]$row.Timestamp}else{(Get-Date).ToString("o")}
                ProcessId=[int]$row.ProcessId
                State=[string]$row.State
                LocalAddress=[string]$row.LocalAddress
                LocalPort=[string]$row.LocalPort
                RemoteAddress=[string]$row.RemoteAddress
                RemotePort=[string]$row.RemotePort
                PTR=[string]$row.PTR
            }
            if (-not (Test-Path $connLog)) {
                $normalized | Export-Csv $connLog -NoTypeInformation -Encoding UTF8
            } else {
                $normalized | Export-Csv $connLog -NoTypeInformation -Append -Encoding UTF8
            }
        } catch {
            Write-SentinelError -Root $Root -Component "Response" -Operation "Write connection evidence" -Exception $_.Exception -Severity "MEDIUM"
        }
    }
}

function Save-Connections {
    param(
        [int]$ProcessIdValue,
        [bool]$ResolvePtr = $false
    )
    if ($ProcessIdValue -le 0) { return @() }

    $output = @()
    try {
        $connections = Get-NetTCPConnection -OwningProcess $ProcessIdValue -ErrorAction Stop
        foreach ($connection in $connections) {
            $ptr = $null
            if ($ResolvePtr -and $config.EnablePtrLookup -and $connection.RemoteAddress -and $connection.RemoteAddress -notin @("0.0.0.0","::","::1","127.0.0.1")) {
                try {
                    $ptr = Resolve-DnsName -Name $connection.RemoteAddress -Type PTR -ErrorAction Stop |
                           Select-Object -First 1 -ExpandProperty NameHost
                } catch {
                    $ptr = $null
                }
            }
            $row=[pscustomobject]@{
                Timestamp=(Get-Date).ToString("o")
                ProcessId=$ProcessIdValue
                State=$connection.State
                LocalAddress=$connection.LocalAddress
                LocalPort=$connection.LocalPort
                RemoteAddress=$connection.RemoteAddress
                RemotePort=$connection.RemotePort
                PTR=$ptr
            }
            $output += $row
        }
        Save-ConnectionRows $output
    } catch {
        # A process can exit before TCP enumeration. Initial Watcher-side network evidence can still survive in the queue request.
        Write-SentinelError -Root $Root -Component "Response" -Operation "Collect network connections" -Exception $_.Exception -Context @{ProcessId=$ProcessIdValue} -Severity "MEDIUM"
    }
    return $output
}


$eventId = [guid]::NewGuid().ToString()
$eventDirectory = Join-Path $evidenceRoot $eventId
New-Item $eventDirectory -ItemType Directory -Force | Out-Null

$fileIntel = Get-FileIntel $FilePath
$currentProcessAtResponseStart = Get-ProcessIntel $ProcessIdValue
$processIntel = if ($observedProcess) { $observedProcess } else { $currentProcessAtResponseStart }
$parentIntel = if ($processIntel -and $processIntel.ParentProcessId) { Get-ProcessIntel ([int]$processIntel.ParentProcessId) } else { $null }

if ($initialConnections.Count -gt 0) {
    Save-ConnectionRows $initialConnections
}

$freshConnections = if ($Score -ge [int]$config.ScorePolicy.DefenderCustomScan) {
    @(Save-Connections -ProcessIdValue $ProcessIdValue -ResolvePtr:($Score -ge [int]$config.ScorePolicy.DeepEvidence))
} else {
    @()
}

$connectionMap = [ordered]@{}
foreach ($connection in @($initialConnections) + @($freshConnections)) {
    if (-not $connection) { continue }
    $key = "{0}|{1}|{2}|{3}" -f $connection.LocalAddress,$connection.LocalPort,$connection.RemoteAddress,$connection.RemotePort
    if (-not $connectionMap.Contains($key)) { $connectionMap[$key] = $connection }
}
$connections = @($connectionMap.Values)

$scanStarted = $false
$defenderDetected = $false
$detections = @()
$scanStatus='NoScanRequired'
if ($Score -ge [int]$config.ScorePolicy.DefenderCustomScan -and -not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { $scanStatus='TargetMissing' }

if ($Score -ge [int]$config.ScorePolicy.DefenderCustomScan -and (Test-Path -LiteralPath $FilePath)) {
    $scanStarted = $true
    $scanStart = Get-Date
    try {
        if (Test-SentinelException -Path $FilePath -Config $config) { $scanStatus='Excepted'; $scanStarted=$false }
        else { Start-MpScan -ScanType CustomScan -ScanPath $FilePath -ErrorAction Stop; $scanStatus='Completed' }
    } catch {
        Write-SentinelError -Root $Root -Component "Response" -Operation "Start Defender custom scan" -Exception $_.Exception -Context @{Path=$FilePath;Score=$Score}
        $scanStarted = $false
        throw
    }

    if ($scanStarted) {
        Start-Sleep -Seconds 1
        try {
            $escapedPath = [regex]::Escape($FilePath)
            $detections = @(Get-MpThreatDetection -ErrorAction Stop |
                Where-Object {
                    $_.InitialDetectionTime -ge $scanStart.AddMinutes(-2) -and
                    (($_.Resources -join " ") -match $escapedPath)
                })
            $defenderDetected = $detections.Count -gt 0
        } catch {
            Write-SentinelError -Root $Root -Component "Response" -Operation "Read Defender scan result" -Exception $_.Exception -Context @{Path=$FilePath}
            throw
        }

        if ($defenderDetected) {
            if ($config.AutoStopProcessWhenDefenderConfirms -and $ProcessIdValue -gt 0) {
                $currentProcessIntel = Get-ProcessIntel $ProcessIdValue
                $identityMatches = (
                    $processIntel -and
                    $currentProcessIntel -and
                    ([string]$currentProcessIntel.ExecutablePath -ieq [string]$processIntel.ExecutablePath) -and
                    ([string]$currentProcessIntel.ExecutablePath -ieq [string]$FilePath) -and
                    ([string]$currentProcessIntel.CreationDate -eq [string]$processIntel.CreationDate)
                )

                if ($identityMatches) {
                    try {
                        Stop-Process -Id $ProcessIdValue -Force -ErrorAction Stop
                        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                            Type="DefenderConfirmedProcessStopped"
                            ProcessId=$ProcessIdValue
                            Path=$FilePath
                            CreationDate=$processIntel.CreationDate
                            SHA256=if($fileIntel){$fileIntel.SHA256}else{$null}
                        }))
                    } catch {
                        Write-SentinelError -Root $Root -Component "Response" -Operation "Stop Defender-confirmed process" -Exception $_.Exception -Context @{ProcessId=$ProcessIdValue;Path=$FilePath} -Severity "MEDIUM"
                    }
                } else {
                    [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                        Type="DefenderConfirmedProcessStopSkipped"
                        Severity="HIGH"
                        ProcessId=$ProcessIdValue
                        ExpectedPath=if($processIntel){$processIntel.ExecutablePath}else{$FilePath}
                        CurrentPath=if($currentProcessIntel){$currentProcessIntel.ExecutablePath}else{$null}
                        ExpectedCreationDate=if($processIntel){$processIntel.CreationDate}else{$null}
                        CurrentCreationDate=if($currentProcessIntel){$currentProcessIntel.CreationDate}else{$null}
                        SHA256=if($fileIntel){$fileIntel.SHA256}else{$null}
                        Reason="PID identity changed or process exited before containment. No Stop-Process was issued."
                    }))
                }
            }

            # Defender remediation outcome (1117/1118/1119) is intentionally
            # interpreted only by Watcher.ps1, which correlates by Detection ID
            # (or Threat ID + resource fallback). Response.ps1 does not call
            # Remove-MpThreat based on a generic 1117 event.
        }
    }
}

if ($defenderDetected -and $config.AutoFirewallBlockOnDefenderConfirmation -and $connections.Count -gt 0) {
    $firewallLifetimeMinutes = [int]$config.FirewallRuleLifetimeMinutes
    if ($firewallLifetimeMinutes -lt 1) {
        Write-SentinelError -Root $Root -Component "Response" -Operation "Validate firewall rule lifetime" `
            -Exception "FirewallRuleLifetimeMinutes must be >= 1; no containment firewall rules were created." -Severity "HIGH"
    } else {
        foreach ($connection in $connections) {
            $ip = [string]$connection.RemoteAddress
            if ($ip -and $ip -notin @("0.0.0.0","::","::1","127.0.0.1") -and $ip -notmatch '^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.') {
                $ruleName = "SentinelLocal-$eventId-$($ip.Replace(':','_'))"
                $createdAt = [datetimeoffset]::Now
                $expiresAt = $createdAt.AddMinutes($firewallLifetimeMinutes)
                $description = "SentinelLocal temporary containment; EventId=$eventId; CreatedAt=$($createdAt.ToString('o')); ExpiresAt=$($expiresAt.ToString('o')); RemoteAddress=$ip"
                try {
                    New-NetFirewallRule -DisplayName $ruleName -Group "SentinelLocal" -Description $description `
                        -Direction Outbound -Action Block -RemoteAddress $ip -ErrorAction Stop | Out-Null
                    [void](Write-SentinelJsonLine -Path (Join-Path $Root "logs\firewall-events.jsonl") -Data ([ordered]@{
                        Type="FirewallRuleCreated"
                        RuleName=$ruleName
                        RemoteAddress=$ip
                        EventId=$eventId
                        CreatedAt=$createdAt.ToString("o")
                        ExpiresAt=$expiresAt.ToString("o")
                    }))
                } catch {
                    Write-SentinelError -Root $Root -Component "Response" -Operation "Add firewall containment rule" -Exception $_.Exception -Context @{RemoteAddress=$ip}
                }
            }
        }
    }
}

$result = [ordered]@{
    EventId=$eventId
    Status=$scanStatus
    RequestId=$requestId
    RequestSource=$requestSource
    RequestFile=$RequestFile
    Type="Response"
    File=$fileIntel
    Process=$processIntel
    Parent=$parentIntel
    Score=$Score
    Reasons=$Reasons
    Connections=$connections
    DefenderCustomScanStarted=$scanStarted
    DefenderDetected=$defenderDetected
    DefenderRemediationDelegatedToWatcher=$defenderDetected
    DefenderDetections=$detections
}

try {
    $result | ConvertTo-Json -Depth 14 | Set-Content (Join-Path $eventDirectory "response.json") -Encoding UTF8 -ErrorAction Stop
} catch {
    Write-SentinelError -Root $Root -Component "Response" -Operation "Save evidence bundle" -Exception $_.Exception -Context @{EventId=$eventId}
    throw
}
if (-not (Write-SentinelJsonLine -Path $alertLog -Data $result)) { throw 'Response result could not be logged.' }
$result
