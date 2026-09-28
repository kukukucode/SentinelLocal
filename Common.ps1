function Get-SentinelStringHash {
    param([Parameter(Mandatory=$true)][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-","")
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-SentinelOrderedMap {
    param($Data)

    $map = [ordered]@{}
    if ($Data -is [System.Collections.IDictionary]) {
        foreach ($key in $Data.Keys) {
            $map[[string]$key] = $Data[$key]
        }
    } else {
        foreach ($property in $Data.PSObject.Properties) {
            $map[$property.Name] = $property.Value
        }
    }
    return $map
}

function Write-SentinelJsonLine {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)]$Data
    )

    $mutex = $null
    $hasMutex = $false
    try {
        $parent = Split-Path -Parent $Path
        if ($parent) { New-Item $parent -ItemType Directory -Force -ErrorAction Stop | Out-Null }

        $payload = ConvertTo-SentinelOrderedMap $Data
        $payload["Timestamp"] = (Get-Date).ToString("o")

        # Each JSONL stream is append-only and hash-chained. This is tamper-evident,
        # not tamper-proof against an attacker who fully controls the host.
        $normalizedPath = [IO.Path]::GetFullPath($Path).ToLowerInvariant()
        $mutexSuffix = (Get-SentinelStringHash $normalizedPath).Substring(0,24)
        $mutex = New-Object System.Threading.Mutex($false, ("Global\SentinelLocalLog_" + $mutexSuffix))
        $hasMutex = $mutex.WaitOne([TimeSpan]::FromSeconds(10))
        if (-not $hasMutex) {
            throw "Timed out waiting for the SentinelLocal log mutex."
        }

        $logDirectory = Split-Path -Parent $Path
        $root = Split-Path -Parent $logDirectory
        $chainDirectory = Join-Path $root "state\log-chain"
        New-Item $chainDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        $chainStatePath = Join-Path $chainDirectory (([IO.Path]::GetFileName($Path)) + ".state")

        $previousHash = "GENESIS"
        if (Test-Path -LiteralPath $chainStatePath) {
            try {
                $chainState = Get-Content $chainStatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                if ($chainState.LastHash) { $previousHash = [string]$chainState.LastHash }
            } catch {
                $previousHash = "STATE-UNREADABLE"
            }
        } elseif (Test-Path -LiteralPath $Path) {
            try {
                $lastLine = Get-Content -LiteralPath $Path -Tail 1 -ErrorAction Stop
                if ($lastLine) {
                    $lastObject = $lastLine | ConvertFrom-Json -ErrorAction Stop
                    if ($lastObject._ChainHash) { $previousHash = [string]$lastObject._ChainHash }
                }
            } catch {
                $previousHash = "LOG-TAIL-UNREADABLE"
            }
        }

        $canonical = $payload | ConvertTo-Json -Depth 14 -Compress
        $chainHash = Get-SentinelStringHash ($previousHash + "`n" + $canonical)

        $payload["_ChainAlg"] = "SHA256"
        $payload["_ChainPrev"] = $previousHash
        $payload["_ChainHash"] = $chainHash

        $json = $payload | ConvertTo-Json -Depth 14 -Compress
        Add-Content -LiteralPath $Path -Value $json -Encoding UTF8 -ErrorAction Stop

        [ordered]@{
            LastHash=$chainHash
            LastUpdated=(Get-Date).ToString("o")
            LogPath=$Path
        } | ConvertTo-Json -Compress | Set-Content -LiteralPath $chainStatePath -Encoding UTF8 -ErrorAction Stop

        # HIGH/CRITICAL events are also mirrored to the Windows Application log.
        # A Windows Event Forwarding collector can move these off-host.
        $severity = if ($payload.Contains("Severity")) { [string]$payload["Severity"] } else { "" }
        if ($severity -in @("HIGH","CRITICAL")) {
            try {
                $entryType = if ($severity -eq "CRITICAL") { "Error" } else { "Warning" }
                $message = $payload | ConvertTo-Json -Depth 8 -Compress
                Write-EventLog -LogName Application -Source "SentinelLocal" -EventId 1902 -EntryType $entryType -Message $message -ErrorAction Stop
            } catch {
                [System.Diagnostics.Debug]::WriteLine("SentinelLocal Event Log mirror failed: " + $_.Exception.Message)
            }
        }
        return $true
    } catch {
        try {
            Write-EventLog -LogName Application -Source "SentinelLocal" -EventId 1901 -EntryType Error `
                -Message ("SentinelLocal logging failure: {0}`n{1}" -f $Path,$_.Exception.Message) -ErrorAction Stop
        } catch {
            [System.Diagnostics.Debug]::WriteLine("SentinelLocal logging failure: " + $_.Exception.Message)
        }
        return $false
    } finally {
        if ($mutex) {
            if ($hasMutex) {
                try { $mutex.ReleaseMutex() } catch {
                    [System.Diagnostics.Debug]::WriteLine("SentinelLocal log mutex release failed: " + $_.Exception.Message)
                }
            }
            $mutex.Dispose()
        }
    }
}

function Write-SentinelError {
    param(
        [Parameter(Mandatory=$true)][string]$Root,
        [Parameter(Mandatory=$true)][string]$Component,
        [Parameter(Mandatory=$true)][string]$Operation,
        [Parameter(Mandatory=$true)]$Exception,
        $Context = $null,
        [ValidateSet("INFO","MEDIUM","HIGH")][string]$Severity = "HIGH"
    )
    $message = if ($Exception -is [System.Exception]) { $Exception.Message } else { [string]$Exception }
    $data = [ordered]@{
        Type = "SentinelError"
        Severity = $Severity
        Component = $Component
        Operation = $Operation
        Error = $message
        Context = $Context
    }
    [void](Write-SentinelJsonLine -Path (Join-Path $Root "logs\errors.jsonl") -Data $data)
}

function Get-SentinelManagedAsrRules {
    return [ordered]@{
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from LSASS"
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block Office applications from creating child processes"
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
        "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JS/VBS from launching downloaded executable content"
        "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code"
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication applications from creating child processes"
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creation from PSExec and WMI"
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted/unsigned processes from USB"
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools"
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
    }
}

function Get-SentinelAsrTable {
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $rows = @()
        $ids = @($pref.AttackSurfaceReductionRules_Ids)
        $actions = @($pref.AttackSurfaceReductionRules_Actions)
        $count = [Math]::Min($ids.Count, $actions.Count)
        for ($i = 0; $i -lt $count; $i++) {
            $rows += [pscustomobject]@{
                Id = ([string]$ids[$i]).ToLowerInvariant()
                Action = [int]$actions[$i]
            }
        }
        return $rows
    } catch {
        throw
    }
}

function Get-SentinelAsrRank {
    param($Action)
    switch ([string]$Action) {
        "0" { return 0 }
        "5" { return 0 }
        "Disabled" { return 0 }
        "NotConfigured" { return 0 }
        "2" { return 1 }
        "AuditMode" { return 1 }
        "6" { return 2 }
        "Warn" { return 2 }
        "1" { return 3 }
        "Enabled" { return 3 }
        default { return -1 }
    }
}

function Get-SentinelCfaRank {
    param($Value)
    switch ([string]$Value) {
        "0" { return 0 }
        "Disabled" { return 0 }
        "2" { return 1 }
        "AuditMode" { return 1 }
        "4" { return 1 }
        "AuditDiskModificationOnly" { return 1 }
        "3" { return 2 }
        "BlockDiskModificationOnly" { return 2 }
        "1" { return 3 }
        "Enabled" { return 3 }
        default { return -1 }
    }
}

function Get-SentinelNetworkProtectionRank {
    param($Value)
    switch ([string]$Value) {
        "0" { return 0 }
        "Disabled" { return 0 }
        "2" { return 1 }
        "AuditMode" { return 1 }
        "1" { return 2 }
        "Enabled" { return 2 }
        default { return -1 }
    }
}

function Get-SentinelPuaRank {
    param($Value)
    switch ([string]$Value) {
        "0" { return 0 }
        "Disabled" { return 0 }
        "2" { return 1 }
        "AuditMode" { return 1 }
        "1" { return 2 }
        "Enabled" { return 2 }
        default { return -1 }
    }
}

function Get-SentinelMapsRank {
    param($Value)
    switch ([string]$Value) {
        "0" { return 0 }
        "Disabled" { return 0 }
        "1" { return 1 }
        "Basic" { return 1 }
        "2" { return 2 }
        "Advanced" { return 2 }
        default { return -1 }
    }
}

function Get-SentinelCloudBlockRank {
    param($Value)
    switch ([string]$Value) {
        "Default" { return 0 }
        "0" { return 0 }
        "Moderate" { return 1 }
        "1" { return 1 }
        "High" { return 2 }
        "2" { return 2 }
        "HighPlus" { return 3 }
        "4" { return 3 }
        "ZeroTolerance" { return 4 }
        "6" { return 4 }
        default { return -1 }
    }
}

function Invoke-SentinelRetention {
    param(
        [Parameter(Mandatory=$true)][string]$Root,
        [Parameter(Mandatory=$true)][int]$MaxLogDays
    )
    if ($MaxLogDays -le 0) { return }

    $cutoff = (Get-Date).AddDays(-1 * $MaxLogDays)
    $logDir = Join-Path $Root "logs"
    $evidenceDir = Join-Path $Root "evidence"
    $failedQueueDir = Join-Path $Root "state\response-queue\failed"

    try {
        if (Test-Path $evidenceDir) {
            Get-ChildItem $evidenceDir -Directory -ErrorAction Stop |
                Where-Object { $_.LastWriteTime -lt $cutoff } |
                Remove-Item -Recurse -Force -ErrorAction Stop
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Retention" -Operation "Delete old evidence" -Exception $_.Exception
    }

    try {
        if (Test-Path $failedQueueDir) {
            Get-ChildItem $failedQueueDir -File -Filter "*.json" -ErrorAction Stop |
                Where-Object { $_.LastWriteTime -lt $cutoff } |
                Remove-Item -Force -ErrorAction Stop
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Retention" -Operation "Delete old failed response requests" -Exception $_.Exception
    }

    if (-not (Test-Path $logDir)) { return }

    foreach ($path in Get-ChildItem $logDir -File -ErrorAction SilentlyContinue) {
        $ext = $path.Extension.ToLowerInvariant()
        $tmp = "$($path.FullName).retention.tmp"

        try {
            if ($ext -eq ".jsonl") {
                $writer = [System.IO.StreamWriter]::new($tmp, $false, [System.Text.UTF8Encoding]::new($true))
                try {
                    foreach ($line in [System.IO.File]::ReadLines($path.FullName)) {
                        $keep = $true
                        try {
                            $obj = $line | ConvertFrom-Json -ErrorAction Stop
                            if ($obj.Timestamp) {
                                $ts = [datetimeoffset]::Parse([string]$obj.Timestamp)
                                $keep = $ts.LocalDateTime -ge $cutoff
                            }
                        } catch {
                            $keep = $true
                        }
                        if ($keep) { $writer.WriteLine($line) }
                    }
                } finally {
                    $writer.Dispose()
                }
                Move-Item $tmp $path.FullName -Force -ErrorAction Stop
            }
            elseif ($path.Name -eq "events.log") {
                $writer = [System.IO.StreamWriter]::new($tmp, $false, [System.Text.UTF8Encoding]::new($true))
                try {
                    foreach ($line in [System.IO.File]::ReadLines($path.FullName)) {
                        $keep = $true
                        $first = ($line -split "`t",2)[0]
                        try {
                            $ts = [datetimeoffset]::Parse($first)
                            $keep = $ts.LocalDateTime -ge $cutoff
                        } catch {
                            $keep = $true
                        }
                        if ($keep) { $writer.WriteLine($line) }
                    }
                } finally {
                    $writer.Dispose()
                }
                Move-Item $tmp $path.FullName -Force -ErrorAction Stop
            }
            elseif ($path.Name -eq "connections.csv") {
                $rows = @(Import-Csv $path.FullName -ErrorAction Stop | Where-Object {
                    if (-not $_.Timestamp) { return $true }
                    try {
                        ([datetimeoffset]::Parse([string]$_.Timestamp)).LocalDateTime -ge $cutoff
                    } catch {
                        $true
                    }
                })
                if ($rows.Count -gt 0) {
                    $rows | Export-Csv $tmp -NoTypeInformation -Encoding UTF8
                } else {
                    Set-Content $tmp -Value '"Timestamp","ProcessId","State","LocalAddress","LocalPort","RemoteAddress","RemotePort","PTR"' -Encoding UTF8
                }
                Move-Item $tmp $path.FullName -Force -ErrorAction Stop
            }
        } catch {
            if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
            Write-SentinelError -Root $Root -Component "Retention" -Operation ("Retain {0}" -f $path.Name) -Exception $_.Exception
        }
    }
}


function Remove-ExpiredSentinelFirewallRules {
    param(
        [Parameter(Mandatory=$true)][string]$Root
    )

    try {
        $rules = @(Get-NetFirewallRule -Group "SentinelLocal" -ErrorAction Stop)
        foreach ($rule in $rules) {
            $description = [string]$rule.Description
            $match = [regex]::Match($description, '(?i)(?:^|;\s*)ExpiresAt=([^;]+)')
            if (-not $match.Success) { continue }

            try {
                $expiresAt = [datetimeoffset]::Parse($match.Groups[1].Value.Trim())
            } catch {
                Write-SentinelError -Root $Root -Component "Firewall" -Operation "Parse firewall rule expiry" `
                    -Exception $_.Exception -Context @{RuleName=$rule.DisplayName;Description=$description} -Severity "MEDIUM"
                continue
            }

            if ($expiresAt -le [datetimeoffset]::Now) {
                try {
                    Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                    [void](Write-SentinelJsonLine -Path (Join-Path $Root "logs\firewall-events.jsonl") -Data ([ordered]@{
                        Type="FirewallRuleExpired"
                        RuleName=$rule.DisplayName
                        RuleId=$rule.Name
                        ExpiredAt=$expiresAt.ToString("o")
                    }))
                } catch {
                    Write-SentinelError -Root $Root -Component "Firewall" -Operation "Remove expired containment rule" `
                        -Exception $_.Exception -Context @{RuleName=$rule.DisplayName;RuleId=$rule.Name}
                }
            }
        }
    } catch {
        # No matching rules is not an error. Other failures should be visible.
        if ($_.Exception.Message -notmatch '(?i)No MSFT_NetFirewallRule objects found') {
            Write-SentinelError -Root $Root -Component "Firewall" -Operation "Enumerate containment rules" `
                -Exception $_.Exception -Severity "MEDIUM"
        }
    }
}


function Get-SentinelCriticalFileNames {
    return @(
        "Common.ps1",
        "Config.json",
        "Watcher.ps1",
        "ResponseWorker.ps1",
        "Response.ps1",
        "IntegrityMonitor.ps1",
        "DefenderHealth.ps1",
        "DefenderHardening.ps1",
        "Restore-DefenderBackup.ps1",
        "Install-SentinelLocal.ps1",
        "Upgrade-SentinelLocal.ps1",
        "Uninstall-SentinelLocal.ps1",
        "SelfTest-SentinelLocal.ps1",
        "Check-SentinelLocal.ps1",
        "Verify-SentinelLogs.ps1",
        "Update-SentinelIntegrityBaseline.ps1"
    )
}
