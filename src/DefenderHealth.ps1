param(
    [string]$Root = "C:\ProgramData\SentinelLocal",
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

$logDir = Join-Path $Root "logs"
$stateDir = Join-Path $Root "state"
$configPath = Join-Path $Root "Config.json"
New-Item $logDir,$stateDir -ItemType Directory -Force | Out-Null

try {
    $config = Get-Content $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-SentinelError -Root $Root -Component "DefenderHealth" -Operation "Load config" -Exception $_.Exception
    throw
}

$healthAlertLog = Join-Path $logDir "defender-health-alerts.jsonl"
$statePath = Join-Path $stateDir "defender-health.json"
$managedAsr = Get-SentinelManagedAsrRules

function Add-HealthAlert {
    param([string]$Severity,[string]$Setting,$Old,$New,[string]$Reason)
    $data = [ordered]@{
        Type="DefenderHealth"
        Severity=$Severity
        Setting=$Setting
        Old=$Old
        New=$New
        Reason=$Reason
    }
    [void](Write-SentinelJsonLine -Path $healthAlertLog -Data $data)
    if (-not $Quiet) {
        Write-Host ("[{0}] {1}: {2} -> {3} ({4})" -f $Severity,$Setting,$Old,$New,$Reason)
    }
}

function Get-HealthSnapshot {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction Stop
        $asr = @(Get-SentinelAsrTable)

        [ordered]@{
            CapturedAt = (Get-Date).ToString("o")
            AntivirusEnabled = [bool]$status.AntivirusEnabled
            RealTimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
            BehaviorMonitorEnabled = [bool]$status.BehaviorMonitorEnabled
            IoavProtectionEnabled = [bool]$status.IoavProtectionEnabled
            OnAccessProtectionEnabled = [bool]$status.OnAccessProtectionEnabled
            AMRunningMode = [string]$status.AMRunningMode
            IsTamperProtected = [bool]$status.IsTamperProtected
            AntivirusSignatureAge = [int]$status.AntivirusSignatureAge
            AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
            MAPSReporting = [string]$pref.MAPSReporting
            SubmitSamplesConsent = [string]$pref.SubmitSamplesConsent
            DisableBlockAtFirstSeen = [bool]$pref.DisableBlockAtFirstSeen
            CheckForSignaturesBeforeRunningScan = [bool]$pref.CheckForSignaturesBeforeRunningScan
            PUAProtection = [string]$pref.PUAProtection
            EnableNetworkProtection = [string]$pref.EnableNetworkProtection
            CloudBlockLevel = [string]$pref.CloudBlockLevel
            EnableControlledFolderAccess = [string]$pref.EnableControlledFolderAccess
            DisableRealtimeMonitoring = [bool]$pref.DisableRealtimeMonitoring
            DisableBehaviorMonitoring = [bool]$pref.DisableBehaviorMonitoring
            DisableIOAVProtection = [bool]$pref.DisableIOAVProtection
            ExclusionPath = @($pref.ExclusionPath)
            ExclusionProcess = @($pref.ExclusionProcess)
            ExclusionExtension = @($pref.ExclusionExtension)
            ASR = $asr
        }
    } catch {
        Write-SentinelError -Root $Root -Component "DefenderHealth" -Operation "Get Defender status/preferences" -Exception $_.Exception
        throw
    }
}

$now = Get-HealthSnapshot
if ($now.AMRunningMode -ne 'Normal' -or -not $now.AntivirusEnabled -or -not $now.RealTimeProtectionEnabled) {
    Add-HealthAlert 'HIGH' 'DefenderOperationalState' 'Normal / protection enabled' $now.AMRunningMode 'Defender active protection is unavailable or degraded; passive mode has different capabilities.'
}
$old = $null
if (Test-Path $statePath) {
    try {
        $old = Get-Content $statePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-SentinelError -Root $Root -Component "DefenderHealth" -Operation "Read previous health state" -Exception $_.Exception -Severity "MEDIUM"
    }
}

if ($old) {
    foreach ($name in @("AntivirusEnabled","RealTimeProtectionEnabled","BehaviorMonitorEnabled","IoavProtectionEnabled","OnAccessProtectionEnabled")) {
        if ([bool]$old.$name -and -not [bool]$now.$name) {
            Add-HealthAlert "HIGH" $name $old.$name $now.$name "Defender protection changed from enabled to disabled"
        }
    }

    foreach ($name in @("DisableRealtimeMonitoring","DisableBehaviorMonitoring","DisableIOAVProtection","DisableBlockAtFirstSeen")) {
        if (-not [bool]$old.$name -and [bool]$now.$name) {
            Add-HealthAlert "HIGH" $name $old.$name $now.$name "Protection-disable flag changed to True"
        }
    }

    function Get-NewItems($Before,$After) {
        return @($After | Where-Object { $_ -and ($_ -notin @($Before)) })
    }

    foreach ($item in (Get-NewItems $old.ExclusionPath $now.ExclusionPath)) {
        Add-HealthAlert "HIGH" "ExclusionPath" "(not present)" $item "New Defender exclusion added"
    }
    foreach ($item in (Get-NewItems $old.ExclusionProcess $now.ExclusionProcess)) {
        Add-HealthAlert "HIGH" "ExclusionProcess" "(not present)" $item "New Defender process exclusion added"
    }
    foreach ($item in (Get-NewItems $old.ExclusionExtension $now.ExclusionExtension)) {
        Add-HealthAlert "HIGH" "ExclusionExtension" "(not present)" $item "New Defender extension exclusion added"
    }

    $oldAsr = @{}
    foreach ($rule in @($old.ASR)) { $oldAsr[([string]$rule.Id).ToLowerInvariant()] = [int]$rule.Action }

    $newAsr = @{}
    foreach ($rule in @($now.ASR)) { $newAsr[([string]$rule.Id).ToLowerInvariant()] = [int]$rule.Action }

    foreach ($id in $oldAsr.Keys) {
        if (-not $newAsr.ContainsKey($id)) {
            Add-HealthAlert "HIGH" "ASR:$id" $oldAsr[$id] "(removed)" "Previously configured ASR rule disappeared"
            continue
        }
        $beforeRank = Get-SentinelAsrRank $oldAsr[$id]
        $afterRank = Get-SentinelAsrRank $newAsr[$id]
        if ($beforeRank -ge 0 -and $afterRank -ge 0 -and $afterRank -lt $beforeRank) {
            Add-HealthAlert "HIGH" "ASR:$id" $oldAsr[$id] $newAsr[$id] "ASR protection mode weakened"
        }
    }

    $oldCfaRank = Get-SentinelCfaRank $old.EnableControlledFolderAccess
    $newCfaRank = Get-SentinelCfaRank $now.EnableControlledFolderAccess
    if ($oldCfaRank -ge 0 -and $newCfaRank -ge 0 -and $newCfaRank -lt $oldCfaRank) {
        Add-HealthAlert "HIGH" "ControlledFolderAccess" $old.EnableControlledFolderAccess $now.EnableControlledFolderAccess "CFA protection mode weakened"
    }

    $oldNetworkRank = Get-SentinelNetworkProtectionRank $old.EnableNetworkProtection
    $newNetworkRank = Get-SentinelNetworkProtectionRank $now.EnableNetworkProtection
    if ($oldNetworkRank -ge 0 -and $newNetworkRank -ge 0 -and $newNetworkRank -lt $oldNetworkRank) {
        Add-HealthAlert "HIGH" "NetworkProtection" $old.EnableNetworkProtection $now.EnableNetworkProtection "Network Protection weakened"
    }

    $oldPuaRank = Get-SentinelPuaRank $old.PUAProtection
    $newPuaRank = Get-SentinelPuaRank $now.PUAProtection
    if ($oldPuaRank -ge 0 -and $newPuaRank -ge 0 -and $newPuaRank -lt $oldPuaRank) {
        Add-HealthAlert "HIGH" "PUAProtection" $old.PUAProtection $now.PUAProtection "PUA protection weakened"
    }

    $oldCloudRank = Get-SentinelCloudBlockRank $old.CloudBlockLevel
    $newCloudRank = Get-SentinelCloudBlockRank $now.CloudBlockLevel
    if ($oldCloudRank -ge 0 -and $newCloudRank -ge 0 -and $newCloudRank -lt $oldCloudRank) {
        Add-HealthAlert "HIGH" "CloudBlockLevel" $old.CloudBlockLevel $now.CloudBlockLevel "Cloud block level weakened"
    }
}

if ($now.AntivirusSignatureAge -gt 2) {
    Add-HealthAlert "MEDIUM" "AntivirusSignatureAge" "<=2" $now.AntivirusSignatureAge "Defender signatures appear stale"
}

if ($config.DefenderHardening.MonitorExpectedSettings) {
    $profile = [string]$config.DefenderHardening.ExpectedProfile
    $requiredAsrRank = if ($profile -eq "RecommendedBlock") { 3 } else { 1 }
    $requiredCfaRank = if ($profile -eq "RecommendedBlock") { 3 } else { 1 }

    foreach ($name in @("AntivirusEnabled","RealTimeProtectionEnabled","BehaviorMonitorEnabled","IoavProtectionEnabled","OnAccessProtectionEnabled")) {
        if (-not [bool]$now.$name) {
            Add-HealthAlert "HIGH" $name "True" $now.$name "Expected Defender profile"
        }
    }

    foreach ($name in @("DisableRealtimeMonitoring","DisableBehaviorMonitoring","DisableIOAVProtection","DisableBlockAtFirstSeen")) {
        if ([bool]$now.$name) {
            Add-HealthAlert "HIGH" $name "False" $now.$name "Expected Defender profile"
        }
    }

    if (-not $now.CheckForSignaturesBeforeRunningScan) {
        Add-HealthAlert "MEDIUM" "CheckForSignaturesBeforeRunningScan" "True" $now.CheckForSignaturesBeforeRunningScan "Expected Defender profile"
    }
    if ((Get-SentinelMapsRank $now.MAPSReporting) -lt 2) {
        Add-HealthAlert "HIGH" "MAPSReporting" "Advanced" $now.MAPSReporting "Expected Defender profile"
    }
    if ((Get-SentinelCloudBlockRank $now.CloudBlockLevel) -lt 2) {
        Add-HealthAlert "HIGH" "CloudBlockLevel" "High or stronger" $now.CloudBlockLevel "Expected Defender profile"
    }
    if ((Get-SentinelNetworkProtectionRank $now.EnableNetworkProtection) -lt 2) {
        Add-HealthAlert "HIGH" "NetworkProtection" "Enabled" $now.EnableNetworkProtection "Expected Defender profile"
    }
    if ((Get-SentinelPuaRank $now.PUAProtection) -lt 2) {
        Add-HealthAlert "MEDIUM" "PUAProtection" "Enabled" $now.PUAProtection "Expected Defender profile"
    }
    if ((Get-SentinelCfaRank $now.EnableControlledFolderAccess) -lt $requiredCfaRank) {
        $expectedCfa = if ($profile -eq "RecommendedBlock") { "Enabled" } else { "AuditMode or stronger" }
        Add-HealthAlert "HIGH" "ControlledFolderAccess" $expectedCfa $now.EnableControlledFolderAccess "Expected Defender profile"
    }

    $nowAsr = @{}
    foreach ($rule in @($now.ASR)) { $nowAsr[([string]$rule.Id).ToLowerInvariant()] = [int]$rule.Action }
    foreach ($id in $managedAsr.Keys) {
        $normalizedId = $id.ToLowerInvariant()
        if (-not $nowAsr.ContainsKey($normalizedId)) {
            Add-HealthAlert "HIGH" "ASR:$normalizedId" "Configured" "(missing)" ("Expected profile: " + $managedAsr[$id])
            continue
        }
        if ((Get-SentinelAsrRank $nowAsr[$normalizedId]) -lt $requiredAsrRank) {
            $expectedAsr = if ($profile -eq "RecommendedBlock") { "Enabled" } else { "AuditMode or stronger" }
            Add-HealthAlert "HIGH" "ASR:$normalizedId" $expectedAsr $nowAsr[$normalizedId] ("Expected profile: " + $managedAsr[$id])
        }
    }
}

try {
    $now | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $statePath -Encoding UTF8 -ErrorAction Stop
} catch {
    Write-SentinelError -Root $Root -Component "DefenderHealth" -Operation "Save health state" -Exception $_.Exception
}

if (-not $Quiet) {
    [pscustomobject]@{
        AntivirusEnabled=$now.AntivirusEnabled
        RealTimeProtectionEnabled=$now.RealTimeProtectionEnabled
        BehaviorMonitorEnabled=$now.BehaviorMonitorEnabled
        IoavProtectionEnabled=$now.IoavProtectionEnabled
        SignatureAgeDays=$now.AntivirusSignatureAge
        MAPSReporting=$now.MAPSReporting
        NetworkProtection=$now.EnableNetworkProtection
        PUAProtection=$now.PUAProtection
        CFA=$now.EnableControlledFolderAccess
        CloudBlockLevel=$now.CloudBlockLevel
    } | Format-List
}
