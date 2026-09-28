#Requires -RunAsAdministrator
param(
    [ValidateSet("Status","AuditFirst","RecommendedBlock")]
    [string]$Profile = "Status",
    [string]$Root = "C:\ProgramData\SentinelLocal"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

$backups = Join-Path $Root "backups"
$logs = Join-Path $Root "logs"
New-Item $backups,$logs -ItemType Directory -Force | Out-Null
$AsrNames = Get-SentinelManagedAsrRules

function Get-CoreSnapshot {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction Stop
        [ordered]@{
            SavedAt = (Get-Date).ToString("o")
            ComputerStatus = [ordered]@{
                AntivirusEnabled = $status.AntivirusEnabled
                RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
                BehaviorMonitorEnabled = $status.BehaviorMonitorEnabled
                IoavProtectionEnabled = $status.IoavProtectionEnabled
                OnAccessProtectionEnabled = $status.OnAccessProtectionEnabled
                AntivirusSignatureAge = $status.AntivirusSignatureAge
                AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
            }
            Preference = [ordered]@{
                MAPSReporting = [string]$pref.MAPSReporting
                SubmitSamplesConsent = [string]$pref.SubmitSamplesConsent
                DisableBlockAtFirstSeen = $pref.DisableBlockAtFirstSeen
                PUAProtection = [string]$pref.PUAProtection
                EnableNetworkProtection = [string]$pref.EnableNetworkProtection
                CheckForSignaturesBeforeRunningScan = $pref.CheckForSignaturesBeforeRunningScan
                CloudBlockLevel = [string]$pref.CloudBlockLevel
                EnableControlledFolderAccess = [string]$pref.EnableControlledFolderAccess
                DisableRealtimeMonitoring = $pref.DisableRealtimeMonitoring
                DisableBehaviorMonitoring = $pref.DisableBehaviorMonitoring
                DisableIOAVProtection = $pref.DisableIOAVProtection
                ExclusionPath = @($pref.ExclusionPath)
                ExclusionProcess = @($pref.ExclusionProcess)
                ExclusionExtension = @($pref.ExclusionExtension)
                AttackSurfaceReductionRules = @(Get-SentinelAsrTable)
            }
        }
    } catch {
        Write-SentinelError -Root $Root -Component "DefenderHardening" -Operation "Get Defender snapshot" -Exception $_.Exception
        throw
    }
}

function Show-Status {
    $snap = Get-CoreSnapshot
    $snap.ComputerStatus.GetEnumerator() | ForEach-Object {
        [pscustomobject]@{Setting=$_.Key;Value=$_.Value}
    } | Format-Table -AutoSize

    Write-Host "`n=== Defender preferences ==="
    $snap.Preference.GetEnumerator() |
        Where-Object { $_.Key -ne "AttackSurfaceReductionRules" } |
        ForEach-Object { [pscustomobject]@{Setting=$_.Key;Value=($_.Value -join ", ")} } |
        Format-Table -AutoSize

    Write-Host "`n=== ASR rules ==="
    $rows = foreach ($rule in $snap.Preference.AttackSurfaceReductionRules) {
        [pscustomobject]@{
            Id = $rule.Id
            Name = $AsrNames[$rule.Id]
            Action = switch ([int]$rule.Action) {
                0 {"Disabled"}
                1 {"Enabled"}
                2 {"AuditMode"}
                5 {"NotConfigured"}
                6 {"Warn"}
                default {[string]$rule.Action}
            }
        }
    }
    $rows | Format-Table -AutoSize
}

if ($Profile -eq "Status") {
    Show-Status
    exit 0
}

$backup = Get-CoreSnapshot
$backupPath = Join-Path $backups ("defender-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$backup | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $backupPath -Encoding UTF8
Write-Host "Backup: $backupPath"

$changes = @(
    @{Name="Cloud protection"; Script={ Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop }},
    @{Name="Safe sample submission"; Script={ Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop }},
    @{Name="Block at First Sight"; Script={ Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction Stop }},
    @{Name="PUA protection"; Script={ Set-MpPreference -PUAProtection Enabled -ErrorAction Stop }},
    @{Name="Network Protection"; Script={ Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop }},
    @{Name="Signature check before scan"; Script={ Set-MpPreference -CheckForSignaturesBeforeRunningScan $true -ErrorAction Stop }},
    @{Name="Cloud block level"; Script={ Set-MpPreference -CloudBlockLevel High -ErrorAction Stop }},
    @{Name="Behavior monitoring"; Script={ Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop }},
    @{Name="IOAV protection"; Script={ Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop }},
    @{Name="Real-time protection"; Script={ Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop }}
)

foreach ($change in $changes) {
    try {
        & $change.Script
        Write-Host ("[OK] {0}" -f $change.Name) -ForegroundColor Green
    } catch {
        Write-Host ("[POLICY/ERROR] {0}: {1}" -f $change.Name,$_.Exception.Message) -ForegroundColor Yellow
        Write-SentinelError -Root $Root -Component "DefenderHardening" -Operation $change.Name -Exception $_.Exception -Severity "MEDIUM"
    }
}

$cfaMode = if ($Profile -eq "AuditFirst") { "AuditMode" } else { "Enabled" }
try {
    Set-MpPreference -EnableControlledFolderAccess $cfaMode -ErrorAction Stop
    Write-Host "[OK] Controlled Folder Access => $cfaMode" -ForegroundColor Green
} catch {
    Write-Host "[POLICY/ERROR] CFA: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-SentinelError -Root $Root -Component "DefenderHardening" -Operation "Controlled Folder Access" -Exception $_.Exception -Severity "MEDIUM"
}

try {
    $current = Get-SentinelAsrTable
    $map = @{}
    foreach ($rule in $current) { $map[[string]$rule.Id] = [int]$rule.Action }

    $desiredAction = if ($Profile -eq "AuditFirst") { 2 } else { 1 }
    foreach ($id in $AsrNames.Keys) { $map[$id.ToLowerInvariant()] = $desiredAction }

    $ids = @($map.Keys)
    $actions = @($ids | ForEach-Object { [int]$map[$_] })
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop

    $modeName = if ($desiredAction -eq 2) { "AuditMode" } else { "Enabled" }
    Write-Host ("[OK] {0} selected ASR rules => {1}" -f $AsrNames.Count,$modeName) -ForegroundColor Green
} catch {
    Write-Host "[POLICY/ERROR] ASR: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-SentinelError -Root $Root -Component "DefenderHardening" -Operation "ASR rules" -Exception $_.Exception -Severity "MEDIUM"
}

Write-Host "`nApplied profile: $Profile" -ForegroundColor Cyan
Write-Host "Tamper Protection / Intune / GPO may intentionally reject or override local changes."
Write-Host "Run: .\DefenderHardening.ps1 -Profile Status"
