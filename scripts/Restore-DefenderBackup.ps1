#Requires -RunAsAdministrator
param(
    [string]$BackupPath,
    [string]$Root = "C:\ProgramData\SentinelLocal"
)

$ErrorActionPreference = "Stop"
$commonPath=Join-Path $PSScriptRoot 'Common.ps1'
if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) { $commonPath=Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Common.ps1' }
. $commonPath

if (-not $BackupPath) {
    $BackupPath = Get-ChildItem (Join-Path $Root "backups\defender-*.json") -File -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending |
                  Select-Object -First 1 -ExpandProperty FullName
}
if (-not $BackupPath -or -not (Test-Path $BackupPath)) { throw "Defender backup not found." }

try {
    $backup = Get-Content $BackupPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-SentinelError -Root $Root -Component "Restore" -Operation "Read backup" -Exception $_.Exception
    throw
}
$pref = $backup.Preference

$attempts = @(
    @{Name="MAPSReporting"; Script={ Set-MpPreference -MAPSReporting $pref.MAPSReporting -ErrorAction Stop }},
    @{Name="SubmitSamplesConsent"; Script={ Set-MpPreference -SubmitSamplesConsent $pref.SubmitSamplesConsent -ErrorAction Stop }},
    @{Name="DisableBlockAtFirstSeen"; Script={ Set-MpPreference -DisableBlockAtFirstSeen ([bool]$pref.DisableBlockAtFirstSeen) -ErrorAction Stop }},
    @{Name="PUAProtection"; Script={ Set-MpPreference -PUAProtection $pref.PUAProtection -ErrorAction Stop }},
    @{Name="EnableNetworkProtection"; Script={ Set-MpPreference -EnableNetworkProtection $pref.EnableNetworkProtection -ErrorAction Stop }},
    @{Name="CheckForSignaturesBeforeRunningScan"; Script={ Set-MpPreference -CheckForSignaturesBeforeRunningScan ([bool]$pref.CheckForSignaturesBeforeRunningScan) -ErrorAction Stop }},
    @{Name="CloudBlockLevel"; Script={ Set-MpPreference -CloudBlockLevel $pref.CloudBlockLevel -ErrorAction Stop }},
    @{Name="EnableControlledFolderAccess"; Script={ Set-MpPreference -EnableControlledFolderAccess $pref.EnableControlledFolderAccess -ErrorAction Stop }},
    @{Name="DisableRealtimeMonitoring"; Script={ Set-MpPreference -DisableRealtimeMonitoring ([bool]$pref.DisableRealtimeMonitoring) -ErrorAction Stop }},
    @{Name="DisableBehaviorMonitoring"; Script={ Set-MpPreference -DisableBehaviorMonitoring ([bool]$pref.DisableBehaviorMonitoring) -ErrorAction Stop }},
    @{Name="DisableIOAVProtection"; Script={ Set-MpPreference -DisableIOAVProtection ([bool]$pref.DisableIOAVProtection) -ErrorAction Stop }}
)

foreach ($attempt in $attempts) {
    try {
        & $attempt.Script
        Write-Host "[OK] $($attempt.Name)" -ForegroundColor Green
    } catch {
        Write-Host "[POLICY/ERROR] $($attempt.Name): $($_.Exception.Message)" -ForegroundColor Yellow
        Write-SentinelError -Root $Root -Component "Restore" -Operation $attempt.Name -Exception $_.Exception -Severity "MEDIUM"
    }
}

$backupAsr = @($pref.AttackSurfaceReductionRules)
try {
    $managedRules = Get-SentinelManagedAsrRules
    $currentAsr = @(Get-SentinelAsrTable)

    $currentMap = @{}
    foreach ($rule in $currentAsr) {
        $currentMap[([string]$rule.Id).ToLowerInvariant()] = [int]$rule.Action
    }

    $backupMap = @{}
    foreach ($rule in $backupAsr) {
        $backupMap[([string]$rule.Id).ToLowerInvariant()] = [int]$rule.Action
    }

    # Revert only the ASR GUIDs SentinelLocal manages. Unrelated rules that were
    # added or changed after the backup are preserved.
    foreach ($id in $managedRules.Keys) {
        $normalizedId = $id.ToLowerInvariant()
        if ($backupMap.ContainsKey($normalizedId)) {
            $currentMap[$normalizedId] = [int]$backupMap[$normalizedId]
        } else {
            [void]$currentMap.Remove($normalizedId)
        }
    }

    if ($currentMap.Count -gt 0) {
        $ids = @($currentMap.Keys)
        $actions = @($ids | ForEach-Object { [int]$currentMap[$_] })
        Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop
    } else {
        # Set-MpPreference cannot express an empty ASR collection reliably.
        # Remove only currently configured SentinelLocal-managed rules.
        $managedCurrentIds = @()
        $managedCurrentActions = @()
        foreach ($rule in $currentAsr) {
            $id = ([string]$rule.Id).ToLowerInvariant()
            if ($managedRules.Contains($id)) {
                $managedCurrentIds += $id
                $managedCurrentActions += [int]$rule.Action
            }
        }
        if ($managedCurrentIds.Count -gt 0) {
            Remove-MpPreference -AttackSurfaceReductionRules_Ids $managedCurrentIds `
                -AttackSurfaceReductionRules_Actions $managedCurrentActions -ErrorAction Stop
        }
    }

    Write-Host "[OK] SentinelLocal-managed ASR rules restored" -ForegroundColor Green
} catch {
    Write-Host "[POLICY/ERROR] ASR restore: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-SentinelError -Root $Root -Component "Restore" -Operation "Restore SentinelLocal-managed ASR" -Exception $_.Exception -Severity "MEDIUM"
}

Write-Host "Restored from: $BackupPath"
Write-Host "Defender exclusions are intentionally not rewritten by this restore script."
