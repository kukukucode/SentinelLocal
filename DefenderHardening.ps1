#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [ValidateSet("Status","AuditFirst","RecommendedBlock")]
    [string]$Profile = "Status",
    [string]$Root = "C:\ProgramData\SentinelLocal"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

$backups = Join-Path $Root "backups"
$logs = Join-Path $Root "logs"
$AsrNames = Get-SentinelManagedAsrRules

function Get-CoreSnapshot {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction Stop
        $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        [ordered]@{
            OperatingSystem=[string]$os.Caption
            # Only documented Pro/Enterprise client editions are applied automatically.
            NetworkProtectionSupported=([int]$os.ProductType -eq 1 -and [int]$os.OperatingSystemSKU -in @(4,27,48,49,125,126) -and [int]$os.BuildNumber -ge 16299)
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

$snapshot=Get-CoreSnapshot
$plan=@(Get-SentinelHardeningPlan $snapshot $Profile)
$plan | Format-Table -AutoSize
if(-not $PSCmdlet.ShouldProcess('Microsoft Defender preferences','Back up, apply planned profile, verify each setting and record outcome')) { return }
New-Item $backups,$logs -ItemType Directory -Force | Out-Null
$backupPath=Join-Path $backups ('defender-'+(Get-Date -Format 'yyyyMMddHHmmssfff')+'-'+[guid]::NewGuid().ToString('N')+'.json')
Write-SentinelAtomicJson $backupPath $snapshot
$failures=[Collections.Generic.List[string]]::new()
foreach($item in $plan | Where-Object { $_.Kind -eq 'Preference' }) {
    try { $arguments=@{ErrorAction='Stop'};$arguments[$item.Setting]=$item.Desired;Set-MpPreference @arguments }
    catch { $failures.Add($item.Setting+': '+$_.Exception.Message) }
}
try {
    $map=@{}
    foreach($rule in @(Get-SentinelAsrTable)) { $map[[string]$rule.Id]=[int]$rule.Action }
    foreach($item in $plan | Where-Object { $_.Kind -eq 'ASR' }) { $map[$item.Setting]=[int]$item.Desired }
    $ids=@($map.Keys);$actions=@($ids | ForEach-Object { $map[$_] })
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop
} catch { $failures.Add('ASR: '+$_.Exception.Message) }
$actual=Get-CoreSnapshot
foreach($item in $plan | Where-Object { $_.Kind -ne 'Unavailable' }) {
    if($item.Kind -eq 'ASR') { $value=@($actual.Preference.AttackSurfaceReductionRules | Where-Object { $_.Id -ieq $item.Setting } | Select-Object -ExpandProperty Action) }
    else { $value=$actual.Preference.($item.Setting) }
    if((ConvertTo-SentinelPreferenceValue $item.Setting $value) -ine (ConvertTo-SentinelPreferenceValue $item.Setting $item.Desired)) { $failures.Add('Post-apply mismatch: '+$item.Setting+' desired='+$item.Desired+' actual='+$value) }
}
$audit=[ordered]@{Type='DefenderProfileApplied';Severity=$(if($failures.Count){'HIGH'}else{'MEDIUM'});Profile=$Profile;Operator=[Security.Principal.WindowsIdentity]::GetCurrent().Name;Backup=$backupPath;Verified=($failures.Count -eq 0);Unavailable=@($plan | Where-Object Kind -eq 'Unavailable' | Select-Object -ExpandProperty Setting);Failures=@($failures)}
if(-not (Write-SentinelJsonLine (Join-Path $logs 'administration.jsonl') $audit)) { throw 'Cannot persist Defender hardening audit.' }
Write-Output $audit
if($failures.Count) { throw ('Some changes failed or were overridden by policy/tamper protection. Review the backup and audit: '+$backupPath) }
