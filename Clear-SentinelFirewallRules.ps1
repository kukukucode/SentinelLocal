#Requires -RunAsAdministrator
param(
    [switch]$ListOnly
)

$rules = @(Get-NetFirewallRule -Group "SentinelLocal" -ErrorAction SilentlyContinue)

if ($ListOnly) {
    if ($rules.Count -eq 0) {
        Write-Host "No SentinelLocal firewall rules."
        return
    }
    $rules | Select-Object DisplayName,Enabled,Direction,Action,Description | Format-Table -AutoSize
    return
}

if ($rules.Count -eq 0) {
    Write-Host "No SentinelLocal firewall rules to remove."
    return
}

$rules | Remove-NetFirewallRule -ErrorAction Stop
Write-Host ("Removed {0} SentinelLocal firewall rule(s)." -f $rules.Count) -ForegroundColor Green
