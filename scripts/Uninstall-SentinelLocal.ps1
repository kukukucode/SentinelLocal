#Requires -RunAsAdministrator
param(
    [switch]$RemoveData,
    [string]$InstallRoot = "C:\ProgramData\SentinelLocal"
)

$watcherTaskName="SentinelLocal Watcher"
$responseWorkerTaskName="SentinelLocal Response Worker"
$integrityTaskName="SentinelLocal Integrity Monitor"

foreach ($taskName in @($watcherTaskName,$responseWorkerTaskName,$integrityTaskName)) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}

$escapedRoot = [regex]::Escape($InstallRoot)
Get-CimInstance Win32_Process |
Where-Object {
    $_.CommandLine -and
    $_.CommandLine -match $escapedRoot -and
    $_.CommandLine -match '(Watcher|ResponseWorker|IntegrityMonitor)\.ps1'
} |
ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Get-NetFirewallRule -Group "SentinelLocal" -ErrorAction SilentlyContinue |
Remove-NetFirewallRule -ErrorAction SilentlyContinue

if ($RemoveData) {
    Remove-Item $InstallRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "SentinelLocal and its local logs/evidence were removed."
} else {
    Write-Host "SentinelLocal tasks removed. Logs/evidence preserved at $InstallRoot"
}

Write-Host "Defender hardening is NOT reverted automatically."
Write-Host "If needed, use Restore-DefenderBackup.ps1 with a saved backup."
