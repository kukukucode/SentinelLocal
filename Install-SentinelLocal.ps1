#Requires -RunAsAdministrator
param(
    [string]$InstallRoot = "C:\ProgramData\SentinelLocal",
    [switch]$ApplyDefenderAuditProfile
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot 'Common.ps1')
$sourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$watcherTaskName = "SentinelLocal Watcher"
$responseWorkerTaskName = "SentinelLocal Response Worker"
$integrityTaskName = "SentinelLocal Integrity Monitor"

if ($InstallRoot -match '"') {
    throw 'InstallRoot cannot contain a double quote character.'
}

$files = @(Get-SentinelPackageFiles)

function Merge-ConfigObject {
    param($Defaults,$Existing)
    if ($null -eq $Existing) { return $Defaults }

    $result = [ordered]@{}
    foreach ($property in $Defaults.PSObject.Properties) {
        $name = $property.Name
        $existingProperty = $Existing.PSObject.Properties[$name]
        if ($null -ne $existingProperty) {
            if (($property.Value -is [pscustomobject]) -and ($existingProperty.Value -is [pscustomobject])) {
                $result[$name] = Merge-ConfigObject $property.Value $existingProperty.Value
            } else {
                $result[$name] = $existingProperty.Value
            }
        } else {
            $result[$name] = $property.Value
        }
    }
    foreach ($property in $Existing.PSObject.Properties) {
        if (-not $result.Contains($property.Name)) { $result[$property.Name] = $property.Value }
    }
    return [pscustomobject]$result
}

function Set-SentinelAcl {
    param([string]$Path)

    & icacls.exe $Path /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r failed with exit code $LASTEXITCODE" }

    & icacls.exe $Path /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls SID grant failed with exit code $LASTEXITCODE" }
}

function New-SentinelTaskAction {
    param([string]$ScriptName)
    $scriptPath = Join-Path $InstallRoot $ScriptName
    $arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Root "{1}"' -f $scriptPath,$InstallRoot
    return New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments
}

# Preflight before changing the machine.
foreach ($file in $files) {
    $sourcePath = Join-Path $sourceRoot $file
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw "Package file missing: $file" }
}
foreach ($file in @($files | Where-Object { $_ -like "*.ps1" })) {
    $sourcePath = Join-Path $sourceRoot $file
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$tokens,[ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        $messages = @($parseErrors | ForEach-Object { $_.Message }) -join "; "
        throw "PowerShell syntax check failed for $file : $messages"
    }
}

$packageConfig = Get-Content (Join-Path $sourceRoot "Config.json") -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$mergedConfig = $packageConfig
if (Test-Path (Join-Path $InstallRoot "Config.json")) {
    $existingConfig = Get-Content (Join-Path $InstallRoot "Config.json") -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $mergedConfig = Merge-ConfigObject $packageConfig $existingConfig
    $mergedConfig.Version = [string]$packageConfig.Version
}
$mergedJson = $mergedConfig | ConvertTo-Json -Depth 20
[void]($mergedJson | ConvertFrom-Json -ErrorAction Stop)

New-Item $InstallRoot -ItemType Directory -Force | Out-Null
New-Item (Join-Path $InstallRoot "logs"),(Join-Path $InstallRoot "evidence"),(Join-Path $InstallRoot "state"),(Join-Path $InstallRoot "backups") -ItemType Directory -Force | Out-Null

if (Test-Path (Join-Path $InstallRoot "Config.json")) {
    Copy-Item (Join-Path $InstallRoot "Config.json") (Join-Path $InstallRoot ("backups\Config-before-v1.1.0-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))) -Force
}

foreach ($file in @($files | Where-Object { $_ -ne "Config.json" })) {
    Copy-Item (Join-Path $sourceRoot $file) (Join-Path $InstallRoot $file) -Force
}
Set-Content -LiteralPath (Join-Path $InstallRoot "Config.json") -Value $mergedJson -Encoding UTF8

Set-SentinelAcl -Path $InstallRoot

if (-not [System.Diagnostics.EventLog]::SourceExists("SentinelLocal")) {
    New-EventLog -LogName Application -Source "SentinelLocal"
}

if ($ApplyDefenderAuditProfile) {
    & (Join-Path $InstallRoot "DefenderHardening.ps1") -Profile AuditFirst -Root $InstallRoot

    $configPath = Join-Path $InstallRoot "Config.json"
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    $config.DefenderHardening.MonitorExpectedSettings = $true
    $config.DefenderHardening.ExpectedProfile = "AuditFirst"
    $config | ConvertTo-Json -Depth 20 | Set-Content $configPath -Encoding UTF8
}

foreach ($taskName in @($watcherTaskName,$responseWorkerTaskName,$integrityTaskName)) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}

$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650)

Register-ScheduledTask -TaskName $watcherTaskName -Action (New-SentinelTaskAction "Watcher.ps1") -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "SentinelLocal v1.1.0: continuous monitoring and Defender event correlation." | Out-Null
Register-ScheduledTask -TaskName $responseWorkerTaskName -Action (New-SentinelTaskAction "ResponseWorker.ps1") -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "SentinelLocal v1.1.0: priority Defender scan and containment response worker." | Out-Null
Register-ScheduledTask -TaskName $integrityTaskName -Action (New-SentinelTaskAction "IntegrityMonitor.ps1") -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "SentinelLocal v1.1.0: self-integrity, task, and heartbeat monitoring." | Out-Null

& (Join-Path $InstallRoot "Update-SentinelIntegrityBaseline.ps1") -Root $InstallRoot

Start-ScheduledTask -TaskName $responseWorkerTaskName
Start-ScheduledTask -TaskName $watcherTaskName
Start-ScheduledTask -TaskName $integrityTaskName

Write-Host ""
Write-Host "SentinelLocal v1.1.0 installed." -ForegroundColor Green
Write-Host "Root: $InstallRoot"
Write-Host "Tasks: $watcherTaskName / $responseWorkerTaskName / $integrityTaskName"
if (-not $ApplyDefenderAuditProfile) {
    Write-Host ""
    Write-Host "Defender settings were NOT changed." -ForegroundColor Yellow
    Write-Host "To apply the audit-first hardening profile:"
    Write-Host "  & '$InstallRoot\DefenderHardening.ps1' -Profile AuditFirst"
}
