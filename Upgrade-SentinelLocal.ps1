#Requires -RunAsAdministrator
param(
    [string]$InstallRoot = "C:\ProgramData\SentinelLocal"
)

$ErrorActionPreference = "Stop"
$sourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$watcherTaskName = "SentinelLocal Watcher"
$responseWorkerTaskName = "SentinelLocal Response Worker"
$integrityTaskName = "SentinelLocal Integrity Monitor"

if ($InstallRoot -match '"') {
    throw 'InstallRoot cannot contain a double quote character.'
}

$files = @(
    "Common.ps1","Config.json","DefenderHealth.ps1","DefenderHardening.ps1",
    "Restore-DefenderBackup.ps1","Response.ps1","ResponseWorker.ps1","Watcher.ps1",
    "Check-SentinelLocal.ps1","SelfTest-SentinelLocal.ps1","Clear-SentinelFirewallRules.ps1",
    "IntegrityMonitor.ps1","Update-SentinelIntegrityBaseline.ps1","Verify-SentinelLogs.ps1"
)

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

# PRE-FLIGHT: keep the currently installed watcher running until package/config checks pass.
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
$existingConfig = $null
if (Test-Path (Join-Path $InstallRoot "Config.json")) {
    $existingConfig = Get-Content (Join-Path $InstallRoot "Config.json") -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
$mergedConfig = if ($existingConfig) { Merge-ConfigObject $packageConfig $existingConfig } else { $packageConfig }
$mergedConfig.Version = [string]$packageConfig.Version
$mergedJson = $mergedConfig | ConvertTo-Json -Depth 20
[void]($mergedJson | ConvertFrom-Json -ErrorAction Stop)

$oldTaskXml = @{}
foreach ($taskName in @($watcherTaskName,$responseWorkerTaskName,$integrityTaskName)) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        $oldTaskXml[$taskName] = Export-ScheduledTask -TaskName $taskName -ErrorAction Stop
    }
}

$backupRoot = Join-Path $InstallRoot ("backups\upgrade-pre-v1.0.0-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$updateSucceeded = $false

try {
    foreach ($taskName in @($watcherTaskName,$responseWorkerTaskName,$integrityTaskName)) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }

    New-Item $backupRoot -ItemType Directory -Force | Out-Null
    foreach ($file in $files) {
        $installedPath = Join-Path $InstallRoot $file
        if (Test-Path -LiteralPath $installedPath -PathType Leaf) {
            Copy-Item $installedPath (Join-Path $backupRoot $file) -Force
        }
    }

    foreach ($file in @($files | Where-Object { $_ -ne "Config.json" })) {
        Copy-Item (Join-Path $sourceRoot $file) (Join-Path $InstallRoot $file) -Force
    }
    Set-Content -LiteralPath (Join-Path $InstallRoot "Config.json") -Value $mergedJson -Encoding UTF8

    Set-SentinelAcl -Path $InstallRoot

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallRoot "SelfTest-SentinelLocal.ps1") -Root $InstallRoot -PreStart
    if ($LASTEXITCODE -ne 0) {
        throw "SentinelLocal v1.0.0 pre-start SelfTest failed with exit code $LASTEXITCODE"
    }

    foreach ($taskName in @($watcherTaskName,$responseWorkerTaskName,$integrityTaskName)) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650)

    Register-ScheduledTask -TaskName $watcherTaskName -Action (New-SentinelTaskAction "Watcher.ps1") -Trigger $trigger -Principal $principal -Settings $settings `
        -Description "SentinelLocal v1.0.0: continuous monitoring and Defender event correlation." | Out-Null
    Register-ScheduledTask -TaskName $responseWorkerTaskName -Action (New-SentinelTaskAction "ResponseWorker.ps1") -Trigger $trigger -Principal $principal -Settings $settings `
        -Description "SentinelLocal v1.0.0: priority Defender scan and containment response worker." | Out-Null
    Register-ScheduledTask -TaskName $integrityTaskName -Action (New-SentinelTaskAction "IntegrityMonitor.ps1") -Trigger $trigger -Principal $principal -Settings $settings `
        -Description "SentinelLocal v1.0.0: self-integrity, task, and heartbeat monitoring." | Out-Null

    & (Join-Path $InstallRoot "Update-SentinelIntegrityBaseline.ps1") -Root $InstallRoot

    Start-ScheduledTask -TaskName $responseWorkerTaskName -ErrorAction Stop
    Start-ScheduledTask -TaskName $watcherTaskName -ErrorAction Stop
    Start-ScheduledTask -TaskName $integrityTaskName -ErrorAction Stop
    $updateSucceeded = $true
}
finally {
    if (-not $updateSucceeded) {
        Write-Host "Upgrade failed; attempting rollback..." -ForegroundColor Yellow

        foreach ($taskName in @($watcherTaskName,$responseWorkerTaskName,$integrityTaskName)) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }

        foreach ($file in $files) {
            $installedPath = Join-Path $InstallRoot $file
            $backupPath = Join-Path $backupRoot $file
            if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
                Copy-Item $backupPath $installedPath -Force -ErrorAction SilentlyContinue
            } elseif ($file -in @(
                "ResponseWorker.ps1","Clear-SentinelFirewallRules.ps1",
                "IntegrityMonitor.ps1","Update-SentinelIntegrityBaseline.ps1","Verify-SentinelLogs.ps1"
            )) {
                Remove-Item $installedPath -Force -ErrorAction SilentlyContinue
            }
        }

        foreach ($taskName in $oldTaskXml.Keys) {
            Register-ScheduledTask -TaskName $taskName -Xml $oldTaskXml[$taskName] -Force -ErrorAction SilentlyContinue | Out-Null
            Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "Upgrade to SentinelLocal v1.0.0 complete." -ForegroundColor Green
Write-Host "Existing Config.json values were preserved; new v1.0.0 keys were added from defaults."
Write-Host "All SentinelLocal scheduled tasks pass -Root explicitly."
Write-Host "Backup: $backupRoot"
