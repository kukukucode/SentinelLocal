#Requires -RunAsAdministrator
param([string]$InstallRoot='C:\ProgramData\SentinelLocal',[string]$TrustedSignerThumbprint,[switch]$AllowUnsignedPackage,[ValidateRange(5,300)][int]$StartupTimeoutSeconds=90)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$sourceRoot=$PSScriptRoot
$files=@(Get-SentinelPackageFiles)
$watcherTaskName='SentinelLocal Watcher';$responseWorkerTaskName='SentinelLocal Response Worker';$integrityTaskName='SentinelLocal Integrity Monitor'
$taskNames=@($watcherTaskName,$responseWorkerTaskName,$integrityTaskName)
if($InstallRoot -match '"' -or -not [IO.Path]::IsPathRooted($InstallRoot)) { throw 'An absolute installation root without double quotes is required.' }
if([IO.Path]::GetFullPath($InstallRoot).TrimEnd('\') -ieq [IO.Path]::GetFullPath($sourceRoot).TrimEnd('\')) { throw 'Source package and installation root must differ.' }
foreach($name in $taskNames) {
    $existingTask=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if($existingTask -and @($existingTask.Actions | Where-Object { ([string]$_.Arguments) -match ('(?i)-Root\s+"'+[regex]::Escape($InstallRoot)+'"') }).Count -eq 0) { throw ('Task belongs to a different installation: '+$name) }
}
if(Test-Path -LiteralPath $InstallRoot) {
    if((Get-Item -LiteralPath $InstallRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installation root cannot be a reparse point.' }
    if(@(Get-ChildItem -LiteralPath $InstallRoot -Recurse -Force -ErrorAction Stop | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Installation tree contains reparse points; deployment refused.' }
}
foreach($file in $files) {
    $path=Join-Path $sourceRoot $file
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('Package file missing: '+$file) }
    if($file -like '*.ps1') {
        $tokens=$null;$errors=$null
        [void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
        if($errors.Count) { throw ('Syntax failure: '+$file) }
    }
}
if(Test-Path -LiteralPath (Join-Path $sourceRoot 'package.manifest.json')) {
    $verifiedPackage=Test-SentinelPackage $sourceRoot $TrustedSignerThumbprint -AllowUnsigned:$AllowUnsignedPackage
} elseif(-not $AllowUnsignedPackage -or $TrustedSignerThumbprint) { throw 'A verified signed package is required. Use -AllowUnsignedPackage only for a reviewed pilot source package.' }
$verifiedHashes=@{}
foreach($file in $files) {
    $verifiedHashes[$file]=if($verifiedPackage) { @($verifiedPackage.FileEntries | Where-Object Name -eq $file)[0].SHA256 } else { (Get-FileHash -LiteralPath (Join-Path $sourceRoot $file) -Algorithm SHA256 -ErrorAction Stop).Hash }
}
$packageConfig=Get-Content -LiteralPath (Join-Path $sourceRoot 'Config.json') -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
Assert-SentinelConfig $packageConfig
if((Get-FileHash -LiteralPath (Join-Path $sourceRoot 'Config.json') -Algorithm SHA256).Hash -ne $verifiedHashes['Config.json']) { throw 'Package configuration changed after verification.' }
function Set-SentinelAcl {
    param([string]$Path)
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $admin=[Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $system=[Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $acl.SetOwner($admin)
    foreach($identity in @($admin,$system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    foreach($item in @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop)) {
        $child=Get-Acl -LiteralPath $item.FullName
        foreach($rule in @($child.Access | Where-Object { -not $_.IsInherited })) { [void]$child.RemoveAccessRuleSpecific($rule) }
        $child.SetAccessRuleProtection($false,$false)
        $child.SetOwner($admin)
        Set-Acl -LiteralPath $item.FullName -AclObject $child -ErrorAction Stop
    }
}

function New-SentinelTaskAction {
    param([string]$ScriptName)
    $scriptPath = Join-Path $InstallRoot $ScriptName
    $arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Root "{1}"' -f $scriptPath,$InstallRoot
    return New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $arguments
}


if(Test-Path -LiteralPath (Join-Path $InstallRoot 'Config.json')) {
    & (Join-Path $PSScriptRoot 'Upgrade-SentinelLocal.ps1') -InstallRoot $InstallRoot -TrustedSignerThumbprint $TrustedSignerThumbprint -AllowUnsignedPackage:$AllowUnsignedPackage -StartupTimeoutSeconds $StartupTimeoutSeconds
    return
}
if(Test-Path -LiteralPath $InstallRoot) {
    if(@(Get-ChildItem -LiteralPath $InstallRoot -Force).Count) { throw 'Fresh installation requires an empty destination.' }
}
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
foreach($directory in @('logs','state','evidence','backups')) { New-Item -ItemType Directory -Path (Join-Path $InstallRoot $directory) -Force | Out-Null }
$mergedConfig=$packageConfig
try {
    foreach($file in $files) { Copy-Item -LiteralPath (Join-Path $sourceRoot $file) -Destination (Join-Path $InstallRoot $file) -Force -ErrorAction Stop }
    foreach($file in $files) {
        if((Get-FileHash -LiteralPath (Join-Path $InstallRoot $file) -Algorithm SHA256).Hash -ne $verifiedHashes[$file]) { throw ('Copied package hash mismatch: '+$file) }
    }
    Set-SentinelAcl $InstallRoot
    & (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallRoot 'SelfTest-SentinelLocal.ps1') -Root $InstallRoot -PreStart
    if($LASTEXITCODE -ne 0) { throw 'Installed package preflight failed.' }
    if(-not [Diagnostics.EventLog]::SourceExists('SentinelLocal')) { New-EventLog -LogName Application -Source SentinelLocal }
    foreach($name in $taskNames) { if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop } }
    $trigger=New-ScheduledTaskTrigger -AtStartup
    $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650) -StartWhenAvailable
    Register-ScheduledTask -TaskName $watcherTaskName -Action (New-SentinelTaskAction 'Watcher.ps1') -Trigger $trigger -Principal $principal -Settings $settings -Description 'SentinelLocal v1.2.0 process, persistence and Defender monitoring' | Out-Null
    Register-ScheduledTask -TaskName $responseWorkerTaskName -Action (New-SentinelTaskAction 'ResponseWorker.ps1') -Trigger $trigger -Principal $principal -Settings $settings -Description 'SentinelLocal v1.2.0 bounded priority response worker' | Out-Null
    Register-ScheduledTask -TaskName $integrityTaskName -Action (New-SentinelTaskAction 'IntegrityMonitor.ps1') -Trigger $trigger -Principal $principal -Settings $settings -Description 'SentinelLocal v1.2.0 integrity and availability monitoring' | Out-Null
    & (Join-Path $InstallRoot 'Update-SentinelIntegrityBaseline.ps1') -Root $InstallRoot
    $started=[datetimeoffset]::Now
    foreach($name in @($responseWorkerTaskName,$watcherTaskName,$integrityTaskName)) { Start-ScheduledTask -TaskName $name -ErrorAction Stop }
    Wait-SentinelDeploymentReady -Root $InstallRoot -Version $mergedConfig.Version -StartedAfter $started -TimeoutSeconds $StartupTimeoutSeconds
    if(-not (Write-SentinelJsonLine (Join-Path $InstallRoot 'logs\administration.jsonl') ([ordered]@{Type='DeploymentCompleted';Severity='MEDIUM';Version=$mergedConfig.Version;Operator=[Security.Principal.WindowsIdentity]::GetCurrent().Name;SignedPackage=[bool]$TrustedSignerThumbprint}))) { throw 'Deployment audit could not be persisted.' }
} catch {
    $failure=$_.Exception
    Stop-SentinelDeploymentTasks $InstallRoot
    foreach($name in $taskNames) { if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop } }
    Write-Host 'Installation did not pass startup verification. Files were retained for investigation; scheduled tasks were removed.'
    throw $failure
}
Write-Host ('Installed and heartbeat-verified: SentinelLocal '+$mergedConfig.Version)
Write-Host ('Root: '+$InstallRoot)
Write-Host 'Windows/Defender security settings were not changed. Review Test-SentinelReadiness.ps1 and DefenderHardening.ps1 -WhatIf before applying a profile.'
