#Requires -RunAsAdministrator
param([string]$InstallRoot='C:\ProgramData\SentinelLocal',[string]$StageReceiptPath,[ValidateRange(5,300)][int]$StartupTimeoutSeconds=90)
$ErrorActionPreference='Stop'
# Internal payload entry: only a protected Bootstrap stage may call this script.
# This guard uses .NET and built-in JSON parsing before any payload import.
if(-not $StageReceiptPath -or [IO.Path]::GetFullPath($StageReceiptPath) -ine (Join-Path $PSScriptRoot '.sentinel-stage.json')) {throw 'Run the independently trusted bootstrap/Bootstrap.ps1; direct installation is refused.'}
$stageAcl=[IO.Directory]::GetAccessControl($PSScriptRoot)
if(-not $stageAcl.AreAccessRulesProtected -or $stageAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')) {throw 'Untrusted staging owner or ACL.'}
$stageRules=@($stageAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
if($stageRules.Count -ne 2) {throw 'Untrusted staging ACL.'}
foreach($rule in $stageRules) {
    if($rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18') -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {throw 'Untrusted staging ACL.'}
}
$stageReceipt=[IO.File]::ReadAllText($StageReceiptPath) | ConvertFrom-Json -ErrorAction Stop
$stageManifestPath=Join-Path $PSScriptRoot 'package.manifest.json'
$stageManifest=[IO.File]::ReadAllText($stageManifestPath) | ConvertFrom-Json -ErrorAction Stop
$sha=[Security.Cryptography.SHA256]::Create()
try {
    $manifestHash=([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($stageManifestPath)))).Replace('-','')
    if($stageReceipt.Schema -ne 1 -or $stageReceipt.Product -ne 'SentinelLocal' -or $manifestHash -ine $stageReceipt.ManifestSHA256 -or $stageManifest.Version -ne $stageReceipt.Version) {throw 'Staging receipt mismatch.'}
    $seen=@{}
    foreach($entry in @($stageManifest.Files)) {
        $name=[string]$entry.Name
        if($name -notmatch '^(?:[A-Za-z0-9_.-]+|docs/[A-Za-z0-9_.-]+)$' -or $name.Contains('..') -or $seen.ContainsKey($name)) {throw 'Unsafe staging file name.'}
        $seen[$name]=$true;$path=Join-Path $PSScriptRoot $name
        $p=$path
        while($p) {
            if([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) {throw 'Reparse staging path.'}
            $p=[IO.Path]::GetDirectoryName($p.TrimEnd('\'))
        }
        $hash=([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($path)))).Replace('-','')
        if($hash -ine $entry.SHA256 -or ([IO.FileInfo]$path).Length -ne [long]$entry.Length) {throw ('Staging file changed: '+$name)}
    }
} finally {$sha.Dispose()}
# END BOOTSTRAP GUARD
$commonPath=Join-Path $PSScriptRoot 'Common.ps1'
if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) { $commonPath=Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Common.ps1' }
. $commonPath
$sourceRoot=Get-SentinelSourceRoot $PSScriptRoot
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
    $path=Get-SentinelSourcePath $sourceRoot $file
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('Package file missing: '+$file) }
    if($file -like '*.ps1') {
        $tokens=$null;$errors=$null
        [void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
        if($errors.Count) { throw ('Syntax failure: '+$file) }
    }
}
$verifiedPackage=$stageReceipt
$verifiedHashes=@{}
foreach($file in $files) {
    $entries=@($stageManifest.Files | Where-Object Name -eq $file)
    if($entries.Count -ne 1) {throw ('Staged package omitted: '+$file)}
    $verifiedHashes[$file]=$entries[0].SHA256
}
$packageConfig=Get-Content -LiteralPath (Get-SentinelSourcePath $sourceRoot 'Config.json') -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
Assert-SentinelConfig $packageConfig
if((Get-FileHash -LiteralPath (Get-SentinelSourcePath $sourceRoot 'Config.json') -Algorithm SHA256).Hash -ne $verifiedHashes['Config.json']) { throw 'Package configuration changed after verification.' }
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


$existingConfig=Get-Content -LiteralPath (Join-Path $InstallRoot 'Config.json') -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
$mergedConfig=Merge-ConfigObject $packageConfig $existingConfig
$mergedConfig.Version=$packageConfig.Version
Assert-SentinelConfig $mergedConfig
$oldTasks=@{}
foreach($name in $taskNames) {
    $task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if($task) { $oldTasks[$name]=[pscustomobject]@{Xml=(Export-ScheduledTask -TaskName $name -ErrorAction Stop);WasRunning=([string]$task.State -eq 'Running')} }
}
$backupRoot=Join-Path $InstallRoot ('backups\upgrade-'+(Get-Date -Format 'yyyyMMddHHmmssfff')+'-'+[guid]::NewGuid().ToString('N'))
$backupReady=$false;$changed=$false;$stopped=$false
try {
    $stopped=$true
    Stop-SentinelDeploymentTasks $InstallRoot
    New-SentinelDeploymentBackup -Root $InstallRoot -BackupRoot $backupRoot -Tasks $oldTasks
    $backupReady=$true;$changed=$true
    foreach($file in $files | Where-Object { $_ -ne 'Config.json' }) { Copy-Item -LiteralPath (Get-SentinelSourcePath $sourceRoot $file) -Destination (Join-Path $InstallRoot $file) -Force -ErrorAction Stop }
    Write-SentinelAtomicJson (Join-Path $InstallRoot 'Config.json') $mergedConfig
    foreach($file in $files | Where-Object { $_ -ne 'Config.json' }) {
        if((Get-FileHash -LiteralPath (Join-Path $InstallRoot $file) -Algorithm SHA256).Hash -ne $verifiedHashes[$file]) { throw ('Copied package hash mismatch: '+$file) }
    }
    Set-SentinelAcl $InstallRoot
    & (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallRoot 'SelfTest-SentinelLocal.ps1') -Root $InstallRoot -PreStart
    if($LASTEXITCODE -ne 0) { throw 'Installed package preflight failed.' }
    if(-not [Diagnostics.EventLog]::SourceExists('SentinelLocal')) { New-EventLog -LogName Application -Source SentinelLocal }
    foreach($name in $taskNames) { if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop } }
    $trigger=New-ScheduledTaskTrigger -AtStartup
    $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    $settings=New-SentinelMonitoringTaskSettings
    Register-ScheduledTask -TaskName $watcherTaskName -Action (New-SentinelTaskAction 'Watcher.ps1') -Trigger $trigger -Principal $principal -Settings $settings -Description 'SentinelLocal v1.2.1 process, persistence and Defender monitoring' | Out-Null
    Register-ScheduledTask -TaskName $responseWorkerTaskName -Action (New-SentinelTaskAction 'ResponseWorker.ps1') -Trigger $trigger -Principal $principal -Settings $settings -Description 'SentinelLocal v1.2.1 bounded priority response worker' | Out-Null
    Register-ScheduledTask -TaskName $integrityTaskName -Action (New-SentinelTaskAction 'IntegrityMonitor.ps1') -Trigger $trigger -Principal $principal -Settings $settings -Description 'SentinelLocal v1.2.1 integrity and availability monitoring' | Out-Null
    & (Join-Path $InstallRoot 'Update-SentinelIntegrityBaseline.ps1') -Root $InstallRoot
    $started=[datetimeoffset]::Now
    foreach($name in @($responseWorkerTaskName,$watcherTaskName,$integrityTaskName)) { Start-ScheduledTask -TaskName $name -ErrorAction Stop }
    Wait-SentinelDeploymentReady -Root $InstallRoot -Version $mergedConfig.Version -StartedAfter $started -TimeoutSeconds $StartupTimeoutSeconds
    if(-not (Write-SentinelJsonLine (Join-Path $InstallRoot 'logs\administration.jsonl') ([ordered]@{Type='DeploymentCompleted';Severity='MEDIUM';Version=$mergedConfig.Version;Operator=[Security.Principal.WindowsIdentity]::GetCurrent().Name;SignedPackage=[bool]$stageReceipt.Signed}))) { throw 'Deployment audit could not be persisted.' }
} catch {
    $failure=$_.Exception
    if($changed -and $backupReady) {
        Stop-SentinelDeploymentTasks $InstallRoot
        foreach($name in $taskNames) { if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop } }
        [void](Restore-SentinelDeploymentBackup -Root $InstallRoot -BackupRoot $backupRoot)
        foreach($name in $oldTasks.Keys) {
            Register-ScheduledTask -TaskName $name -Xml $oldTasks[$name].Xml -Force -ErrorAction Stop | Out-Null
            if($oldTasks[$name].WasRunning) { Start-ScheduledTask -TaskName $name -ErrorAction Stop }
        }
        Write-Host ('Rollback restored previous files, integrity baseline and task definitions. Backup: '+$backupRoot)
    } elseif($stopped) {
        foreach($name in $oldTasks.Keys) { if($oldTasks[$name].WasRunning) { Start-ScheduledTask -TaskName $name -ErrorAction Stop } }
    }
    throw $failure
}
Write-Host ('Upgrade verified: SentinelLocal '+$mergedConfig.Version)
Write-Host ('Backup: '+$backupRoot)
