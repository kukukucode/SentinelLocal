# Trusted entry point: obtain and review/sign this file independently of the payload.
# Never imports or runs code from PackageRoot before verification and protected staging.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [ValidateSet('Verify','Stage','Install','Upgrade')][string]$Mode='Verify',
    [string]$TrustedSignerThumbprint,
    [switch]$DevelopmentUnsigned,
    [string]$ExpectedManifestSHA256,
    [string]$StagingRoot=(Join-Path $env:ProgramData 'SentinelLocalStaging'),
    [string]$InstallRoot=(Join-Path $env:ProgramData 'SentinelLocal'),
    [ValidateRange(5,300)][int]$StartupTimeoutSeconds=90
)
$ErrorActionPreference='Stop'
$required=@('Common.ps1','LogIntegrity.ps1','OperationalSafety.ps1','Deployment.ps1','PackageTrust.ps1','DetectionSafety.ps1','TaskIntegrity.ps1','PolicyManagement.ps1','Test-SentinelReadiness.ps1','Export-SentinelReport.ps1','Set-SentinelPolicy.ps1','New-SentinelPackage.ps1','Verify-SentinelPackage.ps1','EventMonitoring.ps1','ResponseExecution.ps1','SysmonMonitoring.ps1','Status.ps1','Config.json','DefenderHealth.ps1','DefenderHardening.ps1','Restore-DefenderBackup.ps1','Response.ps1','Invoke-SentinelResponse.ps1','ResponseWorker.ps1','Watcher.ps1','Check-SentinelLocal.ps1','Show-SentinelStatus.ps1','Export-SentinelAudit.ps1','Test-SentinelRemoteHealth.ps1','Add-SentinelException.ps1','SelfTest-SentinelLocal.ps1','Clear-SentinelFirewallRules.ps1','IntegrityMonitor.ps1','Update-SentinelIntegrityBaseline.ps1','Verify-SentinelLogs.ps1','Install-SentinelLocal.ps1','Upgrade-SentinelLocal.ps1','Uninstall-SentinelLocal.ps1')
$optional=@('README.md','README_JP.txt','CHANGELOG.txt','docs/OPERATIONS_JP.md','docs/PILOT_JP.md','docs/REPOSITORY_JP.md','docs/SECURITY_JP.md')
$handles=[Collections.Generic.List[IDisposable]]::new()
function Assert-NoReparse([string]$Path) {
    $p=[IO.Path]::GetFullPath($Path)
    while($p) {
        if([IO.File]::Exists($p) -or [IO.Directory]::Exists($p)) {
            if([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) { throw ('Reparse path refused: '+$p) }
        }
        $parent=[IO.Path]::GetDirectoryName($p.TrimEnd('\'))
        if($parent -eq $p) { break };$p=$parent
    }
}
function Open-Locked([string]$Path) {
    Assert-NoReparse $Path
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $handles.Add($stream);return $stream
}
function Stream-Hash($Stream) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $Stream.Position=0;$value=([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-','');$Stream.Position=0;return $value } finally {$sha.Dispose()}
}
function Read-Bytes($Stream,[long]$Limit) {
    if($Stream.Length -gt $Limit) { throw 'Metadata size limit exceeded.' }
    $bytes=New-Object byte[] ([int]$Stream.Length);$Stream.Position=0;$offset=0
    while($offset -lt $bytes.Length) { $n=$Stream.Read($bytes,$offset,$bytes.Length-$offset);if($n -eq 0){throw 'Unexpected end of file.'};$offset+=$n }
    $Stream.Position=0;return ,$bytes
}
function Protected-Acl {
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
    $admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');$acl.SetOwner($admin)
    foreach($sid in @('S-1-5-32-544','S-1-5-18')) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    return $acl
}
function Assert-Protected([string]$Path) {
    Assert-NoReparse $Path
    $acl=[IO.Directory]::GetAccessControl($Path)
    if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')) { throw ('Unprotected directory: '+$Path) }
    $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if($rules.Count -ne 2) {throw ('Unexpected directory ACL: '+$Path)}
    foreach($rule in $rules) {
        if($rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18') -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit') { throw ('Unsafe directory ACL: '+$Path) }
    }
}
function Assert-ProtectedTree([string]$Root) {
    $pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($Root)
    while($pending.Count) {
        $path=$pending.Dequeue();Assert-NoReparse $path
        $directory=[IO.Directory]::Exists($path)
        $acl=if($directory){[IO.Directory]::GetAccessControl($path)}else{[IO.File]::GetAccessControl($path)}
        if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')) {throw ('Untrusted installed owner: '+$path)}
        foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18')) {throw ('Unsafe installed ACL: '+$path)}
        }
        if($directory){foreach($child in [IO.Directory]::EnumerateFileSystemEntries($path)){$pending.Enqueue($child)}}
    }
}
function Assert-SafeParent([string]$Path) {
    Assert-NoReparse $Path
    $parent=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path).TrimEnd('\'))
    if(-not [IO.Directory]::Exists($parent)) { throw 'Destination parent must already exist.' }
    $acl=[IO.Directory]::GetAccessControl($parent)
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')) {throw 'Destination parent has an untrusted owner.'}
    $danger=[Security.AccessControl.FileSystemRights]'DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18','S-1-3-0') -and ($rule.FileSystemRights -band $danger)) { throw 'Destination parent permits replacement by a non-administrator.' }
    }
}
try {
    $PackageRoot=[IO.Path]::GetFullPath($PackageRoot).TrimEnd('\')
    Assert-NoReparse $PackageRoot
    $manifestStream=Open-Locked (Join-Path $PackageRoot 'package.manifest.json')
    $manifestHash=Stream-Hash $manifestStream
    $bytes=Read-Bytes $manifestStream 2MB
    $manifest=[Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
    if($manifest.Schema -ne 1 -or $manifest.Product -ne 'SentinelLocal' -or $manifest.Version -notmatch '^\d+\.\d+\.\d+$' -or @($manifest.Files).Count -gt 100) {throw 'Invalid package manifest.'}
    $signed=[IO.File]::Exists((Join-Path $PackageRoot 'package.manifest.json.p7s'))
    if($signed) {
        if($DevelopmentUnsigned -or $TrustedSignerThumbprint -notmatch '^[a-fA-F0-9]{40}$') {throw 'Signed packages require an independently supplied signer pin.'}
        Add-Type -AssemblyName System.Security
        $sig=Open-Locked (Join-Path $PackageRoot 'package.manifest.json.p7s')
        $cms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($bytes),$true)
        $cms.Decode((Read-Bytes $sig 1MB));$cms.CheckSignature($true)
        if($cms.SignerInfos.Count -ne 1) {throw 'Exactly one signer required.'}
        $info=$cms.SignerInfos[0];$cert=$info.Certificate
        if($cert.Thumbprint -ine $TrustedSignerThumbprint -or $info.DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1') {throw 'Signer pin or digest mismatch.'}
        $eku=@($cert.Extensions | Where-Object {$_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]} | ForEach-Object {$_.EnhancedKeyUsages} | Where-Object {$_.Value -eq '1.3.6.1.5.5.7.3.3'})
        if(-not $eku.Count -or [datetime]::Now -lt $cert.NotBefore -or [datetime]::Now -gt $cert.NotAfter) {throw 'Invalid code-signing certificate.'}
    } elseif(-not $DevelopmentUnsigned -or $TrustedSignerThumbprint -or $ExpectedManifestSHA256 -notmatch '^[a-fA-F0-9]{64}$' -or $manifestHash -ine $ExpectedManifestSHA256) {
        throw 'Unsigned package refused. Development requires a reviewed manifest hash obtained independently.'
    }
    $seen=@{};$streams=@{}
    foreach($entry in @($manifest.Files)) {
        $name=[string]$entry.Name
        if($name -notin ($required+$optional) -or $seen.ContainsKey($name) -or [string]$entry.SHA256 -notmatch '^[a-fA-F0-9]{64}$' -or $entry.Length -isnot [ValueType] -or [long]$entry.Length -lt 0 -or [long]$entry.Length -gt 64MB) {throw 'Unexpected or duplicate manifest file.'}
        $seen[$name]=$true
        $stream=Open-Locked (Join-Path $PackageRoot $name)
        if($stream.Length -ne [long]$entry.Length -or (Stream-Hash $stream) -ine $entry.SHA256) {throw ('File hash mismatch: '+$name)}
        $streams[$name]=$stream
    }
    foreach($name in $required) {if(-not $seen.ContainsKey($name)){throw ('Required file omitted: '+$name)}}
    $cfg=[Text.Encoding]::UTF8.GetString((Read-Bytes $streams['Config.json'] 1MB)).TrimStart([char]0xFEFF) | ConvertFrom-Json
    if($cfg.Version -ne $manifest.Version) {throw 'Config version differs from manifest.'}
    if($Mode -eq 'Verify') {return [pscustomobject]@{Valid=$true;Version=$manifest.Version;Signed=$signed;ManifestSHA256=$manifestHash;Files=$seen.Count}}
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Protected staging requires an elevated administrator.'}
    $StagingRoot=[IO.Path]::GetFullPath($StagingRoot).TrimEnd('\')
    Assert-SafeParent $StagingRoot
    if(-not [IO.Directory]::Exists($StagingRoot)) {[void][IO.Directory]::CreateDirectory($StagingRoot,(Protected-Acl))}
    Assert-Protected $StagingRoot
    $stage=Join-Path $StagingRoot ([guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($stage,(Protected-Acl));Assert-Protected $stage
    foreach($entry in $manifest.Files) {
        $destination=Join-Path $stage $entry.Name
        $directory=[IO.Path]::GetDirectoryName($destination)
        if(-not [IO.Directory]::Exists($directory)) {[void][IO.Directory]::CreateDirectory($directory)}
        $output=[IO.File]::Open($destination,'CreateNew','Write','None')
        try {$streams[$entry.Name].Position=0;$streams[$entry.Name].CopyTo($output)} finally {$output.Dispose()}
        $locked=Open-Locked $destination
        if((Stream-Hash $locked) -ine $entry.SHA256) {throw 'Staged copy hash mismatch.'}
    }
    [IO.File]::WriteAllBytes((Join-Path $stage 'package.manifest.json'),$bytes)
    [void](Open-Locked (Join-Path $stage 'package.manifest.json'))
    $receiptPath=Join-Path $stage '.sentinel-stage.json'
    $receipt=[ordered]@{Schema=1;Product='SentinelLocal';Version=$manifest.Version;ManifestSHA256=$manifestHash;Signed=$signed;SignerThumbprint=$TrustedSignerThumbprint;FileEntries=@($manifest.Files)}
    [IO.File]::WriteAllText($receiptPath,($receipt | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($true));[void](Open-Locked $receiptPath)
    if($Mode -eq 'Stage') {return [pscustomobject]@{StageRoot=$stage;StageReceiptPath=$receiptPath;ManifestSHA256=$manifestHash}}
    $InstallRoot=[IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
    Assert-SafeParent $InstallRoot
    if([IO.Directory]::Exists($InstallRoot)) {Assert-Protected $InstallRoot;Assert-ProtectedTree $InstallRoot}
    else {[void][IO.Directory]::CreateDirectory($InstallRoot,(Protected-Acl))}
    $target=if($Mode -eq 'Upgrade') {'Upgrade-SentinelLocal.ps1'} else {'Install-SentinelLocal.ps1'}
    foreach($value in @($InstallRoot,$receiptPath,$stage)) {if($value.Contains('"')){throw 'Double quotes are not allowed in deployment paths.'}}
    $psi=[Diagnostics.ProcessStartInfo]::new()
    $psi.FileName=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $psi.Arguments='-NoProfile -ExecutionPolicy Bypass -File "{0}" -InstallRoot "{1}" -StageReceiptPath "{2}" -StartupTimeoutSeconds {3}' -f (Join-Path $stage $target),$InstallRoot,$receiptPath,$StartupTimeoutSeconds
    $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    $child=[Diagnostics.Process]::new();$child.StartInfo=$psi
    try {
        [void]$child.Start();$stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
        if(-not $child.WaitForExit(900000)) {$child.Kill();throw 'Deployment timeout; inspect the retained stage and installation.'}
        $child.WaitForExit();Write-Host $stdout.Result
        if($child.ExitCode -ne 0) {throw ('Deployment failed: '+$stderr.Result)}
    } finally {$child.Dispose()}
    [pscustomobject]@{Installed=$true;Version=$manifest.Version;StageRoot=$stage}
} finally {foreach($handle in $handles){$handle.Dispose()}}
