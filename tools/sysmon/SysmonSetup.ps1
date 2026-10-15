# Reviewed deployment helper. Never execute a downloaded file before checking
# its independently supplied digest, Microsoft signature and product identity.
function Assert-SentinelSysmonBinary {
    param([string]$Path,[string]$ExpectedSHA256)
    if($ExpectedSHA256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'An independent SHA256 pin is required.'}
    if((Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash -ine $ExpectedSHA256){throw 'Sysmon binary hash mismatch.'}
    $signature=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){throw 'A valid Microsoft signature is required.'}
    $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    if($version.ProductName -ne 'Sysinternals Sysmon'){throw 'The Microsoft binary is not Sysmon.'}
    return [pscustomobject]@{SHA256=$ExpectedSHA256.ToUpperInvariant();Version=$version.FileVersion;Signer=$signature.SignerCertificate.Subject}
}
function Get-SentinelSysmonConfiguration {
    # All process creations, SHA256; avoid broad image-load, access, file archive,
    # network and DNS collection for this first single-PC observation step.
    return @'
<Sysmon schemaversion="4.82">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude" />
    <ProcessTerminate onmatch="include" />
    <NetworkConnect onmatch="include" />
    <ImageLoad onmatch="include" />
    <ProcessAccess onmatch="include" />
    <FileCreate onmatch="include" />
    <FileDelete onmatch="include" />
    <FileDeleteDetected onmatch="include" />
    <DnsQuery onmatch="include" />
    <WmiEvent onmatch="exclude" />
    <ProcessTampering onmatch="exclude" />
  </EventFiltering>
</Sysmon>
'@
}
function Install-SentinelSysmon {
    param([string]$BinaryPath,[string]$ExpectedSHA256,[switch]$Apply,[switch]$AcceptEula)
    if($env:PROCESSOR_ARCHITECTURE -ne 'AMD64'){throw 'This helper supports AMD64 Windows and Sysmon64.exe.'}
    $source=[IO.Path]::GetFullPath($BinaryPath)
    $ancestor=$source
    while($ancestor){
        if((Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Sysmon source must not traverse reparse points.'}
        $parent=Split-Path -Parent $ancestor;if($parent -eq $ancestor){break};$ancestor=$parent
    }
    # Hold the source across validation and protected copy to prevent substitution.
    $sourceHandle=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $exeHandle=$null;$configHandle=$null
    try {
        $identity=Assert-SentinelSysmonBinary $source $ExpectedSHA256
        $existing=@(Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue)
        if($existing.Count){throw 'Existing Sysmon detected. Review its configuration manually; this helper does not replace it.'}
        if(-not $Apply){return [pscustomobject]@{Preview=$true;Binary=$identity;Configuration=(Get-SentinelSysmonConfiguration);Changes='Install Microsoft Sysmon service/driver; record process command lines and SHA256.'}}
        if(-not $AcceptEula){throw 'Review the Microsoft Sysmon EULA and explicitly pass -AcceptEula to install.'}
        $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run installation from an elevated administrator PowerShell.'}
        $stageBase=Join-Path $env:ProgramData 'SentinelLocalSysmon'
        foreach($candidate in @($env:ProgramData,$stageBase)){
            if((Test-Path -LiteralPath $candidate) -and ((Get-Item -LiteralPath $candidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Sysmon staging must not traverse reparse points.'}
        }
        $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
        [void][IO.Directory]::CreateDirectory($stageBase,$acl)
        $actual=[IO.Directory]::GetAccessControl($stageBase)
        $rules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if(-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544' -or $rules.Count -ne 2){throw 'Untrusted Sysmon staging owner/permissions.'}
        foreach($rule in $rules){if($rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl'){throw 'Untrusted Sysmon staging permissions.'}}
        $stage=Join-Path $stageBase ([guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($stage,$acl)
        $exe=Join-Path $stage 'Sysmon64.exe';$xml=Join-Path $stage 'process-monitor.xml'
        Copy-Item -LiteralPath $source -Destination $exe -ErrorAction Stop
        $exeHandle=[IO.File]::Open($exe,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        [void](Assert-SentinelSysmonBinary $exe $ExpectedSHA256)
        [IO.File]::WriteAllText($xml,(Get-SentinelSysmonConfiguration),[Text.UTF8Encoding]::new($false))
        $configHandle=[IO.File]::Open($xml,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$exe
        $info.Arguments='-accepteula -i "'+$xml+'"';$info.WorkingDirectory=$stage
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $child=[Diagnostics.Process]::new();$child.StartInfo=$info
        $launched=$false
        try {
            [void]$child.Start();$launched=$true;$stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
            if(-not $child.WaitForExit(60000)){$child.Kill();$child.WaitForExit();throw 'Sysmon installation exceeded 60 seconds; inspect the retained stage/service before retrying.'}
            $child.WaitForExit();[IO.File]::WriteAllText((Join-Path $stage 'install-output.txt'),($stdout.Result+$stderr.Result))
            if($child.ExitCode -ne 0){throw ('Sysmon installation failed; exit='+$child.ExitCode+'; stage='+$stage)}
        } finally {if($launched -and -not $child.HasExited){$child.Kill();$child.WaitForExit()};$child.Dispose()}
        $deadline=[datetimeoffset]::Now.AddSeconds(20)
        do {
            $running=@(Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Where-Object Status -eq Running)
            if($running.Count){break};Start-Sleep -Milliseconds 250
        } while([datetimeoffset]::Now -lt $deadline)
        $channel=Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
        if(-not $running.Count -or -not $channel.IsEnabled){throw 'Sysmon did not expose a running service and event channel.'}
        return [pscustomobject]@{Installed=$true;Binary=$identity;StageRoot=$stage;ConfigurationSHA256=(Get-FileHash $xml).Hash;Uninstall='Use the retained Microsoft Sysmon64.exe -u from an administrator shell.'}
    } finally {
        if($configHandle){$configHandle.Dispose()};if($exeHandle){$exeHandle.Dispose()};$sourceHandle.Dispose()
    }
}
