function Test-SentinelObservedProcess {
    param($Observed,$Current,[int]$ProcessIdValue)
    if(-not $Observed -or -not $Current -or $ProcessIdValue -le 0 -or [int]$Observed.ProcessId -ne $ProcessIdValue -or [int]$Current.ProcessId -ne $ProcessIdValue -or -not $Observed.CreationDate -or -not $Current.CreationDate) {return $false}
    try {return [datetimeoffset]::Parse([string]$Observed.CreationDate).UtcTicks -eq [datetimeoffset]::Parse([string]$Current.CreationDate).UtcTicks -and [string]$Observed.ExecutablePath -ieq [string]$Current.ExecutablePath} catch {return $false}
}
function Get-SentinelTargetStatus {
    param([string]$ObservedSHA256,[string]$CurrentSHA256,[bool]$Exists,$Observed,$Current,[int]$ProcessIdValue)
    $live=Test-SentinelObservedProcess $Observed $Current $ProcessIdValue
    if(-not $Exists) {if($live){return 'LiveTargetMissing'};return 'TargetMissing'}
    if($ObservedSHA256 -notmatch '^[a-fA-F0-9]{64}$' -or $CurrentSHA256 -notmatch '^[a-fA-F0-9]{64}$') {return 'TargetIdentityUnverified'}
    if($ObservedSHA256 -ine $CurrentSHA256) {if($live){return 'LiveTargetChanged'};return 'TargetChanged'}
    return 'Matched'
}
function Assert-SentinelEvidencePath {
    param([string]$Root,[string]$Path)
    $base=[IO.Path]::GetFullPath((Join-Path $Root 'evidence')).TrimEnd('\')+'\';$full=[IO.Path]::GetFullPath($Path)
    if(-not $full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)) {throw 'Snapshot escaped evidence root.'}
    $p=$full
    while($p) {
        if(Test-Path -LiteralPath $p) {if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse evidence path.'}}
        $p=[IO.Path]::GetDirectoryName($p.TrimEnd('\'))
    }
    $acl=Get-Acl -LiteralPath $Root -ErrorAction Stop
    if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-32-544','S-1-5-18')) {throw 'Evidence requires an administrator-owned protected installation.'}
    $p=$full
    while($p.Length -ge ([IO.Path]::GetFullPath($Root)).Length) {
        if(Test-Path -LiteralPath $p) {
            $acl=Get-Acl -LiteralPath $p -ErrorAction Stop
            foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
                if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18')) {throw 'Evidence path allows access outside administrators and SYSTEM.'}
            }
        }
        $p=[IO.Path]::GetDirectoryName($p.TrimEnd('\'))
    }
    return $full
}
function Save-SentinelObservedFile {
    param([string]$Root,[string]$Path,[string]$ObservedSHA256,[string]$RequestId,$Config)
    if(-not $Config.CaptureQueuedFileSnapshot -or $ObservedSHA256 -notmatch '^[a-fA-F0-9]{64}$') {return ''}
    $destination=Join-Path $Root ('evidence\queued\'+$RequestId+'\payload.bin')
    [void](Assert-SentinelEvidencePath $Root $destination);Assert-SentinelStorage -Root $Root -Config $Config -Evidence
    $input=[IO.File]::Open($Path,'Open','Read','Read')
    try {
        if($input.Length -gt ([long]$Config.Resources.MaxSnapshotFileMB*1MB)) {throw 'Snapshot size limit exceeded.'}
        $capacity=Get-SentinelStorageStatus $Root $Config
        if(($capacity.EvidenceBytes+$input.Length) -gt ([long]$Config.Resources.MaxEvidenceMB*1MB) -or ($capacity.FreeBytes-$input.Length) -lt ([long]$Config.Resources.MinFreeDiskMB*1MB)) {throw 'Snapshot would exceed evidence or free-disk capacity.'}
        $sha=[Security.Cryptography.SHA256]::Create()
        try {$hash=([BitConverter]::ToString($sha.ComputeHash($input))).Replace('-','')} finally {$sha.Dispose()}
        if($hash -ine $ObservedSHA256) {throw 'Observed content changed before capture.'}
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
        $output=[IO.File]::Open($destination,'CreateNew','Write','None')
        try {$input.Position=0;$input.CopyTo($output)} finally {$output.Dispose()}
        if((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ine $ObservedSHA256) {throw 'Snapshot hash mismatch.'}
        [IO.File]::SetAttributes($destination,[IO.FileAttributes]::ReadOnly);return $destination
    } finally {$input.Dispose()}
}
function Get-SentinelVerifiedSnapshot {
    param([string]$Root,[string]$Path,[string]$ObservedSHA256)
    if(-not $Path -or $ObservedSHA256 -notmatch '^[a-fA-F0-9]{64}$') {return ''}
    $full=Assert-SentinelEvidencePath $Root $Path
    if((Get-FileHash -LiteralPath $full -Algorithm SHA256 -ErrorAction Stop).Hash -ine $ObservedSHA256) {throw 'Snapshot does not match observed content.'}
    return $full
}
function Invoke-SentinelVolatileObservation {
    param([string]$Root,$Event,[scriptblock]$Handler)
    try {& $Handler $Event}
    catch {try {Write-SentinelError -Root $Root -Component Watcher -Operation FailedObservation -Exception $_.Exception -Context @{EventIdentifier=$Event.EventIdentifier} -Severity HIGH} catch {[Diagnostics.Debug]::WriteLine($_.Exception.Message)}}
    finally {Remove-Event -EventIdentifier $Event.EventIdentifier -ErrorAction SilentlyContinue}
}
function Get-SentinelPersistenceTargets {
    param([string]$Value)
    $text=[Environment]::ExpandEnvironmentVariables($Value);$targets=[Collections.Generic.List[string]]::new()
    # Literal local paths only. Never invoke a shell, expand expressions or fetch URLs.
    $pattern='(?i)"(?<p>[A-Z]:\\[^"\r\n]+\.(?:exe|dll|ps1|psm1|vbs|js|hta|cmd|bat))"|''(?<p>[A-Z]:\\[^''\r\n]+\.(?:exe|dll|ps1|psm1|vbs|js|hta|cmd|bat))''|(?<![A-Za-z0-9_])(?<p>[A-Z]:\\[^\s"'';|]+\.(?:exe|dll|ps1|psm1|vbs|js|hta|cmd|bat))(?=,|\s|$|\|)'
    foreach($m in [regex]::Matches($text,$pattern)) {$targets.Add([IO.Path]::GetFullPath($m.Groups['p'].Value))}
    $first=[regex]::Match($text.Trim(),'(?i)^(?<p>[A-Z]:\\[^"\r\n|]+?\.exe)(?=\s|$)')
    if($first.Success){$targets.Add([IO.Path]::GetFullPath($first.Groups['p'].Value))}
    $token=[regex]::Match($text.Trim(),'(?i)^"?(?<name>(?:powershell|pwsh|cmd|rundll32|regsvr32|wscript|cscript|mshta)(?:\.exe)?)(?:"|\s|$)')
    if($token.Success) {
        $name=$token.Groups['name'].Value;if(-not $name.EndsWith('.exe')){$name+='.exe'}
        if($name -ieq 'powershell.exe') {$exe=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'} elseif($name -ieq 'pwsh.exe') {$exe=Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'} else {$exe=Join-Path $env:WINDIR ('System32\'+$name)}
        $targets.Add($exe)
        foreach($script in @(Get-SentinelScriptTargets -ExecutablePath $exe -CommandLine $text)) {$targets.Add($script)}
    }
    return @($targets | Sort-Object -Unique)
}
function Invoke-SentinelGlobalThreatRemoval {
    param($Config,$Identity,$Threats,[string]$AlertLog)
    if(@($Threats).Count -eq 0 -or -not $Config.AutoContainDefenderDetections) {return}
    $allowed=$Config.AutoGlobalRemoveMpThreat -eq $true
    if(-not (Write-SentinelJsonLine -Path $AlertLog -Data ([ordered]@{Type='DefenderEscalation';Severity='HIGH';DetectionId=$Identity.DetectionId;ThreatId=$Identity.ThreatId;GlobalRemovalEnabled=$allowed;Reason=if($allowed){'Explicit global-removal policy: Remove-MpThreat processes ALL active threats.'}else{'Related threat remains active. Global removal disabled; review in Windows Security.'}}))) {throw 'Cannot persist remediation decision.'}
    if($allowed) {Remove-MpThreat -ErrorAction Stop}
}
