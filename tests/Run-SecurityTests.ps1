param(
    [string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-security-'+[guid]::NewGuid().ToString('N'))),
    [switch]$RequireSecureStagingTests,[string]$Filter='.*'
)
$ErrorActionPreference='Stop'
$packageRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $packageRoot 'src\Common.ps1')
. (Join-Path $packageRoot 'src\SysmonMonitoring.ps1')
$bootstrap=Join-Path $packageRoot 'bootstrap\Bootstrap.ps1'
if(Test-Path -LiteralPath $ScratchRoot) {throw 'Scratch directory already exists.'}
[void][IO.Directory]::CreateDirectory($ScratchRoot)
$results=[Collections.Generic.List[object]]::new()
function Assert([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Test([string]$Name,[scriptblock]$Body) {
    if($Name -notmatch $Filter){return}
    try {& $Body;$results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'});Write-Host ('PASS '+$Name)}
    catch {$results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message});Write-Host ('FAIL '+$Name+': '+$_.Exception.Message)}
}
function Refused([scriptblock]$Body,[string]$Message) {
    $failed=$false;try {& $Body | Out-Null} catch {$failed=$true}
    Assert $failed $Message
}
function Fixture([string]$Name) {
    $root=Join-Path $ScratchRoot $Name;[void][IO.Directory]::CreateDirectory($root)
    foreach($file in Get-SentinelPackageFiles){Copy-Item -LiteralPath (Get-SentinelSourcePath $packageRoot $file) -Destination (Join-Path $root $file)}
    return $root
}
function Baseline([string]$Root) {
    $entries=@(foreach($name in Get-SentinelCriticalFileNames){[ordered]@{Name=$name;Path=(Join-Path $Root $name);SHA256=(Get-FileHash -LiteralPath (Join-Path $Root $name)).Hash}})
    Write-SentinelAtomicJson (Join-Path $Root 'state\integrity-baseline.json') ([ordered]@{Files=$entries})
}
function Package([string]$Name) {
    $root=Join-Path $ScratchRoot $Name
    & (Get-SentinelSourcePath $packageRoot 'New-SentinelPackage.ps1') -OutputDirectory $root | Out-Null
    return $root
}
function VerifyDevelopment([string]$Root) {
    & $bootstrap -PackageRoot $Root -DevelopmentUnsigned -ExpectedManifestSHA256 (Get-FileHash -LiteralPath (Join-Path $Root 'package.manifest.json')).Hash
}
function Certificate {
    $rsa=[Security.Cryptography.RSA]::Create(2048)
    $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=SentinelLocal ephemeral TEST ONLY',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $oids=[Security.Cryptography.OidCollection]::new();[void]$oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false))
    return $request.CreateSelfSigned([datetimeoffset]::Now.AddMinutes(-5),[datetimeoffset]::Now.AddDays(1))
}
function Sign([string]$Root,$Cert) {
    Add-Type -AssemblyName System.Security
    $path=Join-Path $Root 'package.manifest.json'
    $cms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($path)),$true)
    $signer=[Security.Cryptography.Pkcs.CmsSigner]::new($Cert);$signer.DigestAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    $cms.ComputeSignature($signer);[IO.File]::WriteAllBytes($path+'.p7s',$cms.Encode())
}
function Write-EventLog {} # No real Event Log/Defender/task mutation in this suite.
Test 'Trusted bootstrap verifies bytes without importing payload code' {
    $root=Package 'bootstrap-valid';$r=VerifyDevelopment $root
    Assert ($r.Valid -and $r.Files -eq @(Get-SentinelPackageFiles).Count+7) 'Valid package failed'
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($bootstrap,[ref]$tokens,[ref]$errors)
    Assert ($errors.Count -eq 0) 'Bootstrap syntax failure'
    $imports=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq 'Dot'},$true))
    Assert ($imports.Count -eq 0) 'Bootstrap imports executable scripts'
}
Test 'Tampered verification dependency never executes' {
    $root=Package 'bootstrap-tampered';$marker=Join-Path $root 'executed.txt'
    Set-Content -LiteralPath (Join-Path $root 'Common.ps1') -Value ("[IO.File]::WriteAllText('"+$marker+"','bad')")
    Refused {VerifyDevelopment $root} 'Tampered payload accepted'
    Assert (-not (Test-Path -LiteralPath $marker)) 'Payload code executed before verification'
}
Test 'Unsigned verification requires independent manifest hash' {
    $root=Package 'bootstrap-unsigned'
    Refused {& $bootstrap -PackageRoot $root} 'Unsigned default accepted'
    Refused {& $bootstrap -PackageRoot $root -DevelopmentUnsigned} 'Unpinned development accepted'
    Refused {& $bootstrap -PackageRoot $root -DevelopmentUnsigned -ExpectedManifestSHA256 ('0'*64)} 'Wrong manifest pin accepted'
}
Test 'CMS signer pin and signed manifest tampering fail closed' {
    $root=Package 'bootstrap-signed';$cert=Certificate
    try {
        Sign $root $cert
        Assert (& $bootstrap -PackageRoot $root -TrustedSignerThumbprint $cert.Thumbprint).Valid 'Pinned CMS rejected'
        Refused {& $bootstrap -PackageRoot $root -TrustedSignerThumbprint ('0'*40)} 'Wrong signer accepted'
        Add-Content -LiteralPath (Join-Path $root 'package.manifest.json') -Value ' '
        Refused {& $bootstrap -PackageRoot $root -TrustedSignerThumbprint $cert.Thumbprint} 'Modified signed manifest accepted'
    } finally {$cert.Dispose()}
}
Test 'Manifest rejects traversal duplicate and omitted critical file' {
    foreach($variant in @('traversal','duplicate','missing')) {
        $root=Package ('manifest-'+$variant);$path=Join-Path $root 'package.manifest.json';$m=Get-Content $path -Raw | ConvertFrom-Json
        switch($variant){traversal {$m.Files[0].Name='../Common.ps1'} duplicate {$m.Files+=@($m.Files[0])} missing {$m.Files=@($m.Files | Select-Object -Skip 1)}}
        Write-SentinelAtomicJson $path $m
        Refused {VerifyDevelopment $root} ('Invalid manifest accepted: '+$variant)
    }
}
Test 'Package verification refuses reparse paths' {
    $root=Package 'bootstrap-reparse';$link=Join-Path $ScratchRoot 'package-junction'
    New-Item -ItemType Junction -Path $link -Target $root | Out-Null
    Refused {VerifyDevelopment $link} 'Reparse root accepted'
}
Test 'Internal installer refuses direct invocation before Common import' {
    $root=Fixture 'direct-installer';$marker=Join-Path $root 'executed.txt'
    Set-Content -LiteralPath (Join-Path $root 'Common.ps1') ("[IO.File]::WriteAllText('"+$marker+"','bad')")
    foreach($name in @('Install','Upgrade')) {
        $source=[IO.File]::ReadAllText((Join-Path $root ($name+'-SentinelLocal.ps1'))).Replace('#Requires -RunAsAdministrator','')
        $file=Join-Path $root ($name+'-fixture.ps1');[IO.File]::WriteAllText($file,$source,[Text.UTF8Encoding]::new($true))
        Refused {& $file} 'Direct installer was allowed'
    }
    Assert (-not (Test-Path -LiteralPath $marker)) 'Common executed before stage guard'
}
$root=Fixture 'identity'
$observed=[pscustomobject]@{ProcessId=123;ExecutablePath='C:\Temp\evil.exe';CreationDate='2026-09-29T01:00:00.0000000Z'}
$current=$observed.PSObject.Copy();$hash='A'*64
Test 'Live self deletion and replacement remain unresolved' {
    Assert ((Get-SentinelTargetStatus $hash '' $false $observed $current 123) -eq 'LiveTargetMissing') 'Live missing target resolved'
    Assert ((Get-SentinelTargetStatus $hash ('B'*64) $true $observed $current 123) -eq 'LiveTargetChanged') 'Live changed target resolved'
    Assert ((Get-SentinelTargetStatus $hash $hash $true $observed $current 123) -eq 'Matched') 'Matching file rejected'
}
Test 'PID reuse and absent observed hash cannot match original identity' {
    $reused=$current.PSObject.Copy();$reused.CreationDate='2026-09-29T01:01:00Z'
    Assert (-not (Test-SentinelObservedProcess $observed $reused 123)) 'PID reuse accepted'
    Assert ((Get-SentinelTargetStatus '' $hash $true $observed $current 123) -eq 'TargetIdentityUnverified') 'Unobserved bytes authorized'
}
Test 'Missing changed and unverified response results never acknowledge requests' {
    $request=Join-Path $root 'request.json';Set-Content $request '{}'
    foreach($status in @('TargetMissing','LiveTargetMissing','LiveTargetChanged','TargetChanged','TargetIdentityUnverified')) {
        Set-Content -LiteralPath (Join-Path $root 'Response.ps1') ("param("+ '$Root,$RequestFile'+");[pscustomobject]@{Status='"+$status+"'}") -Encoding UTF8
        Refused {Invoke-SentinelBoundedResponse $root $request 20 1} ('Unresolved response was accepted: '+$status)
        Assert (Test-Path -LiteralPath $request) 'Original request deleted on unsuccessful response'
    }
}
Test 'Response uses queued hash and records HIGH for live self deletion' {
    $root=Fixture 'response-missing';$request=Join-Path $root 'request.json'
    Write-SentinelAtomicJson $request ([ordered]@{RequestId='test';FilePath=(Join-Path $root 'gone.exe');ProcessIdValue=123;Score=45;ObservedSHA256=$hash;ObservedProcess=$observed;Reasons=@('test')})
    $process=$observed.PSObject.Copy();$process.ExecutablePath=Join-Path $root 'gone.exe';$observed2=$process.PSObject.Copy()
    $q=Get-Content $request -Raw | ConvertFrom-Json;$q.ObservedProcess=$observed2;Write-SentinelAtomicJson $request $q
    function Get-CimInstance {param($ClassName,$Filter) [pscustomobject]@{ProcessId=123;ExecutablePath=$process.ExecutablePath;CreationDate=[datetime]$process.CreationDate;ParentProcessId=0}}
    function Get-NetTCPConnection {param($OwningProcess) @()}
    function Start-MpScan {throw 'A missing target must never invoke real Defender.'}
    $r=& (Join-Path $root 'Response.ps1') -RequestFile $request -Root $root
    Assert ($r.Status -eq 'LiveTargetMissing' -and $r.Unresolved -and $r.Severity -eq 'HIGH') 'Response did not preserve live unresolved identity'
}
Test 'Volatile events acknowledge overflow even when logging also fails' {
    $removed=[Collections.Generic.List[int]]::new();$calls=[Collections.Generic.List[int]]::new()
    function Remove-Event {param($EventIdentifier) $removed.Add($EventIdentifier)}
    function Write-SentinelError {throw 'log unavailable'}
    foreach($n in @(1,2)){Invoke-SentinelVolatileObservation -Root $root -Event ([pscustomobject]@{EventIdentifier=$n}) -Handler {param($e) $calls.Add($e.EventIdentifier);if($e.EventIdentifier -eq 1){throw 'queue full'}}}
    Assert ($removed.Count -eq 2 -and $calls[1] -eq 2) 'Overflow blocked a later process observation'
}
Test 'Strict baseline rejects missing extra duplicate path and invalid hash rows' {
    $root=Fixture 'baseline';Baseline $root;[void](Read-SentinelBaseline $root)
    foreach($variant in @('missing','extra','duplicate','path','hash')) {
        Baseline $root;$path=Join-Path $root 'state\integrity-baseline.json';$b=Get-Content $path -Raw | ConvertFrom-Json
        switch($variant){missing {$b.Files=@($b.Files | Select-Object -Skip 1)} extra {$b.Files+=@([pscustomobject]@{Name='Extra.ps1'})} duplicate {$b.Files[1]=$b.Files[0]} path {$b.Files[0].Path='C:\Wrong\Common.ps1'} hash {$b.Files[0].SHA256='wrong'}}
        Write-SentinelAtomicJson $path $b;Refused {Read-SentinelBaseline $root} ('Bad baseline accepted: '+$variant)
    }
}
Test 'Baseline regeneration fails before replacing old baseline on missing file' {
    $root=Fixture 'baseline-regenerate';Baseline $root;$path=Join-Path $root 'state\integrity-baseline.json';$before=(Get-FileHash $path).Hash
    Remove-Item -LiteralPath (Join-Path $root 'Status.ps1') -Force
    $text=[IO.File]::ReadAllText((Join-Path $root 'Update-SentinelIntegrityBaseline.ps1')).Replace('#Requires -RunAsAdministrator','')
    $file=Join-Path $root 'baseline-fixture.ps1';[IO.File]::WriteAllText($file,$text,[Text.UTF8Encoding]::new($true))
    Refused {& $file -Root $root} 'Incomplete baseline regenerated'
    Assert ((Get-FileHash $path).Hash -eq $before) 'Previous baseline overwritten'
}
function Task {
    [pscustomobject]@{Actions=@([pscustomobject]@{Execute=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe');Arguments=('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+(Join-Path $root 'Watcher.ps1')+'" -Root "'+$root+'"');WorkingDirectory=''});Principal=[pscustomobject]@{UserId='SYSTEM';RunLevel='Highest';LogonType='ServiceAccount'};Triggers=@([pscustomobject]@{Enabled=$true;CimClass=[pscustomobject]@{CimClassName='MSFT_TaskBootTrigger'};Repetition=[pscustomobject]@{Interval='';Duration=''}})}
}
Test 'Task validates exact executable arguments principal and one boot trigger' {
    Assert (Test-SentinelTaskDefinition (Task) $root 'SentinelLocal Watcher') 'Expected task rejected'
    foreach($variant in @('extraAction','exe','args','user','level','logon','extraTrigger','trigger','disabledTrigger','repetition')) {
        $t=Task
        switch($variant){extraAction {$t.Actions+=@($t.Actions[0])} exe {$t.Actions[0].Execute='C:\Whatever\powershell.exe'} args {$t.Actions[0].Arguments+=' -Command bad'} user {$t.Principal.UserId='user'} level {$t.Principal.RunLevel='Limited'} logon {$t.Principal.LogonType='Interactive'} extraTrigger {$t.Triggers+=@($t.Triggers[0])} trigger {$t.Triggers[0].CimClass.CimClassName='MSFT_TaskTimeTrigger'} disabledTrigger {$t.Triggers[0].Enabled=$false} repetition {$t.Triggers[0].Repetition.Interval='PT1M'}}
        Assert (-not (Test-SentinelTaskDefinition $t $root 'SentinelLocal Watcher')) ('Tampered task accepted: '+$variant)
    }
}
Test 'Persistence parsing expands environment and captures script DLL and shell targets inertly' {
    foreach($case in @(
        @('powershell.exe -File "C:\Users\Test User\a.ps1"','C:\Users\Test User\a.ps1'),
        @('%TEMP%\evil.exe',[IO.Path]::GetFullPath((Join-Path $env:TEMP 'evil.exe'))),
        @('cmd /c C:\x\a.cmd','C:\x\a.cmd'),
        @('rundll32.exe "C:\Temp\evil.dll",Entry','C:\Temp\evil.dll'),
        @('wscript.exe C:\Temp\evil.vbs','C:\Temp\evil.vbs'),
        @('mshta.exe C:\Temp\evil.hta','C:\Temp\evil.hta'),
        @('C:\Program Files\Tool\app.exe --arg','C:\Program Files\Tool\app.exe'))) {
        Assert ($case[1] -in @(Get-SentinelPersistenceTargets $case[0])) ('Static target missing: '+$case[0]+'; expected='+$case[1]+'; actual='+(@(Get-SentinelPersistenceTargets $case[0]) -join ','))
    }
    Assert (@(Get-SentinelPersistenceTargets 'https://example.invalid/a.ps1').Count -eq 0) 'Remote target interpreted as local'
    Assert (@(Get-SentinelPersistenceTargets '$(Write-Output dangerous)').Count -eq 0) 'Expression interpreted'
}
Test 'Global Remove-MpThreat requires separate explicit policy and logged decision' {
    $root=Fixture 'global-removal';$config=Get-Content (Join-Path $root 'Config.json') -Raw | ConvertFrom-Json
    $calls=[Collections.Generic.List[int]]::new();function Remove-MpThreat {$calls.Add(1)}
    $log=Join-Path $root 'logs\alerts.jsonl';$identity=[pscustomobject]@{ThreatId=1;DetectionId='test'}
    Invoke-SentinelGlobalThreatRemoval $config $identity @('active') $log
    Assert ($calls.Count -eq 0) 'Default policy globally removed threats'
    $config.AutoGlobalRemoveMpThreat=$true;Invoke-SentinelGlobalThreatRemoval $config $identity @('active') $log
    Assert ($calls.Count -eq 1) 'Explicit global policy failed'
    $config.AutoContainDefenderDetections=$false;Invoke-SentinelGlobalThreatRemoval $config $identity @('active') $log
    Assert ($calls.Count -eq 1) 'Disabled containment ignored'
}
function Event([long]$Id,[long]$Record,$Data) {
    $xml='<Event><EventData>'+(@($Data.Keys | ForEach-Object {'<Data Name="'+$_+'">'+[Security.SecurityElement]::Escape([string]$Data[$_])+'</Data>'}) -join '')+'</EventData></Event>'
    $e=[pscustomobject]@{Id=$Id;RecordId=$Record;TimeCreated=[datetime]'2026-09-29T01:00:00Z';Xml=$xml};$e | Add-Member ScriptMethod ToXml {$this.Xml};return $e
}
Test 'Sysmon detects 19 20 21 25 and correlates 3 22 only by ProcessGuid' {
    $root=Fixture 'sysmon';$config=Get-Content (Join-Path $root 'Config.json') -Raw | ConvertFrom-Json;$config.Sysmon.Enabled=$true
    $guid='{11111111-1111-1111-1111-111111111111}'
    $events=@((Event 1 1 @{ProcessId=123;ParentProcessId=0;Image='C:\Temp\a.exe';UtcTime='2026-09-29 01:00:00.000';ProcessGuid=$guid}),
        (Event 3 2 @{ProcessId=123;ProcessGuid='{different}'}),(Event 3 3 @{ProcessId=123;ProcessGuid=$guid}),
        (Event 22 4 @{ProcessId=123;ProcessGuid=$guid}),(Event 19 5 @{}),(Event 20 6 @{}),(Event 21 7 @{}),(Event 25 8 @{Image='C:\Temp\a.exe';ProcessGuid=$guid}))
    function Get-SentinelEventBatch {[pscustomobject]@{Reset=$false;Events=$events}}
    $queued=[Collections.Generic.List[object]]::new()
    Read-SentinelSysmon $root $config {param($p) [pscustomobject]@{Score=35;Reasons=@('test')}} {param($path,$id,$score,$p) $queued.Add([pscustomobject]@{Score=$score.Score;Process=$p})}
    Assert ($queued.Count -eq 3 -and $queued[0].Score -eq 40 -and $queued[1].Score -eq 45 -and $queued[2].Score -ge 80) 'GUID correlation or tampering detection failed'
    $alerts=@(Get-Content (Join-Path $root 'logs\alerts.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
    Assert (@($alerts | Where-Object {$_.Type -eq 'SysmonWmiPersistence' -and $_.Severity -eq 'HIGH'}).Count -eq 3) 'WMI events only logged'
    Assert (@($alerts | Where-Object {$_.Type -eq 'SysmonProcessTampering' -and $_.Severity -eq 'HIGH'}).Count -eq 1) 'Tampering event only logged'
}
Test 'Sysmon queue overflow never advances durable cursor' {
    $root=Fixture 'sysmon-overflow';$config=Get-Content (Join-Path $root 'Config.json') -Raw | ConvertFrom-Json;$config.Sysmon.Enabled=$true
    $events=@((Event 25 10 @{Image='C:\Temp\a.exe'}))
    function Get-SentinelEventBatch {[pscustomobject]@{Reset=$false;Events=$events}}
    Refused {Read-SentinelSysmon $root $config {} {throw 'queue full'}} 'Queue failure hidden'
    Assert (-not (Test-Path -LiteralPath (Join-Path $root 'state\sysmon-cursor.json'))) 'Durable event skipped on overflow'
}
Test 'Retention preserves unresolved request and response evidence' {
    $root=Fixture 'unresolved-retention';$failed=Join-Path $root 'state\response-queue\failed\request.json';Write-SentinelAtomicJson $failed @{RequestId='unresolved'}
    $evidence=Join-Path $root 'evidence\unresolved\response.json';Write-SentinelAtomicJson $evidence @{Unresolved=$true}
    (Get-Item $failed).LastWriteTime=(Get-Date).AddDays(-100);(Get-Item (Split-Path $evidence)).LastWriteTime=(Get-Date).AddDays(-100)
    Invoke-SentinelRetention -Root $root -MaxLogDays 30
    Assert ((Test-Path $failed) -and (Test-Path $evidence)) 'Unresolved evidence silently expired'
}
Test 'Response detects live replacement and does not scan replaced bytes' {
    $root=Fixture 'response-changed';$file=Join-Path $root 'changed.txt';Set-Content $file 'first';$hash=(Get-FileHash $file).Hash;Set-Content $file 'second'
    $observed=[pscustomobject]@{ProcessId=123;ExecutablePath=$file;CreationDate='2026-09-29T01:00:00Z'}
    $request=Join-Path $root 'request.json';Write-SentinelAtomicJson $request @{RequestId='changed';FilePath=$file;ProcessIdValue=123;Score=45;ObservedSHA256=$hash;ObservedProcess=$observed}
    function Get-CimInstance {param($ClassName,$Filter) [pscustomobject]@{ProcessId=123;ExecutablePath=$file;CreationDate=[datetime]'2026-09-29T01:00:00Z';ParentProcessId=0}}
    function Get-NetTCPConnection {param($OwningProcess) @()}
    function Start-MpScan {throw 'Replaced content must not be scanned as original.'}
    $r=& (Join-Path $root 'Response.ps1') -RequestFile $request -Root $root
    Assert ($r.Status -eq 'LiveTargetChanged' -and $r.Unresolved -and -not $r.DefenderCustomScanStarted) 'Replacement was accepted'
}
Test 'File changed during scan remains unresolved and cannot enter completed hash cache' {
    $root=Fixture 'response-race';$file=Join-Path $root 'race.txt';Set-Content $file 'first';$hash=(Get-FileHash $file).Hash
    $request=Join-Path $root 'request.json';Write-SentinelAtomicJson $request @{RequestId='race';FilePath=$file;ProcessIdValue=0;Score=45;ObservedSHA256=$hash}
    function Get-NetTCPConnection {param($OwningProcess) @()}
    function Start-MpScan {param($ScanType,$ScanPath) Set-Content -LiteralPath $ScanPath 'replacement during scan'}
    function Get-MpThreatDetection {@()}
    function Start-Sleep {param($Seconds)}
    $r=& (Join-Path $root 'Response.ps1') -RequestFile $request -Root $root
    Assert ($r.Status -eq 'TargetChanged' -and $r.Unresolved) 'Scan race was accepted'
    Assert (-not (Test-SentinelCompletedHash $file $hash $r)) 'Changed target entered completed cache'
}
Test 'Bootstrap is emitted separately and never made trusted by package manifest' {
    $root=Join-Path $ScratchRoot 'separate-package';$tool=Join-Path $ScratchRoot 'trusted-tool\Bootstrap.ps1'
    & (Get-SentinelSourcePath $packageRoot 'New-SentinelPackage.ps1') -OutputDirectory $root -BootstrapOutputPath $tool | Out-Null
    Assert ((Get-FileHash $tool).Hash -eq (Get-FileHash $bootstrap).Hash) 'Separate bootstrap changed'
    $m=Get-Content (Join-Path $root 'package.manifest.json') -Raw | ConvertFrom-Json
    Assert (@($m.Files | Where-Object {$_.Name -eq 'Bootstrap.ps1'}).Count -eq 0) 'Bootstrap enrolled in self-trusting manifest'
}

Test 'Worker preserves an unresolved live target in failed queue instead of completing it' {
    $root=Fixture 'worker-unresolved';$config=Get-Content (Join-Path $root 'Config.json') -Raw | ConvertFrom-Json
    $config.ResponseQueueMaxAttempts=1;$config.ResponseQueuePollSeconds=1;$config.ResponseWorkerHeartbeatSeconds=1;$config.ResponseTimeoutSeconds=10;$config.NormalResponseTimeoutSeconds=10
    Write-SentinelAtomicJson (Join-Path $root 'Config.json') $config
    [IO.File]::AppendAllText((Join-Path $root 'Common.ps1'),[Environment]::NewLine+'function Write-EventLog {}'+[Environment]::NewLine)
    Set-Content -LiteralPath (Join-Path $root 'Response.ps1') 'param($Root,$RequestFile);[pscustomobject]@{Status="LiveTargetMissing";Unresolved=$true;Severity="HIGH"}' -Encoding UTF8
    $request=Join-Path $root 'state\response-queue\high\unresolved.json'
    Write-SentinelAtomicJson $request @{RequestId='unresolved';FilePath=(Join-Path $root 'gone.exe');ProcessIdValue=123;Score=80;Priority='High';Attempts=0;ObservedSHA256=('A'*64)}
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments='-NoProfile -ExecutionPolicy Bypass -File "{0}" -Root "{1}"' -f (Join-Path $root 'ResponseWorker.ps1'),$root
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $child=[Diagnostics.Process]::new();$child.StartInfo=$info
    try {
        [void]$child.Start();$stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync();$watch=[Diagnostics.Stopwatch]::StartNew()
        $failed=Join-Path $root 'state\response-queue\failed\unresolved.json'
        while(-not (Test-Path $failed) -and -not $child.HasExited -and $watch.Elapsed.TotalSeconds -lt 20) {Start-Sleep -Milliseconds 100}
        $alertsPath=Join-Path $root 'logs\alerts.jsonl'
        while($watch.Elapsed.TotalSeconds -lt 20) {
            if((Test-Path $failed) -and (Test-Path $alertsPath)) {
                try {if([IO.File]::ReadAllText($alertsPath).Contains('ResponseRequestFailed')){break}} catch {}
            }
            if($child.HasExited){break};Start-Sleep -Milliseconds 100
        }
        Assert (Test-Path $failed) ('Worker dropped or stalled unresolved request: '+$(if($child.HasExited){$stderr.Result}else{'timeout'}))
        $alerts=@(Get-Content (Join-Path $root 'logs\alerts.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
        Assert (@($alerts | Where-Object {$_.Type -eq 'ResponseRequestCompleted'}).Count -eq 0) 'Unresolved request marked completed'
        Assert (@($alerts | Where-Object {$_.Type -eq 'ResponseRequestFailed' -and $_.Severity -eq 'HIGH'}).Count -eq 1) 'Failed live target lacked HIGH alert'
    } finally {if(-not $child.HasExited){$child.Kill();$child.WaitForExit()};$child.Dispose()}
}

Test 'Real Scheduled Task CIM objects satisfy strict startup definition' {
    $root=Fixture 'task-cim'
    $arguments='-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Root "{1}"' -f (Join-Path $root 'Watcher.ps1'),$root
    $action=New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $arguments
    $trigger=New-ScheduledTaskTrigger -AtStartup
    $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    $task=New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal
    Assert (Test-SentinelTaskDefinition $task $root 'SentinelLocal Watcher') 'Real CIM task differed from expected definition'
}

$admin=([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($RequireSecureStagingTests -and -not $admin) {Test 'Elevated protected staging is required by CI' {throw 'CI runner must have an elevated administrator token.'}}
if($admin) {
    $protected=Join-Path $env:ProgramData ('SentinelLocal-CI-'+[guid]::NewGuid().ToString('N'))
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach($sid in @('S-1-5-32-544','S-1-5-18')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
    [void][IO.Directory]::CreateDirectory($protected,$acl)
    Test 'Real protected staging copies verified bytes and rejects post-stage tampering' {
        $root=Package 'secure-stage';$stage=& $bootstrap -PackageRoot $root -Mode Stage -DevelopmentUnsigned -ExpectedManifestSHA256 (Get-FileHash (Join-Path $root 'package.manifest.json')).Hash -StagingRoot (Join-Path $protected 'stages')
        $acl=Get-Acl $stage.StageRoot;Assert $acl.AreAccessRulesProtected 'Stage inherited unsafe ACL'
        $installer=[IO.File]::ReadAllText((Join-Path $stage.StageRoot 'Install-SentinelLocal.ps1'))
        $end=$installer.IndexOf('# END BOOTSTRAP GUARD')+'# END BOOTSTRAP GUARD'.Length
        $probe=Join-Path $stage.StageRoot 'GuardProbe.ps1'
        [IO.File]::WriteAllText($probe,($installer.Substring(0,$end)+[Environment]::NewLine+"'StageGuardPassed'"),[Text.UTF8Encoding]::new($true))
        Assert ((& $probe -StageReceiptPath $stage.StageReceiptPath) -eq 'StageGuardPassed') 'Valid staged package failed the real installer guard'
        $before=(Get-FileHash (Join-Path $stage.StageRoot 'Common.ps1')).Hash
        Set-Content -LiteralPath (Join-Path $root 'Common.ps1') 'source replaced after verification'
        Assert ((Get-FileHash (Join-Path $stage.StageRoot 'Common.ps1')).Hash -eq $before) 'Source replacement changed staged bytes'
        $marker=Join-Path $stage.StageRoot 'executed.txt'
        Set-Content -LiteralPath (Join-Path $stage.StageRoot 'Common.ps1') ("[IO.File]::WriteAllText('"+$marker+"','bad')")
        Refused {& (Join-Path $stage.StageRoot 'Install-SentinelLocal.ps1') -StageReceiptPath $stage.StageReceiptPath} 'Changed staged payload accepted'
        Assert (-not (Test-Path $marker)) 'Changed staged code imported'
    }
    Test 'Bootstrap holds verified source and staging locks through child execution' {
        $root=Package 'locked-child';$installerPath=Join-Path $root 'Install-SentinelLocal.ps1'
        # Harmless trusted test payload: no actual deployment. Assert write refusal in the child.
        $stub='param($InstallRoot,$StageReceiptPath,$StartupTimeoutSeconds)'+[Environment]::NewLine
        $stub+='foreach($path in @((Join-Path $PSScriptRoot ''Common.ps1''),'''+(Join-Path $root 'Common.ps1').Replace("'","''")+''')) {$blocked=$false;try {[IO.File]::WriteAllText($path,''replacement'')} catch [IO.IOException] {$blocked=$true};if(-not $blocked){throw ''Verified file handle allowed writes during execution.''}}'
        [IO.File]::WriteAllText($installerPath,$stub,[Text.UTF8Encoding]::new($true))
        $manifestPath=Join-Path $root 'package.manifest.json';$m=Get-Content $manifestPath -Raw | ConvertFrom-Json
        $entry=@($m.Files | Where-Object Name -eq 'Install-SentinelLocal.ps1')[0];$entry.SHA256=(Get-FileHash $installerPath).Hash;$entry.Length=(Get-Item $installerPath).Length
        Write-SentinelAtomicJson $manifestPath $m
        $r=& $bootstrap -PackageRoot $root -Mode Install -DevelopmentUnsigned -ExpectedManifestSHA256 (Get-FileHash $manifestPath).Hash -StagingRoot (Join-Path $protected 'lock-stages') -InstallRoot (Join-Path $protected 'fake-installation')
        Assert $r.Installed 'Harmless test child failed'
    }
    Test 'Protected snapshot preserves original bytes and refuses tampering oversized or unsafe paths' {
        $root=Join-Path $protected 'snapshot';[void][IO.Directory]::CreateDirectory($root,$acl)
        $config=Get-Content (Join-Path $packageRoot 'config\Config.json') -Raw | ConvertFrom-Json
        $source=Join-Path $ScratchRoot 'snapshot-input.txt';Set-Content $source 'original';$hash=(Get-FileHash $source).Hash
        $snapshot=Save-SentinelObservedFile $root $source $hash ([guid]::NewGuid().ToString()) $config
        Set-Content $source 'replacement'
        Assert ((Get-FileHash $snapshot).Hash -eq $hash -and ((Get-Item $snapshot).Attributes -band [IO.FileAttributes]::ReadOnly)) 'Snapshot did not preserve immutable observation'
        Assert ((Get-SentinelVerifiedSnapshot $root $snapshot $hash) -eq $snapshot) 'Valid snapshot rejected'
        Refused {Get-SentinelVerifiedSnapshot $root $source $hash} 'Unprotected snapshot accepted'
        Refused {Save-SentinelObservedFile $root $source $hash ([guid]::NewGuid().ToString()) $config} 'Changed source captured as original'
        $config.Resources.MaxSnapshotFileMB=1;[IO.File]::WriteAllBytes($source,(New-Object byte[] 2MB))
        Refused {Save-SentinelObservedFile $root $source (Get-FileHash $source).Hash ([guid]::NewGuid().ToString()) $config} 'Oversized snapshot captured'
    }
    # Intentionally retained for CI diagnostics; runner destroys this ephemeral VM.
    Write-Host ('Protected test artifacts: '+$protected)
} else {Write-Host 'SKIP protected staging/snapshot integration: administrator token unavailable; CI requires these tests.'}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ScratchRoot 'test-results.json') -Encoding UTF8
$failed=@($results | Where-Object {-not $_.Passed}).Count
Write-Host ('Security tests: '+($results.Count-$failed)+'/'+$results.Count+' passed')
if($failed){exit 1}else{exit 0}
