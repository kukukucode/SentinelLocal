param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-pilot-'+[guid]::NewGuid().ToString('N'))),[string]$Filter='.*')
$ErrorActionPreference='Stop'
$packageRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $packageRoot 'src\Common.ps1')
if(Test-Path -LiteralPath $ScratchRoot) { throw 'Scratch directory already exists.' }
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$results=[Collections.Generic.List[object]]::new()
function Assert([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message } }
function Test([string]$Name,[scriptblock]$Body) {
    if($Name -notmatch $Filter) { return }
    try { & $Body;$results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'});Write-Host ('PASS '+$Name) }
    catch { $results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message});Write-Host ('FAIL '+$Name+': '+$_.Exception.Message) -ForegroundColor Red }
}
function Fixture([string]$Name,[switch]$Baseline,[switch]$SourceLayout) {
    $directory=Join-Path $ScratchRoot $Name
    New-Item -ItemType Directory -Path $directory | Out-Null
    foreach($file in Get-SentinelPackageFiles) {
        $source=Get-SentinelSourcePath $packageRoot $file
        $relative=if($SourceLayout) { $source.Substring($packageRoot.Length+1) } else { $file }
        $destination=Join-Path $directory $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination
    }
    if($Baseline) {
        $files=@(foreach($file in Get-SentinelPackageFiles) { $item=Get-Item -LiteralPath (Join-Path $directory $file);[pscustomobject]@{Name=$file;SHA256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash;Length=$item.Length;LastWriteTimeUtc=$item.LastWriteTimeUtc.ToString('o')} })
        Write-SentinelAtomicJson (Join-Path $directory 'state\integrity-baseline.json') ([ordered]@{Version='1.2.0';Files=$files})
    }
    return $directory
}
function Config([string]$Root) { return Get-Content -LiteralPath (Join-Path $Root 'Config.json') -Raw -Encoding UTF8 | ConvertFrom-Json }
function SourceFunction([string]$File,[string]$Name) {
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Get-SentinelSourcePath $packageRoot $File),[ref]$tokens,[ref]$errors)
    return [scriptblock]::Create($ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name},$true).Extent.Text)
}
function Sign-Manifest([string]$Root,$Certificate) {
    Add-Type -AssemblyName System.Security
    $path=Join-Path $Root 'package.manifest.json'
    $cms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($path)),$true)
    $signer=[Security.Cryptography.Pkcs.CmsSigner]::new($Certificate);$signer.DigestAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    $cms.ComputeSignature($signer);[IO.File]::WriteAllBytes($path+'.p7s',$cms.Encode())
}
function Test-Certificate {
    $rsa=[Security.Cryptography.RSA]::Create(2048)
    $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=SentinelLocal in-memory TEST ONLY',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $oids=[Security.Cryptography.OidCollection]::new();[void]$oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false))
    return $request.CreateSelfSigned([datetimeoffset]::Now.AddMinutes(-5),[datetimeoffset]::Now.AddDays(1))
}
function Write-EventLog {} # Fixtures never alter the Windows event log.

Test 'Repository folders build the installed flat layout with valid documentation links' {
    Assert ((Get-SentinelSourceRoot (Join-Path $packageRoot 'scripts')) -eq $packageRoot) 'Default package root was not resolved'
    Assert ((Get-SentinelSourcePath $packageRoot 'Config.json') -eq (Join-Path $packageRoot 'config\Config.json')) 'Source configuration did not resolve'
    Assert (@(Get-ChildItem -LiteralPath $packageRoot -File -Filter '*.ps1').Count -eq 0) 'Root still contains operational scripts'
    $output=Join-Path $ScratchRoot 'layout-package'
    & (Get-SentinelSourcePath $packageRoot 'New-SentinelPackage.ps1') -OutputDirectory $output | Out-Null
    foreach($file in Get-SentinelPackageFiles) { Assert (Test-Path -LiteralPath (Join-Path $output $file) -PathType Leaf) ('Flat deployment file missing: '+$file) }
    Assert (-not (Test-Path (Join-Path $output 'src')) -and -not (Test-Path (Join-Path $output 'scripts'))) 'Source folders leaked into deployed paths'
    $verified=& (Join-Path $output 'Verify-SentinelPackage.ps1') -AllowUnsignedPackage
    Assert $verified.Valid 'Distribution default verification root failed'
    foreach($readmePath in @((Join-Path $packageRoot 'README.md'),(Join-Path $output 'README.md'))) {
        foreach($match in [regex]::Matches([IO.File]::ReadAllText($readmePath),'\]\(([^)]+)\)')) {
            $target=$match.Groups[1].Value
            if($target -notmatch '^https?://') { Assert (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $readmePath) $target)) ('Documentation link missing: '+$target) }
        }
    }
}
Test 'Invalid policies fail before changes' {
    $root=Fixture 'config';$config=Config $root;Assert-SentinelConfig $config
    $config.PollSeconds='2';$failed=$false
    try { Assert-SentinelConfig $config } catch { $failed=$true }
    Assert $failed 'String polling interval accepted'
    $config.PollSeconds=2;$config.Resources.HighQueueReserve=$config.Resources.MaxQueueCount
    $failed=$false;try { Assert-SentinelConfig $config } catch { $failed=$true };Assert $failed 'Invalid capacity reserve accepted'
    $config=Config $root;$config.Sysmon.Enabled='false'
    $failed=$false;try { Assert-SentinelConfig $config } catch {$failed=$true};Assert $failed 'String false silently enabled Sysmon'
}
Test 'Policy overlay rejects unknown fields and version changes' {
    $root=Fixture 'merge';$config=Config $root
    $candidate=Merge-SentinelPolicy $config ([pscustomobject]@{Resources=[pscustomobject]@{MaxEvidenceMB=1024}})
    Assert ($candidate.Resources.MaxEvidenceMB -eq 1024 -and $candidate.PollSeconds -eq $config.PollSeconds) 'Overlay lost existing settings'
    foreach($patch in @([pscustomobject]@{Version='99'},[pscustomobject]@{Resources=[pscustomobject]@{Unknown=1}})) {
        $failed=$false;try { Merge-SentinelPolicy $config $patch | Out-Null } catch { $failed=$true };Assert $failed 'Unsupported field accepted'
    }
}
Test 'Changed script content bypasses path deduplication' {
    $Root=Fixture 'dedupe';$config=Config $Root
    $config.ResponseQueueDedupeSeconds=86400 # Identity test remains valid if the local PC sleeps.
    $responsePathDedupe=@{};$responseQueueHigh=Join-Path $Root 'state\response-queue\high';$responseQueueNormal=Join-Path $Root 'state\response-queue\normal';$alertLog=Join-Path $Root 'logs\alerts.jsonl'
    New-Item -ItemType Directory -Path $responseQueueHigh,$responseQueueNormal -Force | Out-Null
    function Save-ResponsePathDedupe {}
    . (SourceFunction 'Watcher.ps1' 'Queue-SentinelResponse')
    $target=Join-Path $Root 'harmless.ps1';Set-Content -LiteralPath $target -Value '# content A'
    Queue-SentinelResponse -FilePath $target -Score 50
    Queue-SentinelResponse -FilePath $target -Score 50
    Assert (@(Get-ChildItem -LiteralPath $responseQueueNormal -Filter '*.json').Count -eq 1) 'Identical content was not deduplicated'
    Set-Content -LiteralPath $target -Value '# changed B'
    Queue-SentinelResponse -FilePath $target -Score 50
    Assert (@(Get-ChildItem -LiteralPath $responseQueueNormal -Filter '*.json').Count -eq 2) 'Changed content was suppressed'
}
Test 'Failed hashes never create a stable dedupe identity' {
    Assert ((Get-SentinelFileIdentity (Join-Path $ScratchRoot 'missing')) -ne (Get-SentinelFileIdentity (Join-Path $ScratchRoot 'missing'))) 'Hash failures can suppress a scan'
}
Test 'Persistence comparison survives restart and failures retain old snapshot' {
    $root=Fixture 'persistence'
    $first=@([pscustomobject]@{Type='Task';Key='A';Value='old'})
    Update-SentinelPersistenceSnapshot $root $first {param($old,$new)}
    $script:observedOld=''
    Update-SentinelPersistenceSnapshot $root @([pscustomobject]@{Type='Task';Key='A';Value='new'}) {param($old,$new) $script:observedOld=$old[0].Value}
    Assert ($script:observedOld -eq 'old') 'Previous boot state was lost'
    $path=Join-Path $root 'state\persistence-snapshot.json';$hash=(Get-FileHash $path).Hash
    $failed=$false;try { Update-SentinelPersistenceSnapshot $root @() {throw 'Mock queue full'} } catch {$failed=$true}
    Assert ($failed -and (Get-FileHash $path).Hash -eq $hash) 'Failed processing advanced durable baseline'
}
Test 'Malformed durable snapshot is preserved for investigation' {
    $root=Fixture 'bad-persistence';$path=Join-Path $root 'state\persistence-snapshot.json'
    Write-SentinelAtomicJson $path ([ordered]@{Schema=0;Items=@()})
    $hash=(Get-FileHash $path).Hash;$failed=$false
    try { Update-SentinelPersistenceSnapshot $root @() {} } catch { $failed=$true }
    Assert ($failed -and (Get-FileHash $path).Hash -eq $hash) 'Malformed state was silently trusted'
}
Test 'Queue reserves room for high risk and refuses overflow' {
    $root=Fixture 'capacity';$config=Config $root;$config.Resources.MaxQueueCount=3;$config.Resources.HighQueueReserve=1
    $queue=Join-Path $root 'state\response-queue\normal';New-Item -ItemType Directory -Path $queue -Force | Out-Null
    foreach($index in 1..2) { Write-SentinelAtomicJson (Join-Path $queue ($index.ToString()+'.json')) @{} }
    $failed=$false;try { Assert-SentinelQueueCapacity $root $config Normal } catch {$failed=$true};Assert $failed 'Normal lane used high reserve'
    Assert-SentinelQueueCapacity $root $config High
    Write-SentinelAtomicJson (Join-Path $queue '3.json') @{}
    $failed=$false;try { Assert-SentinelQueueCapacity $root $config High } catch {$failed=$true};Assert $failed 'High lane overflow accepted'
}
Test 'Aged normal requests progress during high-risk bursts' {
    $root=Fixture 'fairness';$config=Config $root;$queue=Join-Path $root 'state\response-queue'
    foreach($lane in @('high','normal')) {New-Item -ItemType Directory -Path (Join-Path $queue $lane) -Force | Out-Null}
    Write-SentinelAtomicJson (Join-Path $queue 'high\high.json') ([ordered]@{QueuedAt=[datetimeoffset]::Now.ToString('o')})
    Write-SentinelAtomicJson (Join-Path $queue 'normal\normal.json') ([ordered]@{QueuedAt=[datetimeoffset]::Now.AddMinutes(-5).ToString('o')})
    Assert ((Get-SentinelEligibleQueueFile $queue $config 0).Name -eq 'high.json') 'High priority not honored'
    Assert ((Get-SentinelEligibleQueueFile $queue $config 5).Name -eq 'normal.json') 'Normal requests starved'
    Write-SentinelAtomicJson (Join-Path $queue 'normal\normal.json') ([ordered]@{QueuedAt=[datetimeoffset]::Now.AddMinutes(-5).ToString('o');AvailableAfter=[datetimeoffset]::Now.AddMinutes(5).ToString('o')})
    Assert ((Get-SentinelEligibleQueueFile $queue $config 5).Name -eq 'high.json') 'Retry delay ignored'
}
Test 'Evidence quota stops new capture without deleting evidence' {
    $root=Fixture 'evidence-limit';$config=Config $root;$config.Resources.MaxEvidenceMB=1
    $dir=Join-Path $root 'evidence';New-Item -ItemType Directory -Path $dir | Out-Null
    $file=Join-Path $dir 'harmless.data';[IO.File]::WriteAllBytes($file,[byte[]]::new(1MB))
    $failed=$false;try { Assert-SentinelStorage $root $config -Evidence } catch {$failed=$true}
    Assert ($failed -and (Get-Item $file).Length -eq 1MB) 'Evidence was deleted or quota was ignored'
}
Test 'Oversize log fails closed and preserves its bytes' {
    $root=Fixture 'log-limit';$config=Config $root;$config.Resources.MaxLogFileMB=1
    $dir=Join-Path $root 'logs';New-Item -ItemType Directory -Path $dir | Out-Null
    $file=Join-Path $dir 'probe.jsonl';[IO.File]::WriteAllBytes($file,[byte[]]::new(1MB))
    Assert (-not (Write-SentinelJsonLine $file ([ordered]@{Type='Probe'}))) 'Oversize log accepted more writes'
    Assert ((Get-Item $file).Length -eq 1MB) 'Oversize log was truncated'
}
Test 'Rollback restores integrity baseline and removes every newly installed module' {
    $root=Fixture 'rollback' -Baseline;$backup=Join-Path $root 'backups\probe'
    $newFile=Join-Path $root 'OperationalSafety.ps1';Remove-Item -LiteralPath $newFile
    $baselinePath=Join-Path $root 'state\integrity-baseline.json';$oldHash=(Get-FileHash $baselinePath).Hash
    New-SentinelDeploymentBackup $root $backup @{}
    Set-Content -LiteralPath $newFile -Value '# new module';Set-Content -LiteralPath $baselinePath -Value '{}'
    Set-Content -LiteralPath (Join-Path $root 'Config.json') -Value '{}'
    [void](Restore-SentinelDeploymentBackup $root $backup)
    Assert (-not (Test-Path -LiteralPath $newFile)) 'New module survived rollback'
    Assert ((Get-FileHash $baselinePath).Hash -eq $oldHash) 'Integrity baseline was not restored'
    Assert ((Config $root).Version -eq '1.2.0') 'Configuration was not restored'
}
Test 'Corrupt rollback backup cannot partially overwrite installation' {
    $root=Fixture 'bad-rollback';$backup=Join-Path $root 'backups\probe';New-SentinelDeploymentBackup $root $backup @{}
    Set-Content -LiteralPath (Join-Path $backup 'Common.ps1') -Value '# corrupt'
    $hash=(Get-FileHash (Join-Path $root 'Common.ps1')).Hash;$failed=$false
    try { Restore-SentinelDeploymentBackup $root $backup | Out-Null } catch {$failed=$true}
    Assert ($failed -and (Get-FileHash (Join-Path $root 'Common.ps1')).Hash -eq $hash) 'Corrupt backup partially restored'
}
Test 'Successful policy change updates only the configuration baseline' {
    $root=Fixture 'policy' -Baseline;$config=Config $root;$config.PollSeconds=3
    $before=Get-Content -LiteralPath (Join-Path $root 'state\integrity-baseline.json') -Raw | ConvertFrom-Json
    $result=Set-SentinelConfigTransaction $root $config 'Test reviewed configuration'
    Assert ($result.Changed -and (Test-Path $result.Backup)) 'Policy backup missing'
    $after=Assert-SentinelBaseline $root
    foreach($entry in $before.Files | Where-Object Name -ne 'Config.json') { Assert (@($after.Files | Where-Object Name -eq $entry.Name)[0].SHA256 -eq $entry.SHA256) 'Unrelated baseline was reapproved' }
    Assert (Get-SentinelLogVerification (Join-Path $root 'logs\administration.jsonl')).Valid 'Policy audit failed verification'
}
Test 'Policy update refuses an unrelated tampered module' {
    $root=Fixture 'policy-tamper' -Baseline;Add-Content -LiteralPath (Join-Path $root 'Response.ps1') -Value '# unexpected change'
    $hash=(Get-FileHash (Join-Path $root 'Config.json')).Hash;$failed=$false
    try { Set-SentinelConfigTransaction $root (Config $root) 'test' | Out-Null } catch {$failed=$true}
    Assert ($failed -and (Get-FileHash (Join-Path $root 'Config.json')).Hash -eq $hash) 'Tampered module was trusted through policy update'
}
Test 'Failed administration audit rolls configuration and baseline back' {
    $root=Fixture 'policy-audit-failure' -Baseline;$config=Config $root;$config.PollSeconds=3
    $configHash=(Get-FileHash (Join-Path $root 'Config.json')).Hash;$baselineHash=(Get-FileHash (Join-Path $root 'state\integrity-baseline.json')).Hash
    function Write-SentinelJsonLine { return $false }
    $failed=$false;try { Set-SentinelConfigTransaction $root $config 'test' | Out-Null } catch {$failed=$true}
    Assert ($failed -and (Get-FileHash (Join-Path $root 'Config.json')).Hash -eq $configHash -and (Get-FileHash (Join-Path $root 'state\integrity-baseline.json')).Hash -eq $baselineHash) 'Failed policy transaction was committed'
}
Test 'Audit-first hardening does not weaken existing blocking settings' {
    $id=(Get-SentinelManagedAsrRules).Keys | Select-Object -First 1
    $snapshot=[pscustomobject]@{NetworkProtectionSupported=$true;Preference=[pscustomobject]@{EnableNetworkProtection='1';EnableControlledFolderAccess='1';PUAProtection='1';CloudBlockLevel='6';AttackSurfaceReductionRules=@([pscustomobject]@{Id=$id;Action=1})}}
    $plan=@(Get-SentinelHardeningPlan $snapshot AuditFirst)
    Assert (@($plan | Where-Object { $_.Setting -eq $id })[0].Desired -eq 1) 'ASR Block was downgraded'
    Assert (@($plan | Where-Object Setting -eq EnableNetworkProtection)[0].Desired -eq '1') 'Network block was downgraded'
    Assert (@($plan | Where-Object Setting -eq CloudBlockLevel)[0].Desired -eq '6') 'Cloud block level was downgraded'
    Assert ((ConvertTo-SentinelPreferenceValue MAPSReporting 2) -eq 'Advanced') 'Preference verification did not normalize numeric enum'
}
Test 'Audit-first new network setting audits instead of enabling block' {
    $snapshot=[pscustomobject]@{NetworkProtectionSupported=$true;Preference=[pscustomobject]@{EnableNetworkProtection='0';AttackSurfaceReductionRules=@()}}
    Assert (@(Get-SentinelHardeningPlan $snapshot AuditFirst | Where-Object Setting -eq EnableNetworkProtection)[0].Desired -eq 'AuditMode') 'Audit profile unexpectedly blocked network traffic'
}
Test 'Unsupported network protection is excluded from application and verification' {
    $snapshot=[pscustomobject]@{NetworkProtectionSupported=$false;Preference=[pscustomobject]@{EnableNetworkProtection='0';AttackSurfaceReductionRules=@()}}
    $item=@(Get-SentinelHardeningPlan $snapshot AuditFirst | Where-Object Setting -eq EnableNetworkProtection)[0]
    Assert ($item.Kind -eq 'Unavailable' -and $null -eq $item.Desired) 'Unsupported edition received a network protection plan'
}
Test 'Unsigned packages require explicit acceptance and detect modified files' {
    $output=Join-Path $ScratchRoot 'unsigned-package'
    & (Get-SentinelSourcePath $packageRoot 'New-SentinelPackage.ps1') -Root $packageRoot -OutputDirectory $output | Out-Null
    $failed=$false;try { Test-SentinelPackage $output | Out-Null } catch {$failed=$true};Assert $failed 'Unsigned package implicitly trusted'
    Assert (Test-SentinelPackage $output -AllowUnsigned).Valid 'Reviewed pilot package rejected'
    Add-Content -LiteralPath (Join-Path $output 'Response.ps1') -Value '# changed'
    $failed=$false;try { Test-SentinelPackage $output -AllowUnsigned | Out-Null } catch {$failed=$true};Assert $failed 'Modified package file passed hash verification'
}
Test 'Signed manifest requires pinned signer and rejects signature modification' {
    $output=Join-Path $ScratchRoot 'signed-package'
    & (Get-SentinelSourcePath $packageRoot 'New-SentinelPackage.ps1') -Root $packageRoot -OutputDirectory $output | Out-Null
    $certificate=Test-Certificate
    try {
        Sign-Manifest $output $certificate
        Assert (Test-SentinelPackage $output $certificate.Thumbprint).Signed 'Pinned package signature rejected'
        $failed=$false;try {Test-SentinelPackage $output ('0'*40) | Out-Null} catch {$failed=$true};Assert $failed 'Wrong signer accepted'
        $manifest=Join-Path $output 'package.manifest.json';[IO.File]::AppendAllText($manifest,' ')
        $failed=$false;try {Test-SentinelPackage $output $certificate.Thumbprint | Out-Null} catch {$failed=$true};Assert $failed 'Modified manifest signature accepted'
    } finally { $certificate.Dispose() }
}
Test 'Package rejects traversal and omitted required files' {
    $output=Join-Path $ScratchRoot 'bad-package'
    & (Get-SentinelSourcePath $packageRoot 'New-SentinelPackage.ps1') -Root $packageRoot -OutputDirectory $output | Out-Null
    $path=Join-Path $output 'package.manifest.json';$manifest=Get-Content $path -Raw | ConvertFrom-Json
    $manifest.Files[0].Name='..\Config.json';Write-SentinelAtomicJson $path $manifest
    $failed=$false;try { Test-SentinelPackage $output -AllowUnsigned | Out-Null } catch {$failed=$true};Assert $failed 'Path traversal accepted'
}
Test 'Investigation report escapes log content and records integrity results' {
    $root=Fixture 'report';$path=Join-Path $root 'logs\alerts.jsonl'
    Assert (Write-SentinelJsonLine $path ([ordered]@{Type='Probe';Severity='MEDIUM';Reason='</pre><script>alert(1)</script>'})) 'Fixture log failed'
    $output=Join-Path $ScratchRoot 'report-output'
    & (Get-SentinelSourcePath $packageRoot 'Export-SentinelReport.ps1') -Root $root -OutputDirectory $output | Out-Null
    $html=[IO.File]::ReadAllText((Join-Path $output 'index.html'))
    Assert ($html -notmatch '<script>alert' -and $html -match '&lt;script&gt;') 'Log content could inject HTML'
    $json=Get-Content (Join-Path $output 'report.json') -Raw | ConvertFrom-Json
    Assert ($json.Timeline.Count -eq 1 -and $json.Verification[0].Valid) 'Timeline/verification missing'
}
Test 'Readiness probes do not rewrite configuration' {
    $root=Fixture 'readiness';$hash=(Get-FileHash (Join-Path $root 'Config.json')).Hash
    $result=& (Get-SentinelSourcePath $packageRoot 'Test-SentinelReadiness.ps1') -Root $root
    Assert ($result.ReadOnly -and $result.Checks.Count -eq 9 -and (Get-FileHash (Join-Path $root 'Config.json')).Hash -eq $hash) 'Readiness probe changed policy'
}
Test 'cmd script hosts are eligible for referenced-script scanning' {
    $Root=Fixture 'cmd-host'
    . (SourceFunction 'Watcher.ps1' 'Get-FileSignatureStatus')
    . (SourceFunction 'Watcher.ps1' 'Get-ProcessScore')
    . (SourceFunction 'Watcher.ps1' 'Test-RandomishSegment')
    $observed=[pscustomobject]@{Name='cmd.exe';ExecutablePath=(Join-Path $env:WINDIR 'System32\cmd.exe');CommandLine='cmd /c C:\Temp\harmless.cmd'}
    Assert ((Get-ProcessScore $observed).Score -gt 0) 'cmd payloads never reached script scanning'
}
Test 'Completed hash cache rejects targets changed during response' {
    $path=Join-Path $ScratchRoot 'completion-target.ps1';Set-Content $path 'Write-Host initial'
    $hash=(Get-FileHash $path).Hash
    $response=[pscustomobject]@{Status='Completed';File=[pscustomobject]@{SHA256=$hash}}
    Assert (Test-SentinelCompletedHash $path $hash $response) 'Stable completion was rejected'
    Set-Content $path 'Write-Host changed'
    Assert (-not (Test-SentinelCompletedHash $path $hash $response)) 'Changed target entered the completion cache'
    $response.File.SHA256='0'*64
    Assert (-not (Test-SentinelCompletedHash $path (Get-FileHash $path).Hash $response)) 'Unmatched scan identity was cached'
}
Test 'Upgrade startup failure restores old files baseline and task states' {
    $installed=Fixture 'upgrade-old' -Baseline
    $oldConfig=Config $installed;$oldConfig.Version='1.1.0';Write-SentinelAtomicJson (Join-Path $installed 'Config.json') $oldConfig
    Add-Content -LiteralPath (Join-Path $installed 'Common.ps1') -Value '# old reviewed implementation'
    $oldCommonHash=(Get-FileHash (Join-Path $installed 'Common.ps1')).Hash
    $oldBaselineHash=(Get-FileHash (Join-Path $installed 'state\integrity-baseline.json')).Hash
    $source=Fixture 'upgrade-source' -SourceLayout
    $baselineUpdater=Get-SentinelSourcePath $source 'Update-SentinelIntegrityBaseline.ps1'
    [IO.File]::WriteAllText($baselineUpdater,[IO.File]::ReadAllText($baselineUpdater).Replace('#Requires -RunAsAdministrator',''),[Text.UTF8Encoding]::new($true))
    $scriptPath=Get-SentinelSourcePath $source 'Upgrade-SentinelLocal.ps1'
    $scriptText=[IO.File]::ReadAllText($scriptPath).Replace('#Requires -RunAsAdministrator','')
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($scriptText,[ref]$tokens,[ref]$errors)
    $acl=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-SentinelAcl'},$true)
    $scriptText=$scriptText.Replace($acl.Extent.Text,'function Set-SentinelAcl { param($Path) }')
    $scriptText=$scriptText.Replace("if(-not [Diagnostics.EventLog]::SourceExists('SentinelLocal')) { New-EventLog -LogName Application -Source SentinelLocal }",'# Fixture omits privileged event source registration.')
    [IO.File]::WriteAllText($scriptPath,$scriptText,[Text.UTF8Encoding]::new($true))
    $fixtureTasks=@{}
    foreach($name in @('SentinelLocal Watcher','SentinelLocal Response Worker','SentinelLocal Integrity Monitor')) {
        $fixtureTasks[$name]=[pscustomobject]@{TaskName=$name;State=$(if($name -eq 'SentinelLocal Watcher'){'Running'}else{'Ready'});Actions=@([pscustomobject]@{Arguments=('-Root "'+$installed+'"')})}
    }
    function Get-ScheduledTask { [CmdletBinding()]param($TaskName) if($fixtureTasks.ContainsKey($TaskName)) { $fixtureTasks[$TaskName] } }
    function Stop-ScheduledTask { [CmdletBinding()]param($TaskName) $fixtureTasks[$TaskName].State='Ready' }
    function Start-ScheduledTask { [CmdletBinding()]param($TaskName) $fixtureTasks[$TaskName].State='Running' }
    function Export-ScheduledTask { [CmdletBinding()]param($TaskName) return ('old-xml-'+$TaskName) }
    function Unregister-ScheduledTask { [CmdletBinding(SupportsShouldProcess=$true)]param($TaskName) [void]$fixtureTasks.Remove($TaskName) }
    function New-EventLog { param($LogName,$Source) }
    function New-ScheduledTaskTrigger { param([switch]$AtStartup) @{} }
    function New-ScheduledTaskPrincipal { param($UserId,$LogonType,$RunLevel) @{} }
    function New-ScheduledTaskSettingsSet { param($RestartCount,$RestartInterval,$ExecutionTimeLimit,[switch]$StartWhenAvailable) @{} }
    function New-ScheduledTaskAction { param($Execute,$Argument) [pscustomobject]@{Execute=$Execute;Arguments=$Argument} }
    function Register-ScheduledTask {
        [CmdletBinding()]param($TaskName,$Xml,$Action,$Trigger,$Principal,$Settings,$Description,[switch]$Force)
        $fixtureTasks[$TaskName]=[pscustomobject]@{TaskName=$TaskName;State='Ready';Actions=@([pscustomobject]@{Arguments=('-Root "'+$installed+'"')});Xml=$Xml}
    }
    $failed=$false
    $errorText=''
    try { & $scriptPath -InstallRoot $installed -AllowUnsignedPackage -StartupTimeoutSeconds 5 | Out-Null } catch { $errorText=$_.Exception.Message;$failed=$errorText -like '*heartbeat*' }
    Assert $failed ('Expected startup heartbeat failure; actual: '+$errorText)
    Assert ((Config $installed).Version -eq '1.1.0' -and (Get-FileHash (Join-Path $installed 'Common.ps1')).Hash -eq $oldCommonHash -and (Get-FileHash (Join-Path $installed 'state\integrity-baseline.json')).Hash -eq $oldBaselineHash) 'Upgrade failed to restore previous files'
    Assert ($fixtureTasks['SentinelLocal Watcher'].State -eq 'Running' -and $fixtureTasks['SentinelLocal Response Worker'].State -eq 'Ready' -and $fixtureTasks['SentinelLocal Integrity Monitor'].State -eq 'Ready') 'Rollback changed previous task states'
}
Test 'Startup verification rejects stale or wrong-version heartbeat' {
    $root=Fixture 'startup-check';$started=[datetimeoffset]::Now
    foreach($name in @('watcher-heartbeat.json','response-worker-heartbeat.json','integrity-monitor-heartbeat.json')) {
        Write-SentinelAtomicJson (Join-Path $root ('state\'+$name)) ([ordered]@{Version='1.1.0';WatcherProcessId=$PID;Status='Running';LastUpdated=[datetimeoffset]::Now.ToString('o')})
    }
    $failed=$false;try { Wait-SentinelDeploymentReady $root '1.2.0' $started 1 } catch {$failed=$true};Assert $failed 'Old version was accepted'
    foreach($name in @('watcher-heartbeat.json','response-worker-heartbeat.json','integrity-monitor-heartbeat.json')) {
        Write-SentinelAtomicJson (Join-Path $root ('state\'+$name)) ([ordered]@{Version='1.2.0';WatcherProcessId=$PID;Status='Running';LastUpdated=[datetimeoffset]::Now.ToString('o')})
    }
    Wait-SentinelDeploymentReady $root '1.2.0' $started 1
}
Write-SentinelAtomicJson (Join-Path $ScratchRoot 'test-results.json') @($results)
$results | Format-Table -AutoSize
if(@($results | Where-Object { -not $_.Passed }).Count) { exit 1 }
