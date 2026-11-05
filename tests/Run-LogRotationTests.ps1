param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-rotation-tests-'+[guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'src\Common.ps1')
if(Test-Path $ScratchRoot){throw 'Scratch directory exists.'}
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$results=[Collections.Generic.List[object]]::new()
function Assert([bool]$Value,[string]$Message){if(-not $Value){throw $Message}}
function Test([string]$Name,[scriptblock]$Body){try{& $Body;$results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'});Write-Host ('PASS '+$Name)}catch{$results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message});Write-Host ('FAIL '+$Name+': '+$_.Exception.Message)}}
function Refused([scriptblock]$Body){$failed=$false;try{& $Body | Out-Null}catch{$failed=$true};Assert $failed 'Unsafe operation was accepted.'}
function Fixture([string]$Name){Join-Path $ScratchRoot ($Name+'\logs\events.jsonl')}
function Append([string]$Path,[int]$Number,[long]$Total=100000){Add-SentinelChainedRecord -Path $Path -Payload ([ordered]@{Type='Fixture';Number=$Number;Text=('x'*500);Timestamp=[datetimeoffset]::Now.ToString('o')}) -MaxFileBytes 1700 -MaxTotalBytes $Total}
$realAtomic=${function:Write-SentinelAtomicJson}
$realSnapshot=${function:Get-SentinelLogSnapshot}
Test 'Runtime retention seals legacy bytes without parsing history under the writer lock' {
    $path=Fixture 'runtime-legacy';$root=Split-Path (Split-Path $path)
    $rows=@(1..1500 | ForEach-Object {[ordered]@{Type='OldFixture';Number=$_;Timestamp=[datetimeoffset]::Now.AddDays(-45).ToString('o');Text=('x'*200)}})
    Add-SentinelChainedRecords $path $rows
    $original=(Get-FileHash $path).Hash;$checkpoint=Get-SentinelLogCheckpoint $path;$script:HistoryScans=0;$script:ForbidHistoryScan=$true
    function Get-SentinelLogSnapshot{param($Path) $script:HistoryScans++;if($script:ForbidHistoryScan){throw 'Historical parsing blocked a live writer.'};& $realSnapshot $Path}
    try{Invoke-SentinelRetention $root 30}finally{$script:ForbidHistoryScan=$false}
    Assert ($script:HistoryScans -eq 0 -and (Get-Item $path).Length -eq 0) 'Startup retention parsed history or left the old active stream.'
    $index=Read-SentinelSegmentIndex $path (Get-SentinelLogCheckpoint $path)
    $archive=Join-Path (Split-Path $path) $index.Segments[0].Name
    Assert (@($index.Segments).Count -eq 1 -and (Get-FileHash $archive).Hash -eq $original -and $index.Segments[0].LineCount -eq 1500) 'Legacy migration lost or rewrote evidence.'
    Add-SentinelChainedRecord $path ([ordered]@{Type='AfterMigration';Timestamp=[datetimeoffset]::Now.ToString('o')})
    Assert ((Get-SentinelLogVerification $path).Valid -and @(Read-SentinelLogRows $path).Count -eq 1501) 'Writes or verification failed after sealing.'
    Invoke-SentinelRetention $root 30
    $count=@((Read-SentinelSegmentIndex $path (Get-SentinelLogCheckpoint $path)).Segments).Count
    Invoke-SentinelRetention $root 30
    Assert (@((Read-SentinelSegmentIndex $path (Get-SentinelLogCheckpoint $path)).Segments).Count -eq $count) 'An empty stream created repeated segments.'
}
Test 'Periodic sealing retires old prefixes and keeps new active data linked' {
    $path=Fixture 'periodic-sealing'
    Add-SentinelChainedRecord $path ([ordered]@{Type='Old';Timestamp=[datetimeoffset]::Now.AddDays(-45).ToString('o')})
    function Get-SentinelLogUtcNow{return [datetimeoffset]::UtcNow.AddDays(-40)}
    Invoke-SentinelSegmentRetention $path ([datetime]::Now.AddDays(-50)) -SealActive
    $old=Read-SentinelSegmentIndex $path (Get-SentinelLogCheckpoint $path)
    Add-SentinelChainedRecord $path ([ordered]@{Type='New';Timestamp=[datetimeoffset]::Now.ToString('o')})
    function Get-SentinelLogUtcNow{return [datetimeoffset]::UtcNow}
    Invoke-SentinelSegmentRetention $path ([datetime]::Now.AddDays(-30)) -SealActive
    $index=Read-SentinelSegmentIndex $path (Get-SentinelLogCheckpoint $path) -Deep
    Assert ($index.RetiredSequence -eq $old.Segments[0].Sequence -and @($index.Segments).Count -eq 1 -and @(Read-SentinelLogRows $path).Count -eq 1 -and (Get-SentinelLogVerification $path).Valid) 'Periodic retention removed new data or broke the retained anchor.'
}
Test 'An already oversized legacy stream stays visible and intact after verified sealing' {
    $path=Fixture 'legacy-oversize';$root=Split-Path (Split-Path $path)
    $config=Get-Content (Join-Path $repo 'config\Config.json') -Raw | ConvertFrom-Json;$config.Resources.MaxLogFileMB=1
    $rows=@(1..1600 | ForEach-Object {[ordered]@{Type='Legacy';Number=$_;Text=('x'*500);Timestamp=[datetimeoffset]::Now.ToString('o')}})
    Add-SentinelChainedRecords $path $rows
    $hash=(Get-FileHash $path).Hash;$length=(Get-Item $path).Length
    Assert ((Get-SentinelStorageStatus $root $config).OversizeLogs.Count -eq 1) 'Oversized active stream was hidden.'
    Invoke-SentinelRetention $root 30
    $state=Get-SentinelStorageStatus $root $config
    Assert ($state.Healthy -and $state.OversizeLogs.Count -eq 0 -and $state.PreservedOversizeSegments.Count -eq 1 -and $state.LogBytes -eq $length) 'Verified historical oversize was lost or confused with an active oversize.'
    $archive=Join-Path (Split-Path $path) $state.PreservedOversizeSegments[0]
    Assert ((Get-FileHash $archive).Hash -eq $hash -and (Get-SentinelLogVerification $path).Valid) 'Migration truncated or modified the legacy bytes.'
    $config.Resources.MaxTotalLogMB=1
    Assert (-not (Get-SentinelStorageStatus $root $config).Healthy) 'Archived bytes bypassed the total quota.'
    Assert (-not (Write-SentinelJsonLine $path ([ordered]@{Type='MustNotFit'}))) 'Append bypassed aggregate quota.'
    Assert ((Get-FileHash $archive).Hash -eq $hash) 'Capacity pressure deleted legacy evidence.'
    $config.Resources.MaxTotalLogMB=512
    $bytes=[IO.File]::ReadAllBytes($archive);$bytes[50]=$bytes[50] -bxor 1;[IO.File]::WriteAllBytes($archive,$bytes)
    $state=Get-SentinelStorageStatus $root $config
    Assert (-not $state.Healthy -and $state.PreservedOversizeSegments.Count -eq 0 -and $state.OversizeLogs.Count -eq 1) 'Modified archive received a capacity exemption.'
}
Test 'Capacity rotation preserves all records and links immutable segments to the active checkpoint' {
    $path=Fixture 'normal';foreach($i in 1..8){Append $path $i}
    $checkpoint=Get-SentinelLogCheckpoint $path;$index=Read-SentinelSegmentIndex $path $checkpoint -Deep
    Assert (@($index.Segments).Count -gt 0 -and (Get-SentinelLogVerification $path).Valid) 'Rotation failed verification.'
    $rows=@(foreach($file in @(Get-ChildItem (Split-Path $path) -Filter '*.jsonl')){Get-Content $file.FullName | ForEach-Object {$_ | ConvertFrom-Json}})
    Assert ($rows.Count -eq 8 -and @($rows.Number | Sort-Object -Unique).Count -eq 8) 'Rotation lost or duplicated records.'
    $archive=Join-Path (Split-Path $path) $index.Segments[0].Name
    Refused {Append $archive 99}
}
Test 'Missing same-length modified and unindexed segments are rejected by verification' {
    $path=Fixture 'tamper';foreach($i in 1..4){Append $path $i}
    $index=Read-SentinelSegmentIndex $path (Get-SentinelLogCheckpoint $path)
    $archive=Join-Path (Split-Path $path) $index.Segments[0].Name;$bytes=[IO.File]::ReadAllBytes($archive)
    $changed=[byte[]]$bytes.Clone();$changed[50]=$changed[50] -bxor 1;[IO.File]::WriteAllBytes($archive,$changed)
    Assert (-not (Get-SentinelLogVerification $path).Valid) 'Same-length segment mutation was trusted.'
    [IO.File]::WriteAllBytes($archive,$bytes);$hidden=$archive+'.hidden';[IO.File]::Move($archive,$hidden)
    Assert (-not (Get-SentinelLogVerification $path).Valid) 'Missing indexed segment was trusted.'
    [IO.File]::Move($hidden,$archive)
    Copy-Item -LiteralPath $archive -Destination (Join-Path (Split-Path $path) 'events.s999999.jsonl')
    Assert (-not (Get-SentinelLogVerification $path).Valid) 'Unindexed extra segment was trusted.'
}
Test 'Interrupted rotation recovers its immutable archive and active anchor before retrying append' {
    $path=Fixture 'interrupted';Append $path 1;Append $path 2
    $script:FailIndex=$true
    function Write-SentinelAtomicJson{param($Path,$Data) if($Path -like '*.segments.json' -and $script:FailIndex){$script:FailIndex=$false;throw 'Interrupted index commit'};& $realAtomic $Path $Data}
    Refused {Append $path 3}
    Assert (Test-Path ((Get-SentinelChainPath $path)+'.rotate.pending')) 'Rotation recovery plan missing.'
    [void](Get-SentinelLogCheckpoint $path);Append $path 3
    Assert ((Get-SentinelLogVerification $path).Valid -and -not (Test-Path ((Get-SentinelChainPath $path)+'.rotate.pending'))) 'Rotation did not recover.'
    $count=0;foreach($file in @(Get-ChildItem (Split-Path $path) -Filter '*.jsonl')){$count+=@(Get-Content $file.FullName).Count};Assert ($count -eq 3) 'Recovery lost records.'
}
Test 'Aggregate quota and oversize records fail without deleting or overwriting existing evidence' {
    $path=Fixture 'quota';Append $path 1 1200;$before=(Get-FileHash $path).Hash
    Refused {Append $path 2 1200}
    Assert ((Get-FileHash $path).Hash -eq $before) 'Aggregate quota changed existing evidence.'
    Refused {Add-SentinelChainedRecord $path ([ordered]@{Type='Oversize';Text=('y'*3000)}) -MaxFileBytes 1700 -MaxTotalBytes 100000}
    Assert ((Get-FileHash $path).Hash -eq $before) 'Oversize append changed existing evidence.'
}
Test 'Retention retires only old immutable prefixes and preserves a verifiable anchor' {
    $path=Fixture 'retention'
    function Get-SentinelLogUtcNow{return [datetimeoffset]::UtcNow.AddDays(-40)}
    foreach($i in 1..5){Append $path $i}
    $before=Get-SentinelLogCheckpoint $path;$index=Read-SentinelSegmentIndex $path $before
    Assert (@($index.Segments).Count -gt 0) 'Fixture did not rotate.'
    Invoke-SentinelSegmentRetention $path ([datetime]::Now.AddDays(-30))
    $after=Read-SentinelSegmentIndex $path (Get-SentinelLogCheckpoint $path) -Deep
    Assert ($after.RetiredSequence -gt 0 -and @($after.Segments).Count -eq 0 -and (Get-SentinelLogVerification $path).Valid) 'Retired prefix is not anchored.'
    Append $path 6
    Assert (Get-SentinelLogVerification $path).Valid 'Append after retirement broke chain.'
}
Test 'Reparse archive paths are refused without modifying an unrelated target' {
    $path=Fixture 'reparse';foreach($i in 1..4){Append $path $i}
    $index=Read-SentinelSegmentIndex $path (Get-SentinelLogCheckpoint $path);$archive=Join-Path (Split-Path $path) $index.Segments[0].Name
    $target=Join-Path $ScratchRoot 'unrelated';New-Item -ItemType Directory -Path $target | Out-Null
    $indexPath=(Get-SentinelChainPath $path)+'.segments.json';$before=(Get-FileHash $indexPath).Hash
    # A directory at a segment path is also invalid; creating a file symlink
    # is intentionally unnecessary for a non-elevated Windows test run.
    [IO.File]::Move($archive,($archive+'.saved'));New-Item -ItemType Junction -Path $archive -Target $target | Out-Null
    Refused {Append $path 5}
    Assert ((Get-FileHash $indexPath).Hash -eq $before -and @(Get-ChildItem $target).Count -eq 0) 'Unsafe archive path changed data.'
}
Test 'Concurrent rotation and legacy retention entry point preserve every new record' {
    $root=Join-Path $ScratchRoot 'concurrent';New-Item -ItemType Directory -Path (Join-Path $root 'logs') | Out-Null
    foreach($n in 0..3){Add-SentinelChainedRecord (Join-Path $root ('logs\concurrent'+$n+'.jsonl')) ([ordered]@{Type='Old';Timestamp=[datetimeoffset]::Now.AddDays(-60).ToString('o')})}
    $children=@()
    try{
        foreach($role in @('Writer','Writer','Retention')){
            $id=$children.Count;$command="& '{0}' -PackageRoot '{1}' -ScratchRoot '{2}' -Role '{3}' -WriterId {4} -MaxSegmentBytes 1700 -SegmentRetention" -f (Join-Path $PSScriptRoot 'ConcurrentLogProbe.ps1').Replace("'","''"),$repo.Replace("'","''"),$root.Replace("'","''"),$role,$id
            $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe';$info.Arguments='-NoProfile -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command));$info.UseShellExecute=$false;$info.CreateNoWindow=$true
            $children+=@([Diagnostics.Process]::Start($info))
        }
        foreach($child in $children){if(-not $child.WaitForExit(90000)){throw 'Concurrent rotation timed out.'};Assert ($child.ExitCode -eq 0) 'Concurrent writer/retention failed.'}
        foreach($n in 0..3){$path=Join-Path $root ('logs\concurrent'+$n+'.jsonl');$rows=@(Read-SentinelLogRows $path | Where-Object Type -eq 'Probe');Assert ($rows.Count -eq 24 -and @($rows | Group-Object Writer,Number).Count -eq 24 -and (Get-SentinelLogVerification $path).Valid) 'Concurrent rotation lost records or anchors.'}
    }finally{foreach($child in $children){if(-not $child.HasExited){$child.Kill();$child.WaitForExit()};$child.Dispose()}}
}
Test 'A reparse checkpoint directory cannot redirect a new stream transaction' {
    $path=Fixture 'checkpoint-reparse';$root=Split-Path (Split-Path $path);$target=Join-Path $ScratchRoot 'checkpoint-unrelated'
    New-Item -ItemType Directory -Path (Join-Path $root 'state'),$target -Force | Out-Null
    New-Item -ItemType Junction -Path (Join-Path $root 'state\log-chain') -Target $target | Out-Null
    Refused {Append $path 1}
    Assert (@(Get-ChildItem -LiteralPath $target).Count -eq 0 -and -not (Test-Path -LiteralPath $path)) 'Checkpoint junction changed unrelated data.'
}
Test 'Snapshot and bounded readers include immutable segments and bind their index in the external manifest' {
    $path=Fixture 'snapshot';foreach($i in 1..8){Append $path $i}
    $root=Split-Path (Split-Path $path);$stage=Join-Path $ScratchRoot 'snapshot-copy'
    $entries=@(Copy-SentinelLogSnapshot $root $stage);$copy=Join-Path $stage 'logs\events.jsonl'
    Assert ((Get-SentinelLogVerification $copy).Valid -and @(Read-SentinelLogRows $copy).Count -eq 8) 'Snapshot lost archived records.'
    $tail=@(Read-SentinelLogRows $copy -Tail 3)
    Assert (($tail.Number -join ',') -eq '6,7,8') 'Bounded reader did not cross segment boundaries in order.'
    $active=@($entries | Where-Object Name -eq 'events.jsonl')[0]
    Assert ($active.SegmentIndexSHA256 -eq (Get-FileHash ((Get-SentinelChainPath $copy)+'.segments.json')).Hash) 'External manifest omitted index identity.'
    $indexPath=(Get-SentinelChainPath $path)+'.rotate.pending';Write-SentinelAtomicJson $indexPath @{Schema=0}
    $before=(Get-FileHash $indexPath).Hash
    Refused {Copy-SentinelLogSnapshot $root (Join-Path $ScratchRoot 'pending-copy')}
    Assert ((Get-FileHash $indexPath).Hash -eq $before) 'Read-only export repaired a pending rotation.'
}
Test 'Retirement resumes after its index commit without losing the retained chain' {
    $path=Fixture 'retirement-interrupted'
    function Get-SentinelLogUtcNow{return [datetimeoffset]::UtcNow.AddDays(-40)}
    foreach($i in 1..5){Append $path $i}
    $script:FailRetirement=$true
    function Write-SentinelAtomicJson{param($Path,$Data) & $realAtomic $Path $Data;if($Path -like '*.segments.json' -and $Data.RetiredSequence -gt 0 -and $script:FailRetirement){$script:FailRetirement=$false;throw 'Interrupted after retirement commit'}}
    Refused {Invoke-SentinelSegmentRetention $path ([datetime]::Now.AddDays(-30))}
    Assert (Test-Path ((Get-SentinelChainPath $path)+'.retire.pending')) 'Retirement recovery plan missing.'
    [void](Get-SentinelLogCheckpoint $path)
    Assert ((Get-SentinelLogVerification $path).Valid -and -not (Test-Path ((Get-SentinelChainPath $path)+'.retire.pending'))) 'Committed retirement did not recover.'
    Append $path 6;Assert (Get-SentinelLogVerification $path).Valid 'Post-recovery append broke anchor.'
}
Test 'Malformed retirement plans cannot delete a segment or rewrite its index' {
    $path=Fixture 'bad-retirement';foreach($i in 1..5){Append $path $i}
    $before=Read-SentinelSegmentIndex $path (Get-SentinelLogCheckpoint $path);$indexPath=(Get-SentinelChainPath $path)+'.segments.json';$hash=(Get-FileHash $indexPath).Hash
    $archive=Join-Path (Split-Path $path) $before.Segments[0].Name;$archiveHash=(Get-FileHash $archive).Hash
    $after=$before | ConvertTo-Json -Depth 20 | ConvertFrom-Json;$after.Segments=@();$after.RetiredSequence=$before.Segments[-1].Sequence;$after.RetiredHash=$before.Segments[-1].LastHash
    Write-SentinelAtomicJson ((Get-SentinelChainPath $path)+'.retire.pending') @{Schema=1;Stream='events.jsonl';IndexBefore=$before;IndexAfter=$after;Removed=@($before.Segments[-1])}
    Refused {Get-SentinelLogCheckpoint $path}
    Assert ((Get-FileHash $indexPath).Hash -eq $hash -and (Get-FileHash $archive).Hash -eq $archiveHash) 'Invalid transaction changed retained evidence.'
}
$results.ToArray() | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $ScratchRoot 'test-results.json') -Encoding UTF8
$failed=@($results | Where-Object {-not $_.Passed}).Count
Write-Host ('Log rotation tests: '+($results.Count-$failed)+'/'+$results.Count+' passed.')
if($failed){exit 1}
