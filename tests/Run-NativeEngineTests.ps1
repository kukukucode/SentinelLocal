param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-native-tests-'+[guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'src\Common.ps1')
if(Test-Path $ScratchRoot){throw 'Scratch directory exists.'}
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$results=[Collections.Generic.List[object]]::new()
function Assert([bool]$Value,[string]$Message){if(-not $Value){throw $Message}}
function Test([string]$Name,[scriptblock]$Body){try{& $Body;$results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'});Write-Host ('PASS '+$Name)}catch{$results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message});Write-Host ('FAIL '+$Name+': '+$_.Exception.Message)}}
function Refused([scriptblock]$Body){$failed=$false;try{& $Body | Out-Null}catch{$failed=$true};Assert $failed 'Invalid state was silently accepted.'}
function Fixture([string]$Name){$path=Join-Path $ScratchRoot $Name;New-Item -ItemType Directory -Path $path | Out-Null;return $path}
function ChainFile([string]$Path,[object[]]$Rows){
    $last='GENESIS';$lines=[Collections.Generic.List[string]]::new()
    foreach($row in $Rows){$payload=$row | ConvertTo-Json -Compress -Depth 14;$hash=Get-SentinelStringHash ($last+"`n"+$payload);$record=[ordered]@{};foreach($key in $row.Keys){$record[$key]=$row[$key]};$record._ChainAlg='SHA256';$record._ChainPrev=$last;$record._ChainHash=$hash;$lines.Add(($record | ConvertTo-Json -Compress -Depth 14));$last=$hash}
    [IO.File]::WriteAllLines($Path,$lines,[Text.UTF8Encoding]::new($false))
}
Test 'Missing flat DLL cannot redirect loading into an adjacent native directory' {
    $root=Fixture 'loader-flat';$beforeDirectory=$script:SentinelNativeCodeDirectory;$beforeLoaded=$script:SentinelNativeLoaded
    try{$script:SentinelNativeCodeDirectory=$root;$script:SentinelNativeLoaded=$false;Refused {Initialize-SentinelNative}}
    finally{$script:SentinelNativeCodeDirectory=$beforeDirectory;$script:SentinelNativeLoaded=$beforeLoaded}
}
Test 'DLL bytes must match pinned metadata before execution' {
    $root=Fixture 'loader-hash';Copy-Item (Join-Path $repo 'native\bin\sentinel_engine.dll') $root
    $info=Get-Content (Join-Path $repo 'native\bin\sentinel-engine.json') -Raw | ConvertFrom-Json;$info.SHA256='0'*64
    Write-SentinelAtomicJson (Join-Path $root 'sentinel-engine.json') $info
    $beforeDirectory=$script:SentinelNativeCodeDirectory;$beforeLoaded=$script:SentinelNativeLoaded
    try{$script:SentinelNativeCodeDirectory=$root;$script:SentinelNativeLoaded=$false;Refused {Initialize-SentinelNative}}
    finally{$script:SentinelNativeCodeDirectory=$beforeDirectory;$script:SentinelNativeLoaded=$beforeLoaded}
}
Test 'PS5 canonical parity includes control characters Unicode HTML and compatibility numbers' {
    $root=Fixture 'canonical';$path=Join-Path $root 'process-events.jsonl'
    $text='日本語😀 <>&'''+(-join (0..31 | ForEach-Object {[char]$_}))+[char]0x85+[char]0x2028+[char]0x2029
    ChainFile $path @([ordered]@{Text=$text;Array=@(1,$true,$null,'x');Nested=[ordered]@{Key='value'}},[ordered]@{Decimal=1.25;Exponent=1e20;日本語='compatibility'})
    $native=Get-SentinelNativeLogScan $path;$legacy=Get-SentinelLegacyLogSnapshot $path
    foreach($key in @('LineCount','ByteLength','FirstPreviousHash','LastHash')){Assert ($native.$key -ceq $legacy.$key) ('Canonical mismatch: '+$key)}
    Assert ($native.CanonicalValidationComplete -and $native.SHA256 -ceq (Get-FileHash $path).Hash) 'Compatibility validation was skipped.'
}
Test 'Cached proofs rehash actual bytes and reject same-length tampering' {
    $root=Fixture 'tampering';$path=Join-Path $root 'alerts.jsonl';ChainFile $path @([ordered]@{Text='AAA'})
    [void](Get-SentinelNativeLogScan $path);$stamp=(Get-Item $path).LastWriteTimeUtc
    $bytes=[IO.File]::ReadAllText($path).Replace('AAA','BBB');[IO.File]::WriteAllText($path,$bytes,[Text.UTF8Encoding]::new($false));(Get-Item $path).LastWriteTimeUtc=$stamp
    Refused {Get-SentinelNativeLogScan $path}
}
Test 'Interior BOM and empty chain predecessor cannot establish a valid snapshot' {
    $root=Fixture 'invalid-boundary';$path=Join-Path $root 'alerts.jsonl';ChainFile $path @([ordered]@{Text='A'},[ordered]@{Text='B'})
    $lines=[IO.File]::ReadAllLines($path);$lines[1]=[char]0xFEFF+$lines[1];[IO.File]::WriteAllLines($path,$lines,[Text.UTF8Encoding]::new($false))
    Refused {Get-SentinelNativeLogScan $path}
    $payload='{"Text":"A"}';$hash=Get-SentinelStringHash ("`n"+$payload)
    [IO.File]::WriteAllText($path,('{"Text":"A","_ChainAlg":"SHA256","_ChainPrev":"","_ChainHash":"'+$hash+'"}'),[Text.UTF8Encoding]::new($false))
    Refused {Get-SentinelNativeLogScan $path}
}
Test 'Streaming capture matches full rows without trusting PID alone and reports synthetic timing' {
    $root=Fixture 'stream';$path=Join-Path $root 'process-events.jsonl';$now=[datetimeoffset]::Now
    $rows=@(for($i=0;$i -lt 3000;$i++){[ordered]@{Timestamp=$now.AddSeconds($i-3000).ToString('o');Type='ProcessCreated';Source='Sysmon';MetadataComplete=$true;Process=[ordered]@{ProcessId=(1000+$i);CreationDate=$now.ToString('o');CommandLine='synthetic'}}})
    ChainFile $path $rows
    $script:SentinelBenchmarkCapture=@{start=$now.AddSeconds(-40).ToString('o');end=$now.ToString('o');pids=@(3990,3991)}
    try{
        $timer=[Diagnostics.Stopwatch]::StartNew();$legacy=Get-SentinelLegacyLogSnapshot $path;$timer.Stop();$legacySeconds=$timer.Elapsed.TotalSeconds
        $timer.Restart();$native=Get-SentinelNativeLogScan $path;$timer.Stop();$nativeSeconds=$timer.Elapsed.TotalSeconds
        Assert ($native.LineCount -eq 3000 -and $native.LastHash -ceq $legacy.LastHash -and @($native.Rows).Count -eq 2) 'Streaming selection or chain differs.'
        $copy=Join-Path $root 'process-events.copy.jsonl';Copy-Item $path $copy
        Assert (@((Get-SentinelNativeLogScan $copy).Rows).Count -eq 2) 'Digest-bound proof reuse lost captured records.'
        $script:SentinelBenchmarkCapture=@{start=$now.AddDays(1).ToString('o');end=$now.AddDays(2).ToString('o');pids=@(3990)}
        Assert (@((Get-SentinelNativeLogScan $path).Rows).Count -eq 0) 'Time-range proof included an unrelated window.'
        [ordered]@{Synthetic=$true;Rows=3000;LegacySeconds=$legacySeconds;NativeSeconds=$nativeSeconds;Scope='CI fixture only; not end-to-end or real-PC timing'} | ConvertTo-Json | Set-Content (Join-Path $ScratchRoot 'synthetic-timing.json') -Encoding UTF8
        Write-Host ('Synthetic scan seconds: legacy='+$legacySeconds+'; native='+$nativeSeconds)
    }finally{$script:SentinelBenchmarkCapture=$null}
}
Test 'Queue catalog matches legacy after partial acknowledgement and refuses stale progress' {
    $root=Fixture 'queue';$directory=Join-Path $root 'state\sysmon-analysis\pending';New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $path=Join-Path $directory '00000000000000000001-AAAAAAAAAAAAAAAAAAAAAAAA.json';$now=[datetimeoffset]::Now.ToString('o')
    $unit=[ordered]@{Schema=1;Reset=$false;NextIndex=0;QueuedAt=$now;Events=@([ordered]@{Id=1;RecordId=1;TimeCreated=$now;Xml='<Event/>'},[ordered]@{Id=22;RecordId=2;TimeCreated=$now;Xml='<Event/>'})}
    Write-SentinelAtomicJson $path $unit
    Write-SentinelAtomicJson ($path+'.progress') ([ordered]@{Schema=1;UnitName=[IO.Path]::GetFileName($path);PayloadSHA256=(Get-FileHash $path).Hash;EventCount=2;NextIndex=1})
    $native=Get-SentinelSysmonQueueState $root;$legacy=Get-SentinelLegacySysmonQueueState $root
    foreach($key in @('PendingEvents','Units','Bytes')){Assert ($native.$key -eq $legacy.$key) ('Queue differs: '+$key)}
    Assert ([datetimeoffset]$native.OldestEventAt -eq $legacy.OldestEventAt) 'Oldest event differs.'
    $unit.Events[0].RecordId=9;Write-SentinelAtomicJson $path $unit;Refused {Get-SentinelSysmonQueueState $root}
}
Test 'Scheduler matches legacy priority aging delayed requests and malformed request handling' {
    $root=Fixture 'scheduler';foreach($lane in @('high','normal')){New-Item -ItemType Directory -Path (Join-Path $root $lane) | Out-Null}
    $config=Get-Content (Join-Path $repo 'config\Config.json') -Raw | ConvertFrom-Json
    Write-SentinelAtomicJson (Join-Path $root 'high\a.json') @{QueuedAt=[datetimeoffset]::Now.AddHours(-1).ToString('o');AvailableAfter=[datetimeoffset]::Now.AddHours(1).ToString('o')}
    Write-SentinelAtomicJson (Join-Path $root 'high\b.json') @{QueuedAt=[datetimeoffset]::Now.ToString('o')}
    Write-SentinelAtomicJson (Join-Path $root 'normal\a.json') @{QueuedAt=[datetimeoffset]::Now.AddHours(-1).ToString('o')}
    foreach($burst in @(0,([int]$config.Scheduling.HighBurstLimit))){Assert ((Get-SentinelEligibleQueueFile $root $config $burst).FullName -ceq (Get-SentinelLegacyEligibleQueueFile $root $config $burst).FullName) 'Scheduler ordering differs.'}
    [IO.File]::WriteAllText((Join-Path $root 'high\b.json'),'broken')
    Assert ((Get-SentinelEligibleQueueFile $root $config 0).FullName -ceq (Get-SentinelLegacyEligibleQueueFile $root $config 0).FullName) 'Malformed request was hidden.'
}
Test 'Dedupe journal imports PS5 UTF8 BOM state appends and reopens durable keys' {
    $root=Fixture 'dedupe';$path=Join-Path $root 'dedupe.json';$now=[datetimeoffset]::Now.ToString('o')
    @([ordered]@{Key='legacy';LastQueued=$now;Score=40}) | ConvertTo-Json | Set-Content $path -Encoding UTF8
    $opened=Invoke-SentinelNative @{op='journal_open';path=$path;mode='path';now=$now;max_age=3600}
    Assert (@($opened.Rows).Count -eq 1) 'Legacy key not imported.'
    [void](Invoke-SentinelNative @{op='journal_put';path=$path;key='new';at=$now;score=60;now=$now;max_age=3600})
    $reopened=Invoke-SentinelNative @{op='journal_open';path=$path;mode='path';now=$now;max_age=3600}
    Assert (@($reopened.Rows).Count -eq 2 -and (Get-Content $path -Raw) -notmatch '"new"') 'Delta was not recovered from the durable WAL.'
    Add-Content ($path+'.wal') '{partial' -Encoding UTF8;Refused {Invoke-SentinelNative @{op='journal_open';path=$path;mode='path';now=$now;max_age=3600}}
}
$results.ToArray() | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $ScratchRoot 'test-results.json') -Encoding UTF8
$failed=@($results | Where-Object {-not $_.Passed}).Count
Write-Host ('Native integration tests: '+($results.Count-$failed)+'/'+$results.Count+' passed.')
if($failed){exit 1}
