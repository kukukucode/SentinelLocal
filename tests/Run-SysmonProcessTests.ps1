param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-sysmon-process-'+[guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'src\Common.ps1')
. (Join-Path $repo 'src\SysmonMonitoring.ps1')
. (Join-Path $repo 'tools\sysmon\SysmonSetup.ps1')
. (Join-Path $repo 'tools\evaluation\DurableObservation.ps1')
if(Test-Path $ScratchRoot){throw 'Scratch directory already exists.'}
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$results=[Collections.Generic.List[object]]::new()
$realWrite=${function:Write-SentinelJsonLine}
function Assert([bool]$Value,[string]$Message){if(-not $Value){throw $Message}}
function Test([string]$Name,[scriptblock]$Body){
    try {& $Body;$results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'});Write-Host ('PASS '+$Name)}
    catch {$results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message});Write-Host ('FAIL '+$Name+': '+$_.Exception.Message)}
}
function Refused([scriptblock]$Body){$failed=$false;try {& $Body | Out-Null}catch{$failed=$true};Assert $failed 'Unsafe operation was accepted'}
function Fixture([string]$Name){$root=Join-Path $ScratchRoot $Name;New-Item -ItemType Directory -Path $root | Out-Null;return $root}
function Event([int]$Id,[long]$Record,$Data){
    $xml='<Event><EventData>'+(@($Data.Keys | ForEach-Object {'<Data Name="'+$_+'">'+[Security.SecurityElement]::Escape([string]$Data[$_])+'</Data>'}) -join '')+'</EventData></Event>'
    $e=[pscustomobject]@{Id=$Id;RecordId=$Record;TimeCreated=[datetime]'2026-10-03T00:00:00Z';Xml=$xml}
    $e | Add-Member ScriptMethod ToXml {$this.Xml};return $e
}
function Get-FixtureData([int]$Number){
    @{ProcessId=(1000+$Number);ParentProcessId=999;Image='C:\Deleted\short.exe';CommandLine='"C:\Deleted\short.exe" inert-argument';UtcTime='2026-10-03 00:00:00.123';ProcessGuid=('{00000000-0000-0000-0000-'+$Number.ToString('000000000000')+'}');ParentProcessGuid='{00000000-0000-0000-0000-999999999999}';Hashes=('SHA256='+('A'*64))}
}
$config=Get-Content (Join-Path $repo 'config\Config.json') -Raw | ConvertFrom-Json;$config.Sysmon.Enabled=$true
function Get-SentinelEventBatch {param($LogName,$Cursor,$CursorTime,$Ids,$BatchSize) $script:Batch}
function Get-CimInstance {throw 'Recorded metadata must not query a live/reused PID.'}
Test 'Exited processes retain recorded identity command line birth time GUID and SHA256' {
    $root=Fixture 'exited';$script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 1 1 (Get-FixtureData 1)),(Event 1 2 (Get-FixtureData 2)),(Event 1 3 (Get-FixtureData 3)))}
    Read-SentinelSysmon $root $config {param($process) [pscustomobject]@{Score=0;Reasons=@()}} {throw 'Zero score must not queue a response'}
    $rows=@(Get-Content (Join-Path $root 'logs\process-events.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
    Assert ($rows.Count -eq 3 -and @($rows | Where-Object {-not $_.MetadataComplete}).Count -eq 0) 'Lost creation metadata'
    foreach($row in $rows){Assert ($row.Process.CommandLine -eq '"C:\Deleted\short.exe" inert-argument' -and $row.Process.ObservedSHA256 -eq ('A'*64) -and -not $row.Process.LiveIdentityVerified) 'Recorded identity changed or was claimed live'}
    Assert (Get-SentinelLogVerification (Join-Path $root 'logs\process-events.jsonl')).Valid 'Process evidence chain invalid'
    $cache=Get-Content (Join-Path $root 'state\sysmon-correlations.json') -Raw | ConvertFrom-Json
    Assert (@($cache.Processes).Count -eq 0) 'Benign zero-score processes expanded correlation state'
}
Test 'Slow Sysmon batches yield after durable events and resume without skipping the remaining backlog' {
    $root=Fixture 'bounded-batch';$script:FakeTick=0
    $events=@((Event 1 1 (Get-FixtureData 1)),(Event 1 2 (Get-FixtureData 2)),(Event 1 3 (Get-FixtureData 3)))
    function Get-SentinelSysmonMonotonicSeconds{return $script:FakeTick}
    function Get-SentinelEventBatch{param($LogName,$Cursor,$CursorTime,$Ids,$BatchSize) [pscustomobject]@{Reset=$false;Events=@($events | Where-Object {$_.RecordId -gt $Cursor})}}
    $score={param($process) $script:FakeTick+=6;[pscustomobject]@{Score=0;Reasons=@()}}
    Read-SentinelSysmon $root $config $score {throw 'Must not queue'}
    $cursor=Get-Content (Join-Path $root 'state\sysmon-cursor.json') -Raw | ConvertFrom-Json
    $rows=@(Get-Content (Join-Path $root 'logs\process-events.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
    Assert ($cursor.RecordId -eq 2 -and $rows.Count -eq 2) 'Slow batch failed to yield at a durable boundary.'
    Read-SentinelSysmon $root $config $score {throw 'Must not queue'}
    $cursor=Get-Content (Join-Path $root 'state\sysmon-cursor.json') -Raw | ConvertFrom-Json
    $rows=@(Get-Content (Join-Path $root 'logs\process-events.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
    Assert ($cursor.RecordId -eq 3 -and $rows.Count -eq 3 -and @($rows.RecordId | Sort-Object -Unique).Count -eq 3) 'Resuming duplicated or skipped source events.'
    Assert (Get-SentinelLogVerification (Join-Path $root 'logs\process-events.jsonl')).Valid 'Yield damaged the evidence chain.'
    Refused {Read-SentinelSysmon $root $config $score {} -MaximumProcessingSeconds 0}
}
Test 'Durable observation requires all identities and rejects PID reuse hash changes and ambiguous events' {
    $root=Join-Path $ScratchRoot 'exited'
    $rows=@(Get-Content (Join-Path $root 'logs\process-events.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
    $trials=@($rows | ForEach-Object {[pscustomobject]@{Id=[string]$_.RecordId;ProcessId=$_.Process.ProcessId;ExecutablePath=$_.Process.ExecutablePath;SHA256=$_.Process.ObservedSHA256;ProcessCreatedAt=$_.Process.CreationDate;Arguments='inert-argument'}})
    $packet=[pscustomobject]@{Kind='BenignObservationPacket';CommandsSucceeded=$true;Root=$root;Trials=$trials}
    $report=Get-SentinelDurableObservation $packet
    Assert ($report.Complete -and $report.CapturedCount -eq 3 -and -not $report.PerformanceMeasured -and $report.ReviewRequired) 'Capture became performance data or lost identity.'
    $trials[0].SHA256='B'*64
    Assert (-not (Compare-SentinelDurableObservation $packet $rows).Complete) 'Changed hash accepted.'
    $trials[0].SHA256='A'*64;$trials[0].ProcessCreatedAt='2026-10-03T00:00:01.123Z'
    Assert (-not (Compare-SentinelDurableObservation $packet $rows).Complete) 'Reused PID at another creation time accepted.'
    $trials[0].ProcessCreatedAt=$rows[0].Process.CreationDate
    Assert (-not (Compare-SentinelDurableObservation $packet (@($rows)+@($rows[0]))).Complete) 'Ambiguous events accepted.'
    $packet.CommandsSucceeded=$false;Refused {Compare-SentinelDurableObservation $packet $rows}
}
Test 'Queue failure leaves durable creation retryable and keeps recorded SHA256' {
    $root=Fixture 'retry';$script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 1 1 (Get-FixtureData 1)))}
    Refused {Read-SentinelSysmon $root $config {param($p) [pscustomobject]@{Score=80;Reasons=@('fixture')}} {throw 'Queue unavailable'}}
    Assert (-not (Test-Path (Join-Path $root 'state\sysmon-cursor.json'))) 'Failed queue advanced the cursor'
    $script:Queued=$null
    Read-SentinelSysmon $root $config {param($p) [pscustomobject]@{Score=80;Reasons=@('fixture')}} {param($path,$id,$score,$p) $script:Queued=$p}
    Assert ($script:Queued.ObservedSHA256 -eq ('A'*64) -and $script:Queued.ProcessGuid -eq (Get-FixtureData 1).ProcessGuid) 'Replay lost original observation'
    Assert ((Get-Content (Join-Path $root 'state\sysmon-cursor.json') -Raw | ConvertFrom-Json).RecordId -eq 1) 'Successful replay did not commit'
}
Test 'Failed process evidence persistence never acknowledges the event' {
    $root=Fixture 'write-failure';$script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 1 1 (Get-FixtureData 1)))}
    function Write-SentinelJsonLine {param($Path,$Data) if($Path -like '*process-events.jsonl'){return $false};& $realWrite $Path $Data}
    Refused {Read-SentinelSysmon $root $config {throw 'Must not score without evidence'} {throw 'Must not queue'}}
    Assert (-not (Test-Path (Join-Path $root 'state\sysmon-cursor.json'))) 'Evidence failure advanced cursor'
}
Test 'Missing command line/hash is explicitly incomplete and provider errors stay visible' {
    $root=Fixture 'incomplete';$d=Get-FixtureData 1;$d.CommandLine='';$d.Hashes='SHA1=1234'
    $script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 1 1 $d),(Event 255 2 @{ID='fixture';Description='lost events'}))}
    Read-SentinelSysmon $root $config {param($p) [pscustomobject]@{Score=0;Reasons=@()}} {throw 'Unexpected response'}
    $record=Get-Content (Join-Path $root 'logs\process-events.jsonl') | ConvertFrom-Json
    Assert (-not $record.MetadataComplete) 'Missing fields counted as complete'
    $alerts=@(Get-Content (Join-Path $root 'logs\alerts.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
    Assert (@($alerts | Where-Object {$_.Type -eq 'SysmonTelemetryError' -and $_.Severity -eq 'HIGH'}).Count -eq 1) 'Provider loss was silent'
}
Test 'Sysmon mode skips volatile CIM registration and unavailable source fails closed' {
    $script:Registrations=0;$script:Running=$true;$script:ChannelEnabled=$true
    function Register-CimIndicationEvent {param($Query,$SourceIdentifier) $script:Registrations++}
    function Get-Service {param($Name) if($script:Running){[pscustomobject]@{Status='Running'}}}
    function Get-WinEvent {param($ListLog) [pscustomobject]@{IsEnabled=$script:ChannelEnabled}}
    Assert ((Initialize-SentinelProcessMonitor $config) -eq 'Sysmon' -and $script:Registrations -eq 0) 'Sysmon also subscribed to volatile events'
    $script:Running=$false;Refused {Initialize-SentinelProcessMonitor $config}
    $script:Running=$true;$script:ChannelEnabled=$false;Refused {Initialize-SentinelProcessMonitor $config}
    $config.Sysmon.Enabled=$false
    Assert ((Initialize-SentinelProcessMonitor $config) -eq 'CIM' -and $script:Registrations -eq 1) 'Explicit disabled mode did not subscribe'
    $config.Sysmon.Enabled=$true
}
Test 'Sysmon provisioning rejects an absent pin changed bytes and other Microsoft products' {
    $exe=Join-Path $env:WINDIR 'System32\cmd.exe';$hash=(Get-FileHash $exe).Hash
    Refused {Assert-SentinelSysmonBinary $exe ''}
    Refused {Assert-SentinelSysmonBinary $exe ('0'*64)}
    Refused {Assert-SentinelSysmonBinary $exe $hash}
    [xml]$xml=Get-SentinelSysmonConfiguration
    Assert ($xml.Sysmon.HashAlgorithms -eq 'SHA256' -and $xml.Sysmon.EventFiltering.ProcessCreate.onmatch -eq 'exclude' -and -not $xml.Sysmon.EventFiltering.ProcessCreate.HasChildNodes) 'Process collection filters or SHA256 changed'
}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ScratchRoot 'test-results.json') -Encoding UTF8
$failed=@($results | Where-Object {-not $_.Passed}).Count
Write-Host ('Sysmon process tests: '+($results.Count-$failed)+'/'+$results.Count+' passed')
if($failed){exit 1}else{exit 0}
