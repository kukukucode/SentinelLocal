param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-ingestion-tests-'+[guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'src\Common.ps1')
if(Test-Path $ScratchRoot){throw 'Scratch directory exists.'}
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$results=[Collections.Generic.List[object]]::new()
function Assert([bool]$Value,[string]$Message){if(-not $Value){throw $Message}}
function Test([string]$Name,[scriptblock]$Body){try{& $Body;$results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'});Write-Host ('PASS '+$Name)}catch{$results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message});Write-Host ('FAIL '+$Name+': '+$_.Exception.Message)}}
function Refused([scriptblock]$Body){$failed=$false;try{& $Body | Out-Null}catch{$failed=$true};Assert $failed 'Failure was silently acknowledged.'}
function Fixture([string]$Name){$path=Join-Path $ScratchRoot $Name;New-Item -ItemType Directory -Path $path | Out-Null;return $path}
$config=Get-Content (Join-Path $repo 'config\Config.json') -Raw | ConvertFrom-Json;$config.Sysmon.Enabled=$true
function Event([long]$Number,[datetime]$Time=([datetime]::Now)){
    $data=@{ProcessId=(1000+$Number);ParentProcessId=99;Image='C:\Deleted\fixture.exe';CommandLine='C:\Deleted\fixture.exe fixture';UtcTime=$Time.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff');ProcessGuid=('guid-'+$Number);ParentProcessGuid='parent';Hashes=('SHA256='+('A'*64))}
    $xml='<Event><EventData>'+(@($data.Keys | ForEach-Object {'<Data Name="'+$_+'">'+[Security.SecurityElement]::Escape([string]$data[$_])+'</Data>'}) -join '')+'</EventData></Event>'
    $event=[pscustomobject]@{Id=1;RecordId=$Number;TimeCreated=$Time;Xml=$xml};$event | Add-Member ScriptMethod ToXml {$this.Xml};return $event
}
function Get-SentinelEventBatch{param($LogName,$Cursor,$CursorTime,$Ids,$BatchSize) if($script:SourceError){throw 'Source unavailable'};return $script:Batch}
function Get-SentinelSysmonSourceState{[pscustomobject]@{Running=(-not $script:SourceStopped);ChannelEnabled=$true}}
Test 'Thirty process identities are durable before any signature scoring or response evaluation' {
    $root=Fixture 'capture';$script:Batch=[pscustomobject]@{Reset=$false;Events=@(1..30 | ForEach-Object {Event $_})}
    $timer=[Diagnostics.Stopwatch]::StartNew();Receive-SentinelSysmonBatch $root $config;$timer.Stop()
    $rows=@(Get-Content (Join-Path $root 'logs\process-events.jsonl') | ForEach-Object {$_ | ConvertFrom-Json})
    Assert ($rows.Count -eq 30 -and @($rows | Where-Object {-not $_.MetadataComplete}).Count -eq 0) 'Fast capture lost metadata.'
    Assert ((Get-SentinelSysmonQueueState $root).PendingEvents -eq 30) 'Evaluation work is not durable.'
    Assert ((Get-Content (Join-Path $root 'state\sysmon-cursor.json') -Raw | ConvertFrom-Json).RecordId -eq 30) 'Source cursor not committed after durable work.'
    Assert (Get-SentinelLogVerification (Join-Path $root 'logs\process-events.jsonl')).Valid 'Batch chain invalid.'
    Write-Host ('Synthetic acquisition seconds: '+$timer.Elapsed.TotalSeconds+'; not a real-PC performance result.')
}
Test 'Deferred analysis survives a response failure without deleting pending work or original content identity' {
    $root=Fixture 'analysis';$script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 1))};Receive-SentinelSysmonBatch $root $config
    Refused {Invoke-SentinelPendingSysmonAnalysis $root $config {param($p) [pscustomobject]@{Score=80;Reasons=@('fixture')}} {throw 'Response queue unavailable'}}
    Assert ((Get-SentinelSysmonQueueState $root).PendingEvents -eq 1) 'Failed evaluation vanished.'
    $script:Observed=$null
    [void](Invoke-SentinelPendingSysmonAnalysis $root $config {param($p) [pscustomobject]@{Score=80;Reasons=@('fixture')}} {param($path,$id,$score,$observed) $script:Observed=$observed})
    Assert ($script:Observed.ObservedSHA256 -eq ('A'*64) -and $script:Observed.ProcessGuid -eq 'guid-1') 'Deferred identity changed.'
    Assert ((Get-SentinelSysmonQueueState $root).PendingEvents -eq 0) 'Completed analysis did not drain.'
    Assert (@(Get-Content (Join-Path $root 'logs\process-events.jsonl')).Count -eq 1) 'Analysis duplicated acquisition records.'
}
Test 'Evidence failure and bounded evaluation capacity retain the source cursor' {
    $root=Fixture 'capacity';$script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 1),(Event 2),(Event 3))}
    $small=$config | ConvertTo-Json -Depth 20 | ConvertFrom-Json;$small.Resources.MaxQueueCount=2
    Refused {Receive-SentinelSysmonBatch $root $small}
    Assert (-not (Test-Path (Join-Path $root 'state\sysmon-cursor.json'))) 'Overflow acknowledged source.'
    function Write-SentinelJsonBatch{param($Path,$Data) return $false}
    Refused {Receive-SentinelSysmonBatch $root $config}
    Assert (-not (Test-Path (Join-Path $root 'state\sysmon-cursor.json')) -and (Get-SentinelSysmonQueueState $root).PendingEvents -eq 0) 'Evidence failure acknowledged or published work.'
}
Test 'Source log resets preserve FIFO evaluation order instead of sorting new record IDs ahead of old work' {
    $root=Fixture 'reset-order';$script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 500))};Receive-SentinelSysmonBatch $root $config
    $script:Batch=[pscustomobject]@{Reset=$true;Events=@((Event 1))};Receive-SentinelSysmonBatch $root $config
    $script:Order=[Collections.Generic.List[int]]::new()
    $score={param($p) $script:Order.Add([int]$p.ProcessId);[pscustomobject]@{Score=0;Reasons=@()}}
    [void](Invoke-SentinelPendingSysmonAnalysis $root $config $score {})
    [void](Invoke-SentinelPendingSysmonAnalysis $root $config $score {})
    Assert ($script:Order.Count -eq 2 -and $script:Order[0] -eq 1500 -and $script:Order[1] -eq 1001) 'Reset reordered outstanding evaluation.'
}
Test 'Evaluation byte capacity refuses oversized durable XML without acknowledging source' {
    $root=Fixture 'byte-pressure';$event=Event 1;$event.Xml=$event.Xml.Replace('</Event>',('<Padding>'+('x'*1MB)+'</Padding></Event>'))
    $script:Batch=[pscustomobject]@{Reset=$false;Events=@($event)};$small=$config | ConvertTo-Json -Depth 20 | ConvertFrom-Json;$small.Resources.MaxLogFileMB=1
    $failed=$false;try{Receive-SentinelSysmonBatch $root $small}catch{$failed=$_.Exception.Message -like '*byte capacity*'}
    Assert ($failed -and -not (Test-Path (Join-Path $root 'state\sysmon-cursor.json')) -and (Get-SentinelSysmonQueueState $root).Units -eq 0) 'Byte pressure acknowledged source or published incomplete work.'
}
Test 'Disk capacity failure never advances the native cursor' {
    $root=Fixture 'disk-pressure';$script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 1))}
    function Assert-SentinelStorage{throw 'Synthetic disk pressure'}
    Refused {Receive-SentinelSysmonBatch $root $config}
    Assert (-not (Test-Path (Join-Path $root 'state\sysmon-cursor.json')) -and (Get-SentinelSysmonQueueState $root).PendingEvents -eq 0) 'Disk pressure acknowledged the event.'
}
Test 'Missing executable in deferred scoring remains suspicious and preserves the observed hash' {
    $root=Fixture 'missing-image';$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'src\Watcher.ps1'),[ref]$tokens,[ref]$errors)
    foreach($name in @('Get-FileSignatureStatus','Get-ProcessScore')){$item=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true);. ([scriptblock]::Create($item.Extent.Text))}
    $event=Event 1;$event.Xml=$event.Xml.Replace('C:\Deleted\fixture.exe','C:\Windows\Temp\SentinelLocal-missing-fixture.exe')
    $script:Batch=[pscustomobject]@{Reset=$false;Events=@($event)};Receive-SentinelSysmonBatch $root $config
    $script:QueuedMissing=$null
    [void](Invoke-SentinelPendingSysmonAnalysis $root $config {param($p) Get-ProcessScore $p} {param($path,$id,$score,$observed) $script:QueuedMissing=$observed})
    Assert ($script:QueuedMissing.ObservedSHA256 -eq ('A'*64) -and $script:QueuedMissing.ProcessId -eq 1001) 'Deferred disappearance bypassed response or lost detection identity.'
}
Test 'Empty source discontinuity clears old correlation state after earlier durable work' {
    $root=Fixture 'empty-reset';$script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 1))};Receive-SentinelSysmonBatch $root $config
    [void](Invoke-SentinelPendingSysmonAnalysis $root $config {param($p) [pscustomobject]@{Score=15;Reasons=@('fixture')}} {})
    Assert (@((Get-Content (Join-Path $root 'state\sysmon-correlations.json') -Raw | ConvertFrom-Json).Processes).Count -eq 1) 'Correlation fixture missing.'
    $script:Batch=[pscustomobject]@{Reset=$true;Events=@()};Receive-SentinelSysmonBatch $root $config
    Assert ((Get-SentinelSysmonQueueState $root).Units -eq 1) 'Empty reset was not durable.'
    [void](Invoke-SentinelPendingSysmonAnalysis $root $config {throw 'Reset should not score a process'} {})
    Assert (@((Get-Content (Join-Path $root 'state\sysmon-correlations.json') -Raw | ConvertFrom-Json).Processes).Count -eq 0 -and (Get-SentinelSysmonQueueState $root).Units -eq 0) 'Empty reset retained correlations or work.'
}
Test 'Real analysis helper drains durable work and is adopted and restarted using its bound process identity' {
    $root=Fixture 'child';foreach($name in Get-SentinelPackageFiles){Copy-Item -LiteralPath (Get-SentinelSourcePath $repo $name) -Destination (Join-Path $root $name)}
    $localConfig=$config | ConvertTo-Json -Depth 20 | ConvertFrom-Json;Write-SentinelAtomicJson (Join-Path $root 'Config.json') $localConfig
    $state=Join-Path $root 'state';$alertLog=Join-Path $root 'logs\alerts.jsonl';$configBefore=$config;$config=$localConfig
    $tokens=$null;$parseErrors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'src\Watcher.ps1'),[ref]$tokens,[ref]$parseErrors)
    $functionAst=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Ensure-SysmonAnalyzer'},$true)
    . ([scriptblock]::Create($functionAst.Extent.Text.Replace('$PSScriptRoot','$Root')))
    $script:analysisChild=$null;$script:analysisLastStart=[datetimeoffset]::MinValue
    try{
        $script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 101))};Receive-SentinelSysmonBatch $root $config
        Ensure-SysmonAnalyzer;$first=$script:analysisChild.Id
        $deadline=[datetime]::UtcNow.AddSeconds(45)
        do{Start-Sleep -Milliseconds 250;$left=(Get-SentinelSysmonQueueState $root).PendingEvents}while($left -gt 0 -and [datetime]::UtcNow -lt $deadline -and -not $script:analysisChild.HasExited)
        Assert ($left -eq 0 -and -not $script:analysisChild.HasExited) 'Actual helper failed to drain work.'
        Assert ((Get-Content (Join-Path $state 'sysmon-analysis-cursor.json') -Raw | ConvertFrom-Json).RecordId -eq 101) 'Actual analysis cursor did not advance.'
        $script:analysisChild.Dispose();$script:analysisChild=$null;Ensure-SysmonAnalyzer
        Assert ($script:analysisChild.Id -eq $first) 'Parent restart spawned a duplicate rather than adopting its helper.'
        $script:analysisChild.Kill();$script:analysisChild.WaitForExit()
        $script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 102))};Receive-SentinelSysmonBatch $root $config
        $script:analysisLastStart=[datetimeoffset]::MinValue;Ensure-SysmonAnalyzer
        $deadline=[datetime]::UtcNow.AddSeconds(45)
        do{Start-Sleep -Milliseconds 250;$left=(Get-SentinelSysmonQueueState $root).PendingEvents}while($left -gt 0 -and [datetime]::UtcNow -lt $deadline -and -not $script:analysisChild.HasExited)
        Assert ($left -eq 0 -and $script:analysisChild.Id -ne $first -and -not $script:analysisChild.HasExited) 'Restart lost or failed to consume durable work.'
        Remove-Item -LiteralPath (Join-Path $state 'sysmon-analysis-heartbeat.json') -Force
        Stop-SentinelSysmonAnalyzer $root
        Assert ($script:analysisChild.WaitForExit(5000)) 'Deployment could not stop an owned helper without a heartbeat.'
    }finally{if($script:analysisChild){if(-not $script:analysisChild.HasExited){$script:analysisChild.Kill();$script:analysisChild.WaitForExit()};$script:analysisChild.Dispose();$script:analysisChild=$null};$config=$configBefore}
}
function Get-SentinelSysmonAnalysisProcess{param($ProcessIdValue) return $script:AnalysisProcess}
Test 'Deferred checkpoints are amortized and the recorded payload remains immutable' {
    $root=Fixture 'amortized-progress';$script:Batch=[pscustomobject]@{Reset=$false;Events=@(1..80 | ForEach-Object {Event $_})};Receive-SentinelSysmonBatch $root $config
    $payload=Get-ChildItem (Join-Path $root 'state\sysmon-analysis\pending') -Filter '*.json' | Select-Object -First 1
    $hash=(Get-FileHash $payload.FullName).Hash;$script:ProgressWrites=0;$script:CacheWrites=0;$script:PayloadRewrites=0
    $originalAtomic=${function:Write-SentinelAtomicJson}
    function Write-SentinelAtomicJson{
        param($Path,$Data)
        if($Path -like '*.json.progress'){$script:ProgressWrites++}
        if($Path -like '*\sysmon-correlations.json'){$script:CacheWrites++}
        if($Path -like '*\sysmon-analysis\processing\*.json'){$script:PayloadRewrites++}
        & $originalAtomic $Path $Data
    }
    function Get-SentinelSysmonMonotonicSeconds{return 0.0}
    $script:Evaluations=0
    [void](Invoke-SentinelPendingSysmonAnalysis $root $config {param($p) $script:Evaluations++;[pscustomobject]@{Score=15;Reasons=@()}} {})
    Assert ($script:Evaluations -eq 80 -and $script:ProgressWrites -eq 3 -and $script:CacheWrites -eq 3 -and $script:PayloadRewrites -eq 0) 'Large payloads or correlation snapshots were still rewritten for each event.'
    $metrics=Get-Content (Join-Path $root 'state\sysmon-analysis-metrics.json') -Raw | ConvertFrom-Json
    Assert ($metrics.Events -eq 80 -and $metrics.CheckpointCount -eq 3 -and $metrics.PSObject.Properties['ScoringSeconds'] -and $metrics.PSObject.Properties['ResponseQueueSeconds'] -and $metrics.PSObject.Properties['CheckpointSeconds']) 'Analysis phase metrics do not describe the actual committed work.'
    Assert ((Get-SentinelSysmonQueueState $root).PendingEvents -eq 0 -and (Get-Content (Join-Path $root 'state\sysmon-analysis-cursor.json') -Raw | ConvertFrom-Json).RecordId -eq 80) 'Batched checkpoint lost or falsely completed events.'
    Assert (@(Read-SentinelLogRows (Join-Path $root 'logs\process-events.jsonl')).Count -eq 80) 'Evaluation duplicated original acquisition evidence.'
}
Test 'Failure inside a checkpoint window replays only its unacknowledged prefix' {
    $root=Fixture 'checkpoint-retry';$script:Batch=[pscustomobject]@{Reset=$false;Events=@(1..40 | ForEach-Object {Event $_})};Receive-SentinelSysmonBatch $root $config
    $payload=Get-ChildItem (Join-Path $root 'state\sysmon-analysis\pending') -Filter '*.json' | Select-Object -First 1;$hash=(Get-FileHash $payload.FullName).Hash
    function Get-SentinelSysmonMonotonicSeconds{return 0.0}
    $script:EvaluatedIds=[Collections.Generic.List[int]]::new();$script:FailRequest=$true
    $score={param($p) [pscustomobject]@{Score=80;Reasons=@('Fixture')}}
    $queue={param($path,$id,$rating,$observed) if($id -eq 1035 -and $script:FailRequest){throw 'Synthetic response failure'};$script:EvaluatedIds.Add($id);Assert ($observed.ObservedSHA256 -eq ('A'*64)) 'Observed hash changed during replay.'}
    Refused {Invoke-SentinelPendingSysmonAnalysis $root $config $score $queue}
    $processing=Get-ChildItem (Join-Path $root 'state\sysmon-analysis\processing') -Filter '*.json' | Select-Object -First 1
    Assert ((Get-FileHash $processing.FullName).Hash -eq $hash -and (Get-SentinelSysmonQueueState $root).PendingEvents -eq 10) 'Failure rewrote payload or acknowledged an incomplete window.'
    $progress=Get-Content ($processing.FullName+'.progress') -Raw | ConvertFrom-Json
    Assert ($progress.NextIndex -eq 30 -and (Get-Content (Join-Path $root 'state\sysmon-analysis-cursor.json') -Raw | ConvertFrom-Json).RecordId -eq 30) 'Checkpoint skipped the failed event.'
    $script:FailRequest=$false;[void](Invoke-SentinelPendingSysmonAnalysis $root $config $score $queue)
    Assert ((Get-SentinelSysmonQueueState $root).PendingEvents -eq 0 -and @($script:EvaluatedIds | Where-Object {$_ -eq 1001}).Count -eq 1 -and @($script:EvaluatedIds | Where-Object {$_ -eq 1031}).Count -eq 2) 'Retry did not resume at the last durable checkpoint.'
}
Test 'Corrupt progress and changed payloads cannot skip work' {
    $root=Fixture 'progress-binding';$script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 1),(Event 2))};Receive-SentinelSysmonBatch $root $config
    function Get-SentinelSysmonMonotonicSeconds{if($script:MonoCalls++ -eq 0){return 0.0};return 10.0}
    $script:MonoCalls=0;[void](Invoke-SentinelPendingSysmonAnalysis $root $config {param($p) [pscustomobject]@{Score=0;Reasons=@()}} {})
    $payload=Get-ChildItem (Join-Path $root 'state\sysmon-analysis\processing') -Filter '*.json' | Select-Object -First 1
    $sidecar=$payload.FullName+'.progress';Assert ((Get-SentinelSysmonQueueState $root).PendingEvents -eq 1) 'Partial window fixture failed.'
    $good=[IO.File]::ReadAllBytes($sidecar);$progress=Get-Content $sidecar -Raw | ConvertFrom-Json;$progress.NextIndex=3;Write-SentinelAtomicJson $sidecar $progress
    Refused {Get-SentinelSysmonQueueState $root};Refused {Invoke-SentinelPendingSysmonAnalysis $root $config {throw 'Must not evaluate corrupt progress'} {}}
    [IO.File]::WriteAllBytes($sidecar,$good);$bytes=[IO.File]::ReadAllBytes($payload.FullName);[IO.File]::AppendAllText($payload.FullName,' ')
    Refused {Get-SentinelSysmonQueueState $root}
    [IO.File]::WriteAllBytes($payload.FullName,$bytes)
    [IO.File]::Move($payload.FullName,($payload.FullName+'.saved'));Refused {Get-SentinelSysmonQueueState $root}
    [IO.File]::Move(($payload.FullName+'.saved'),$payload.FullName)
    [void](Invoke-SentinelPendingSysmonAnalysis $root $config {param($p) [pscustomobject]@{Score=0;Reasons=@()}} {})
    Assert ((Get-SentinelSysmonQueueState $root).PendingEvents -eq 0) 'Restored payload/progress could not resume.'
}
Test 'Producer uses free slots and avoids querying the native source while saturated' {
    $root=Fixture 'adaptive-capacity';$small=$config | ConvertTo-Json -Depth 20 | ConvertFrom-Json;$small.Resources.MaxQueueCount=5;$small.Resources.HighQueueReserve=1;$small.EventBatchSize=3
    $script:NativeQueries=0;$script:QueryLimits=[Collections.Generic.List[int]]::new()
    function Get-SentinelEventBatch{param($LogName,$Cursor,$CursorTime,$Ids,$BatchSize) $script:NativeQueries++;$script:QueryLimits.Add($BatchSize);[pscustomobject]@{Reset=$false;Events=@(1..8 | Where-Object {$_ -gt $Cursor} | Select-Object -First $BatchSize | ForEach-Object {Event $_})}}
    Receive-SentinelSysmonBatch $root $small;Receive-SentinelSysmonBatch $root $small
    Assert (($script:QueryLimits -join ',') -eq '3,2' -and (Get-SentinelSysmonQueueState $root).PendingEvents -eq 5) 'Producer discarded free slots or exceeded capacity.'
    Refused {Receive-SentinelSysmonBatch $root $small}
    Assert ($script:NativeQueries -eq 2 -and (Get-Content (Join-Path $root 'state\sysmon-cursor.json') -Raw | ConvertFrom-Json).RecordId -eq 5) 'Full queue performed a wasted source query or advanced its cursor.'
    [void](Invoke-SentinelPendingSysmonAnalysis $root $small {param($p) [pscustomobject]@{Score=0;Reasons=@()}} {})
    Receive-SentinelSysmonBatch $root $small
    Assert ((Get-SentinelSysmonQueueState $root).PendingEvents -eq 5 -and (Get-Content (Join-Path $root 'state\sysmon-cursor.json') -Raw | ConvertFrom-Json).RecordId -eq 8) 'Capacity recovery skipped source events.'
    Assert (@(Read-SentinelLogRows (Join-Path $root 'logs\process-events.jsonl')).Count -eq 8) 'Adaptive batches lost or duplicated acquisition evidence.'
}
Test 'A legacy partially processed unit resumes at its existing acknowledged position' {
    $root=Fixture 'legacy-progress';$script:Batch=[pscustomobject]@{Reset=$false;Events=@(1..40 | ForEach-Object {Event $_})};Receive-SentinelSysmonBatch $root $config
    $file=Get-ChildItem (Join-Path $root 'state\sysmon-analysis\pending') -Filter '*.json' | Select-Object -First 1
    $unit=Get-Content $file.FullName -Raw | ConvertFrom-Json;$unit.NextIndex=17;Write-SentinelAtomicJson $file.FullName $unit
    Write-SentinelAtomicJson (Join-Path $root 'state\sysmon-analysis-cursor.json') @{RecordId=17;TimeCreated=$unit.Events[16].TimeCreated}
    function Get-SentinelSysmonMonotonicSeconds{return 0.0}
    $script:LegacyIds=[Collections.Generic.List[int]]::new()
    [void](Invoke-SentinelPendingSysmonAnalysis $root $config {param($p) $script:LegacyIds.Add($p.ProcessId);[pscustomobject]@{Score=0;Reasons=@()}} {})
    Assert ($script:LegacyIds.Count -eq 23 -and $script:LegacyIds[0] -eq 1018 -and $script:LegacyIds[-1] -eq 1040 -and (Get-SentinelSysmonQueueState $root).PendingEvents -eq 0) 'Migration replayed an already acknowledged legacy prefix or lost remaining work.'
}
Test 'Interrupted completed-payload cleanup replays conservatively instead of losing work' {
    $root=Fixture 'cleanup-recovery';$script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 1),(Event 2))};Receive-SentinelSysmonBatch $root $config
    function Get-SentinelSysmonMonotonicSeconds{return 0.0}
    $script:FailDelete=$true;$script:ReplayCount=0
    function Remove-Item{
        [CmdletBinding()]param($LiteralPath,[switch]$Force)
        if($LiteralPath -like '*\sysmon-analysis\processing\*.json' -and $script:FailDelete){$script:FailDelete=$false;throw 'Synthetic interruption before payload deletion'}
        Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters
    }
    $score={param($p) $script:ReplayCount++;[pscustomobject]@{Score=0;Reasons=@()}}
    Refused {Invoke-SentinelPendingSysmonAnalysis $root $config $score {}}
    Assert ((Get-SentinelSysmonQueueState $root).PendingEvents -eq 2) 'Incomplete cleanup hid work using an orphan acknowledgement.'
    [void](Invoke-SentinelPendingSysmonAnalysis $root $config $score {})
    Assert ((Get-SentinelSysmonQueueState $root).PendingEvents -eq 0 -and $script:ReplayCount -eq 4 -and @(Read-SentinelLogRows (Join-Path $root 'logs\process-events.jsonl')).Count -eq 2) 'Cleanup recovery lost work or duplicated source evidence.'
}
Test 'Healthy heartbeat does not conceal delayed events while quiet sources remain healthy' {
    $root=Fixture 'backlog';$now=[datetimeoffset]::Now
    Write-SentinelAtomicJson (Join-Path $root 'state\sysmon-analysis-heartbeat.json') @{Version=$config.Version;Status='Running';ProcessId=99;LastUpdated=$now.ToString('o')}
    $script:AnalysisProcess=[pscustomobject]@{ProcessId=99;ExecutablePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe');CommandLine=('-File "'+(Join-Path $root 'Watcher.ps1')+'" -Root "'+$root+'" -AnalysisOnly');CreationDate=[datetime]::Now.AddMinutes(-1)}
    $script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 1 ([datetime]::Now.AddMinutes(-5))))}
    $state=Get-SentinelSysmonBacklog $root $config
    Assert ($state.Status -eq 'Delayed' -and $state.SourcePendingEvents -eq 1 -and $state.SourceOldestWaitSeconds -gt 120) 'Source delay was healthy.'
    $script:Batch=[pscustomobject]@{Reset=$false;Events=@()}
    Assert ((Get-SentinelSysmonBacklog $root $config).Status -eq 'Healthy') 'Quiet source became stale merely because no events arrived.'
    $script:SourceStopped=$true;$stopped=Get-SentinelSysmonBacklog $root $config;$script:SourceStopped=$false
    Assert ($stopped.Status -eq 'Unverified' -and $stopped.Error -like '*service is stopped*' -and $null -eq $stopped.SourcePendingEvents) 'Stopped provider was shown as healthy/zero pending.'
    $script:Batch=[pscustomobject]@{Reset=$true;Events=@()}
    Assert ((Get-SentinelSysmonBacklog $root $config).Status -eq 'Discontinuity') 'Cleared source was healthy.'
    $script:SourceError=$true;$state=Get-SentinelSysmonBacklog $root $config;$script:SourceError=$false
    Assert ($state.Status -eq 'Unverified' -and $null -eq $state.SourcePendingEvents) 'Unavailable source became zero pending.'
    $script:AnalysisProcess.CreationDate=[datetime]::Now.AddMinutes(1);$script:Batch=[pscustomobject]@{Reset=$false;Events=@()}
    Assert ((Get-SentinelSysmonBacklog $root $config).Status -eq 'Unverified') 'Reused analysis PID was accepted.'
}
Test 'A heartbeat refreshed during slow probes uses its read time without accepting future stale or reused identities' {
    $root=Fixture 'probe-clock';$script:ProbeClock=[datetimeoffset]::Now
    $initial=$script:ProbeClock;$beatPath=Join-Path $root 'state\sysmon-analysis-heartbeat.json'
    $script:BeatOffset=-1;$script:QueueOffset=-1
    function Get-SentinelSysmonClock{return $script:ProbeClock}
    function Get-SentinelEventBatch{
        $script:ProbeClock=$script:ProbeClock.AddSeconds(20)
        Write-SentinelAtomicJson $beatPath @{Version=$config.Version;Status='Running';ProcessId=99;LastUpdated=$script:ProbeClock.AddSeconds($script:BeatOffset).ToString('o')}
        [pscustomobject]@{Reset=$false;Events=@()}
    }
    function Get-SentinelSysmonQueueState{[pscustomobject]@{PendingEvents=1;Bytes=100;OldestEventAt=$script:ProbeClock.AddSeconds($script:QueueOffset)}}
    $script:AnalysisProcess=[pscustomobject]@{ProcessId=99;ExecutablePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe');CommandLine=('-File "'+(Join-Path $root 'Watcher.ps1')+'" -Root "'+$root+'" -AnalysisOnly');CreationDate=$initial.AddMinutes(-1).LocalDateTime}
    $state=Get-SentinelSysmonBacklog $root $config
    Assert ($state.Status -eq 'Healthy' -and [datetimeoffset]$state.HeartbeatCheckedAt -eq $initial.AddSeconds(20) -and [datetimeoffset]$state.ProbeStartedAt -eq $initial -and $state.AnalysisOldestWaitSeconds -eq 1) 'Slow probe made a refreshed heartbeat or newly queued event appear future-dated.'
    $script:BeatOffset=30;$state=Get-SentinelSysmonBacklog $root $config
    Assert ($state.Status -eq 'Unverified' -and $state.Error -like '*AgeSeconds=-30*' -and $null -eq $state.SourcePendingEvents) 'A genuinely future heartbeat passed.'
    $script:BeatOffset=-121;$state=Get-SentinelSysmonBacklog $root $config
    Assert ($state.Status -eq 'Unverified' -and $state.Error -like '*AgeSeconds=121*') 'A genuinely stale heartbeat passed.'
    $script:BeatOffset=-1;$script:AnalysisProcess.CreationDate=$script:ProbeClock.AddMinutes(10).LocalDateTime
    Assert ((Get-SentinelSysmonBacklog $root $config).Status -eq 'Unverified') 'PID reuse passed with a fresh clock.'
    $script:AnalysisProcess.CreationDate=$initial.AddMinutes(-1).LocalDateTime;$script:QueueOffset=30
    Assert ((Get-SentinelSysmonBacklog $root $config).Status -eq 'Unverified') 'A genuinely future source event passed.'
    $script:QueueOffset=-300;$state=Get-SentinelSysmonBacklog $root $config
    Assert ($state.Status -eq 'Delayed' -and $state.AnalysisOldestWaitSeconds -eq 300) 'A real backlog became healthy after fixing the clock comparison.'
}
Test 'Signature reuse is bound to locked actual bytes and expires even for an unchanged path' {
    $path=Join-Path $ScratchRoot 'signature.fixture';[IO.File]::WriteAllText($path,'AAAA');$mtime=(Get-Item $path).LastWriteTimeUtc
    $script:SignatureCalls=0;$script:SignatureLockObserved=$false;$script:SentinelSignatureCache=@{}
    function Get-AuthenticodeSignature{param($FilePath) $script:SignatureCalls++;try{[IO.File]::WriteAllText($FilePath,'BBBB')}catch{$script:SignatureLockObserved=$true};[pscustomobject]@{Status=$(if([IO.File]::ReadAllText($FilePath) -eq 'AAAA'){'Valid'}else{'HashMismatch'})}}
    $details=New-SentinelScoringTimings
    Assert ((Get-SentinelContentSignatureStatus $path -Timings $details) -eq 'Valid' -and (Get-SentinelContentSignatureStatus $path -Timings $details) -eq 'Valid' -and $script:SignatureCalls -eq 1 -and $script:SignatureLockObserved) 'Content lock or reuse failed.'
    [IO.File]::WriteAllText($path,'BBBB');(Get-Item $path).LastWriteTimeUtc=$mtime
    Assert ((Get-SentinelContentSignatureStatus $path -Timings $details) -eq 'HashMismatch' -and $script:SignatureCalls -eq 2) 'Same-length same-time replacement reused trust.'
    foreach($entry in $script:SentinelSignatureCache.Values){$entry.At=[datetimeoffset]::Now.AddSeconds(-16)}
    [void](Get-SentinelContentSignatureStatus $path -Timings $details)
    Assert ($script:SignatureCalls -eq 3) 'Expired status was reused.'
    Assert ($details.SignatureCacheHits -eq 1 -and $details.SignatureCacheMisses -eq 3 -and $details.SignatureBytesHashed -eq 16) 'Phase counters skipped byte validation or counted a cache hit as a verification.'
}
Test 'Original filename reads apply only to ProgramData without changing signature or rename scores' {
    $tokens=$null;$parseErrors=$null
    $watcherAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'src\Watcher.ps1'),[ref]$tokens,[ref]$parseErrors)
    foreach($name in @('Get-ProcessScore','Get-FileSignatureStatus','Test-RandomishSegment')){
        $definition=$watcherAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    $Root=$ScratchRoot;$script:OriginalCalls=0;$script:SignatureChecks=0;$script:OriginalValue='different.exe';$script:SignedState='Valid';$script:FilePresent=$true;$script:ScoreErrors=0
    function Test-SentinelInternalResponse{return $false}
    function Test-Path{return $script:FilePresent}
    function Get-SentinelContentSignatureStatus{param($Path,$Timings) $script:SignatureChecks++;return $script:SignedState}
    function Get-SentinelOriginalFilename{$script:OriginalCalls++;return $script:OriginalValue}
    function Write-SentinelError{$script:ScoreErrors++}
    $details=New-SentinelScoringTimings
    $process=[pscustomobject]@{ExecutablePath='C:\Windows\fixture.exe';Name='fixture.exe';CommandLine='fixture.exe'}
    $score=Get-ProcessScore $process -Timings $details
    Assert ($score.Score -eq 0 -and $script:OriginalCalls -eq 0 -and $script:SignatureChecks -eq 1 -and $details.OriginalFilenameReads -eq 0) 'Unrelated binaries still read PE versions or bypassed signatures.'
    $process.ExecutablePath='C:\ProgramData\vendor\fixture.exe'
    Assert ((Get-ProcessScore $process -Timings $details).Score -eq 25 -and $script:OriginalCalls -eq 1 -and $details.OriginalFilenameReads -eq 1) 'ProgramData rename score changed.'
    $script:OriginalValue='fixture.exe'
    Assert ((Get-ProcessScore $process).Score -eq 0) 'An unchanged original filename gained a score.'
    $script:SignedState='HashMismatch'
    Assert ((Get-ProcessScore $process).Score -eq 15) 'Invalid signature score changed.'
    $script:FilePresent=$false
    Assert ((Get-ProcessScore $process).Score -eq 15 -and $script:SignatureChecks -eq 4) 'Missing target semantics changed.'
    $script:FilePresent=$true
    function Get-SentinelOriginalFilename{throw 'Version resource unavailable'}
    Assert ((Get-ProcessScore $process -Timings $details).Score -eq 15 -and $script:ScoreErrors -eq 1) 'Metadata failure discarded the signature score or failed silently.'
}
Test 'Scoring phase counters survive the deferred callback and are exported with confirmed work' {
    $root=Fixture 'score-details';$script:Batch=[pscustomobject]@{Reset=$false;Events=@((Event 9001))};Receive-SentinelSysmonBatch $root $config
    [void](Invoke-SentinelPendingSysmonAnalysis $root $config {param($process,$details) $details.SignatureCacheHits++;$details.SignatureBytesHashed+=123;[pscustomobject]@{Score=0;Reasons=@()}} {})
    $metrics=Get-Content -LiteralPath (Join-Path $root 'state\sysmon-analysis-metrics.json') -Raw | ConvertFrom-Json
    Assert ($metrics.Events -eq 1 -and $metrics.ScoringDetails.SignatureCacheHits -eq 1 -and $metrics.ScoringDetails.SignatureBytesHashed -eq 123) 'Scoring breakdown was lost or falsely acknowledged.'
}
Test 'Read-only scoring diagnostic profiles actual pending files without acknowledging or rewriting work' {
    $root=Fixture 'read-only-score';$executable=Join-Path $root 'fixture.exe'
    Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\cmd.exe') -Destination $executable
    $event=Event 9101;$event.Xml=$event.Xml.Replace('C:\Deleted\fixture.exe',[Security.SecurityElement]::Escape($executable))
    $script:Batch=[pscustomobject]@{Reset=$false;Events=@($event)};Receive-SentinelSysmonBatch $root $config
    $before=@(Get-ChildItem -LiteralPath $root -File -Recurse | ForEach-Object {($_.FullName.Substring($root.Length))+'|'+(Get-FileHash -LiteralPath $_.FullName).Hash} | Sort-Object)
    $output=Join-Path $ScratchRoot 'read-only-scoring-output'
    & (Join-Path $repo 'tools\diagnostics\Measure-SentinelScoring.ps1') -Root $root -OutputDirectory $output -SampleCount 1
    $report=Get-Content -LiteralPath (Join-Path $output 'scoring.json') -Raw | ConvertFrom-Json
    $after=@(Get-ChildItem -LiteralPath $root -File -Recurse | ForEach-Object {($_.FullName.Substring($root.Length))+'|'+(Get-FileHash -LiteralPath $_.FullName).Hash} | Sort-Object)
    Assert (($before -join "`n") -ceq ($after -join "`n")) 'The diagnostic changed installed files or acknowledged work.'
    Assert ($report.ReadOnly -and -not $report.QueueAcknowledged -and -not $report.TrialProcessesLaunched -and $report.Rows.Count -eq 2 -and $report.ProfiledProcessEvents -eq 1 -and $report.Rows[0].ScoringDetails.SignatureBytesHashed -gt 0 -and $report.Rows[1].ScoringDetails.SignatureCacheHits -eq 1) 'Actual scoring phases were not exercised in both passes.'
    Assert ((Get-SentinelSysmonQueueState $root).PendingEvents -eq 1) 'Profiling consumed the event.'
}
Test 'Guardian warns on backlog and records recovery without suppressing failed alert writes' {
    $root=Fixture 'guardian';$alertLog=Join-Path $root 'logs\alerts.jsonl';$lastAlertStatePath=Join-Path $root 'state\integrity-last-alerts.json';$lastAlerts=@{}
    $tokens=$null;$parseErrors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'src\IntegrityMonitor.ps1'),[ref]$tokens,[ref]$parseErrors)
    foreach($name in @('Alert-Once','Save-LastAlerts','Clear-AlertKey','Check-SysmonBacklog')){$item=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true);. ([scriptblock]::Create($item.Extent.Text))}
    $script:GuardianBacklog=[pscustomobject]@{Status='Delayed';AnalysisPendingEvents=1;SourcePendingEvents=0;Error=$null}
    function Get-SentinelSysmonBacklog{return $script:GuardianBacklog}
    Check-SysmonBacklog;Check-SysmonBacklog
    Assert (@(Read-SentinelLogRows $alertLog).Count -eq 1) 'Unchanged backlog was not deduplicated.'
    $script:GuardianBacklog.Status='Healthy';Check-SysmonBacklog;Check-SysmonBacklog
    $rows=@(Read-SentinelLogRows $alertLog)
    Assert ($rows.Count -eq 2 -and $rows[1].Type -eq 'SysmonBacklogRecovered' -and -not $lastAlerts.ContainsKey('SysmonBacklog')) 'Recovery was not recorded and cleared.'
    function Write-SentinelJsonLine{return $false}
    $script:GuardianBacklog.Status='Unverified';Check-SysmonBacklog
    Assert (-not $lastAlerts.ContainsKey('SysmonBacklog')) 'Failed alert write suppressed future retry.'
}
$results.ToArray() | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $ScratchRoot 'test-results.json') -Encoding UTF8
$failed=@($results | Where-Object {-not $_.Passed}).Count
Write-Host ('Ingestion reliability tests: '+($results.Count-$failed)+'/'+$results.Count+' passed.')
if($failed){exit 1}
