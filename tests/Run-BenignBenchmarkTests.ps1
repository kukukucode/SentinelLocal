param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-benchmark-tests-'+[guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'tools\evaluation\BenignBenchmark.ps1')
if(Test-Path $ScratchRoot){throw 'Scratch directory exists.'}
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$results=[Collections.Generic.List[object]]::new()
function Assert([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Test([string]$Name,[scriptblock]$Body){try{& $Body;$results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'});Write-Host ('PASS '+$Name)}catch{$results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message});Write-Host ('FAIL '+$Name+': '+$_.Exception.Message)}}
function Refused([scriptblock]$Body){$failed=$false;try{& $Body | Out-Null}catch{$failed=$true};Assert $failed 'Unsafe or invalid operation accepted.'}
function Trial([int]$Number){[pscustomobject]@{Id=('fixture-'+$Number);ProcessId=$Number;ExecutablePath='C:\Windows\System32\cmd.exe';SHA256=('A'*64);Arguments='/d /c echo fixture';ProcessCreatedAt='2026-10-03T00:00:00.001Z';StartedAt='2026-10-03T00:00:00Z';ObservationEndedAt='2026-10-03T00:02:00Z'}}
function Record([int]$Number,[double]$Seconds){[pscustomobject]@{Type='ProcessCreated';Source='Sysmon';MetadataComplete=$true;RecordId=$Number;EventTime='2026-10-03T00:00:00.010Z';Timestamp=([datetimeoffset]'2026-10-03T00:00:00Z').AddSeconds($Seconds).ToString('o');Process=[pscustomobject]@{ProcessId=$Number;ExecutablePath='C:\Windows\System32\cmd.exe';ObservedSHA256=('A'*64);CreationDate='2026-10-03T00:00:00.001Z';CommandLine='"C:\Windows\System32\cmd.exe" /d /c echo fixture';ProcessGuid=('guid-'+$Number)}}}
Test 'Measured capture fraction and ingestion percentiles use matched process identities only' {
    $summary=Get-SentinelBenchmarkSummary @((Trial 1),(Trial 2),(Trial 3)) @((Record 1 1),(Record 2 10),(Record 3 37)) $true
    Assert ($summary.ObservationValid -and $summary.CaptureFraction -eq 1 -and $summary.PersistDelaySeconds.Median -eq 10 -and $summary.PersistDelaySeconds.P95 -eq 37 -and $summary.PersistDelaySeconds.Maximum -eq 37) 'Matched timing/capture statistics wrong.'
    Assert (-not $summary.DetectionPerformanceMeasured -and $summary.AlertReviewRequired -and $null -eq $summary.FalsePositiveRate -and $null -eq $summary.TimeToDetect) 'Ingestion was presented as malware performance.'
}
Test 'Missing late hash-mismatched and reused-PID records cannot count as capture' {
    $wrong=Record 2 5;$wrong.Process.ObservedSHA256='B'*64
    $reuse=Record 3 5;$reuse.Process.CreationDate='2026-10-03T00:00:01Z'
    $summary=Get-SentinelBenchmarkSummary @((Trial 1),(Trial 2),(Trial 3)) @((Record 1 121),$wrong,$reuse) $true
    Assert ($summary.CaptureFraction -eq 0 -and $summary.NotCapturedTrials -eq 3 -and $summary.PersistDelaySeconds.Count -eq 0) 'Late/wrong-identity record counted.'
}
Test 'Invalid monitoring or inaccessible evidence never produces a zero rate' {
    $summary=Get-SentinelBenchmarkSummary @((Trial 1)) @() $false
    Assert (-not $summary.ObservationValid -and $null -eq $summary.CaptureFraction -and $summary.Trials[0].State -eq 'Unverified' -and $null -eq $summary.PersistDelaySeconds.Median) 'Missing observability became zero capture.'
}
Test 'Replay of the same provider event is deduplicated but distinct GUID ambiguity is unverified' {
    $record=Record 1 5
    $summary=Get-SentinelBenchmarkSummary @((Trial 1)) @($record,$record) $true
    Assert ($summary.CapturedTrials -eq 1 -and $summary.ObservationValid) 'Replay duplicated process.'
    $other=Record 1 7;$other.Process.ProcessGuid='another-guid'
    $summary=Get-SentinelBenchmarkSummary @((Trial 1)) @($record,$other) $true
    Assert (-not $summary.ObservationValid -and $null -eq $summary.CaptureFraction -and $summary.AmbiguousTrials -eq 1) 'Distinct identities silently merged.'
}
function Get-EvaluationRuntimeProcess([int]$ProcessIdValue){$script:Processes[$ProcessIdValue]}
function Get-EvaluationSysmonService{if($script:ServiceStopped){throw 'Source stopped'};return @('Sysmon64')}
Test 'Health sampling validates live component identity freshness worker time and configuration' {
    $root=Join-Path $ScratchRoot 'health';New-Item -ItemType Directory -Path (Join-Path $root 'state') | Out-Null
    Copy-Item (Join-Path $repo 'config\Config.json') (Join-Path $root 'Config.json')
    $config=Get-Content (Join-Path $root 'Config.json') -Raw | ConvertFrom-Json;$script:BenchmarkConfigHash=(Get-FileHash (Join-Path $root 'Config.json')).Hash
    $script:Processes=@{};$script:ServiceStopped=$false;$i=1
    foreach($spec in @(@('watcher-heartbeat.json','WatcherProcessId','Watcher.ps1','Running'),@('response-worker-heartbeat.json','ResponseWorkerProcessId','ResponseWorker.ps1','Busy'),@('integrity-monitor-heartbeat.json','IntegrityMonitorProcessId','IntegrityMonitor.ps1','Running'))){
        $beat=[ordered]@{Version=$config.Version;Status=$spec[3];LastUpdated=[datetimeoffset]::Now.ToString('o');RequestStartedAt=[datetimeoffset]::Now.ToString('o');ProcessMonitorMode='Sysmon'};$beat[$spec[1]]=$i;Write-SentinelAtomicJson (Join-Path $root ('state\'+$spec[0])) $beat
        $script:Processes[$i]=[pscustomobject]@{ProcessId=$i;ExecutablePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe');CommandLine=('-File "'+(Join-Path $root $spec[2])+'" -Root "'+$root+'"');CreationDate=[datetime]::Now.AddMinutes(-10)};$i++
    }
    Assert (Get-SentinelBenchmarkHealth $root $config).Healthy 'Healthy running fixture rejected.'
    $script:Processes[1].CreationDate=[datetime]::Now.AddMinutes(1)
    Assert (-not (Get-SentinelBenchmarkHealth $root $config).Healthy) 'Reused PID accepted.'
    $script:Processes[1].CreationDate=[datetime]::Now.AddMinutes(-10);$script:ServiceStopped=$true
    Assert (-not (Get-SentinelBenchmarkHealth $root $config).Healthy) 'Stopped Sysmon accepted.'
    $script:ServiceStopped=$false;Add-Content (Join-Path $root 'Config.json') ' '
    Assert (-not (Get-SentinelBenchmarkHealth $root $config).Healthy) 'Changed configuration accepted.'
}
Test 'Unready or disabled-Sysmon preflight starts no commands and invalid paths are refused' {
    function Wait-SentinelObservationBaseline{[pscustomobject]@{ReadyForBenignTrials=$false;Environment=[pscustomobject]@{SysmonEnabled=$true}}}
    function Invoke-SentinelBenignCommand{throw 'Must not launch.'}
    $root=Join-Path $ScratchRoot 'health';$output=Join-Path $ScratchRoot 'not-started'
    Refused {Invoke-SentinelBenignBenchmark $root $output}
    Assert (-not (Test-Path $output)) 'Preflight failure created measured output.'
    Refused {Invoke-SentinelBenignBenchmark $root (Join-Path $root 'measurement')}
    Refused {Invoke-SentinelBenignBenchmark $root $output 0 120}
    Refused {Invoke-SentinelBenignBenchmark $root $output 10 5}
}
$results.ToArray() | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $ScratchRoot 'test-results.json') -Encoding UTF8
$failed=@($results | Where-Object {-not $_.Passed}).Count
Write-Host ('Benign benchmark tests: '+($results.Count-$failed)+'/'+$results.Count+' passed.')
if($failed){exit 1}else{exit 0}
