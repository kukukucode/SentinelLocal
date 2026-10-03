param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-benign-observation-'+[guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'tools\evaluation\BenignObservation.ps1')
$realCommand=${function:Invoke-SentinelBenignCommand}
if(Test-Path -LiteralPath $ScratchRoot) { throw 'Scratch directory already exists.' }
[void](New-Item -ItemType Directory -Path $ScratchRoot)
$results=[Collections.Generic.List[object]]::new()
function Assert([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message } }
function Test([string]$Name,[scriptblock]$Body) {
    try { & $Body;$results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'});Write-Host ('PASS '+$Name) }
    catch { $results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message});Write-Host ('FAIL '+$Name+': '+$_.Exception.Message) }
}
function Reset-Fixture {
    $script:Calls=0;$script:Ready=$true;$script:PostReady=$true;$script:Changed=$false;$script:FailCommand=$false;$script:Reads=0;$script:BusyOnce=$false
}
function Get-SentinelEvaluationReadiness([string]$Root) {
    $script:Reads++
    if($script:BusyOnce -and $script:Reads -eq 1) {
        return [pscustomobject]@{ReadyForBenignTrials=$false;Checks=@([pscustomobject]@{Name='ResponseWorker heartbeat/process';State='Unverified';Value='Component status is "Busy"; expected Idle.'})}
    }
    [pscustomobject]@{ReadyForBenignTrials=$(if($script:Reads -eq 1){$script:Ready}else{$script:PostReady});Environment=[pscustomobject]@{ConfigSHA256=$(if($script:Changed -and $script:Reads -gt 1){'B'*64}else{'A'*64})};Checks=@()}
}
function Invoke-SentinelBenignCommand($Scenario) {
    $script:Calls++
    if($script:FailCommand) { throw 'Fixture command failed' }
    [pscustomobject]@{Id=$Scenario.Id;ProcessId=123;ExitCode=0;StartedAt=[datetimeoffset]::Now.ToString('o');TelemetryReviewed=$false}
}
function Start-Sleep { param($Seconds) } # No delays or real process launches in orchestration tests.
$root=Join-Path $ScratchRoot 'installed';[void](New-Item -ItemType Directory -Path $root)
Test 'Windows command launches retain executable identity PID creation time and successful exit' {
    foreach($scenario in Get-SentinelBenignScenarios) {
        $record=& $realCommand $scenario
        Assert ($record.ExitCode -eq 0 -and $record.ProcessId -gt 0 -and $record.SHA256 -eq (Get-FileHash -LiteralPath $record.ExecutablePath).Hash) 'Launch lost process or file identity'
        Assert ([datetimeoffset]$record.ProcessCreatedAt -ge [datetimeoffset]$record.StartedAt -and [datetimeoffset]$record.ProcessEndedAt -ge [datetimeoffset]$record.ProcessCreatedAt) 'Creation or end time is invalid'
        Assert (-not $record.TelemetryReviewed) 'Launching a process claimed telemetry review'
    }
}
Test 'Three fixed local commands yield review-required evidence without manufactured rates' {
    Reset-Fixture
    $scenarios=@(Get-SentinelBenignScenarios)
    Assert (($scenarios.FileName -join ',') -eq 'hostname.exe,whoami.exe,cmd.exe' -and $scenarios[2].Arguments -eq '/d /c echo SentinelLocal benign smoke') 'Unexpected command or arguments'
    $out=Join-Path $ScratchRoot 'success'
    $packet=Invoke-SentinelBenignObservation $root $out
    Assert ($packet.CommandsSucceeded -and $script:Calls -eq 3 -and $packet.Trials.Count -eq 3) 'Commands were not recorded'
    Assert ($packet.ReviewRequired -and -not $packet.PerformanceMeasured -and -not $packet.PSObject.Properties['Cases']) 'Unreviewed commands were presented as measured trials'
    $saved=Get-Content (Join-Path $out 'observation.json') -Raw | ConvertFrom-Json
    Assert ($saved.Trials.Count -eq 3 -and $saved.Trials[0].ObservationEndedAt -and -not $saved.Trials[0].TelemetryReviewed) 'Evidence packet lost timing or review state'
}
Test 'Unready preflight starts no commands and retains diagnostics' {
    Reset-Fixture;$script:Ready=$false
    $packet=Invoke-SentinelBenignObservation $root (Join-Path $ScratchRoot 'unready')
    Assert (-not $packet.CommandsSucceeded -and $packet.Error -and $script:Calls -eq 0 -and $script:Reads -eq 1) 'Unready monitoring started trials'
}
Test 'Only a transient busy worker is retried before commands begin' {
    Reset-Fixture;$script:BusyOnce=$true
    $packet=Invoke-SentinelBenignObservation $root (Join-Path $ScratchRoot 'busy-once')
    Assert ($packet.CommandsSucceeded -and $script:Reads -eq 3 -and $script:Calls -eq 3) 'Transient Busy prevented a healthy baseline or skipped postflight'
    Reset-Fixture;$script:BusyOnce=$true
    $report=Wait-SentinelObservationBaseline $root 0
    Assert (-not $report.ReadyForBenignTrials -and $script:Reads -eq 1 -and $script:Calls -eq 0) 'Busy deadline was ignored'
}
Test 'Command failure unready postflight and configuration changes cannot succeed' {
    foreach($failure in @('command','postflight','configuration')) {
        Reset-Fixture
        switch($failure){command {$script:FailCommand=$true} postflight {$script:PostReady=$false} configuration {$script:Changed=$true}}
        $packet=Invoke-SentinelBenignObservation $root (Join-Path $ScratchRoot $failure)
        Assert (-not $packet.CommandsSucceeded -and $packet.Error -and $script:Reads -eq 2) ('Invalid observation passed: '+$failure)
    }
}
Test 'Existing monitored and junction output paths are refused before probes or execution' {
    Reset-Fixture
    foreach($path in @($root,(Join-Path $root 'reports'),(Join-Path $ScratchRoot 'success'))) {
        $failed=$false;try{Invoke-SentinelBenignObservation $root $path | Out-Null}catch{$failed=$true}
        Assert $failed 'Unsafe output accepted'
    }
    $alias=Join-Path $ScratchRoot 'alias';[void](New-Item -ItemType Junction -Path $alias -Target $root)
    $failed=$false;try{Invoke-SentinelBenignObservation $root (Join-Path $alias 'reports') | Out-Null}catch{$failed=$true}
    Assert ($failed -and $script:Reads -eq 0 -and $script:Calls -eq 0) 'Invalid output reached probes or process execution'
}
$results.ToArray() | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $ScratchRoot 'test-results.json') -Encoding UTF8
if(@($results | Where-Object {-not $_.Passed}).Count) { exit 1 } else { exit 0 }
