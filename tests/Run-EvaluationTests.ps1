param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-evaluation-tests-'+[guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$toolRoot=Join-Path $repo 'tools\evaluation'
. (Join-Path $toolRoot 'Evaluation.ps1')
if(Test-Path -LiteralPath $ScratchRoot) { throw 'Test directory already exists; refusing to overwrite.' }
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$results=[Collections.Generic.List[object]]::new()
function Assert([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message } }
function Read-Fixture { return (Get-Content -LiteralPath (Join-Path $toolRoot 'synthetic-example.json') -Raw -Encoding UTF8 | ConvertFrom-Json) }
function Assert-Rejected($Data,[string]$Expected) {
    $message=$null
    try { [void](Get-SentinelEvaluationSummary $Data) } catch { $message=$_.Exception.Message }
    Assert ($null -ne $message -and $message -like "*$Expected*") ('Expected rejection containing '+$Expected+'; received '+$message)
}
function Run-Test([string]$Name,[scriptblock]$Body) {
    try { & $Body; $results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'}); Write-Host ('PASS '+$Name) }
    catch { $results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message}); Write-Host ('FAIL '+$Name+': '+$_.Exception.Message) -ForegroundColor Red }
}

Run-Test 'Rates use completed trials and keep engine attribution separate' {
    $summary=Get-SentinelEvaluationSummary (Read-Fixture)
    $sentinel=$summary.Sources.Sentinel.Categories
    Assert ($sentinel.Malware.AlertRate -eq 0.5 -and $sentinel.Malware.CompletedTrials -eq 2 -and $sentinel.Malware.ErrorTrials -eq 1) 'Malware denominator includes errors or emulation'
    Assert ($sentinel.Benign.AlertRate -eq 0.5 -and $summary.Sources.Defender.Categories.Benign.AlertRate -eq 0) 'Incorrect false-positive rate or engine attribution'
    Assert ($sentinel.Emulation.AlertRate -eq 0.5 -and $summary.Sources.Defender.Categories.Emulation.AlertRate -eq 0) 'Emulation and malware results were conflated'
}
Run-Test 'Empty or entirely failed categories stay unmeasured' {
    $data=Read-Fixture; $data.Cases=@()
    $summary=Get-SentinelEvaluationSummary $data
    Assert ($null -eq $summary.Sources.Sentinel.Categories.Malware.AlertRate) 'Empty category became zero percent'
    Assert ($null -eq $summary.Sources.Sentinel.Categories.Malware.TimeToFirstAlertSeconds.Median) 'Empty latency became zero'
    Assert ($null -eq $summary.Sources.Sentinel.AttackCoverage.DetectedFractionOfTested) 'Untested coverage became zero'
    $data.Cases=@((Read-Fixture).Cases[2]); $summary=Get-SentinelEvaluationSummary $data
    Assert ($summary.Sources.Sentinel.Categories.Malware.ErrorTrials -eq 1 -and $null -eq $summary.Sources.Sentinel.Categories.Malware.AlertRate) 'Failed trial counted as a miss'
}
Run-Test 'Multiple alerts count once using earliest absolute timestamp' {
    $data=Read-Fixture
    $data.Cases[0].Alerts+=@(
        [pscustomobject]@{Source='Sentinel';Timestamp='2026-01-01T09:00:00.500+09:00';EvidenceRef='synthetic://earliest'},
        [pscustomobject]@{Source='Sentinel';Timestamp='2026-01-01T00:00:05Z';EvidenceRef='synthetic://later'})
    $summary=Get-SentinelEvaluationSummary $data
    $stats=$summary.Sources.Sentinel.Categories.Malware
    Assert ($stats.AlertedTrials -eq 1 -and $stats.TimeToFirstAlertSeconds.Median -eq 0.5 -and $stats.NoAlertTrials -eq 1) 'Alerts inflated rate, timezones were misordered, or misses entered latency'
    Assert ($summary.Sources.Defender.Categories.Malware.TimeToFirstAlertSeconds.Median -eq 1) 'Engine latencies were combined'
}
Run-Test 'Median and nearest-rank p95 use detected trials only' {
    $stats=Get-EvaluationLatency @(20,1,19,2,18,3,17,4,16,5,15,6,14,7,13,8,12,9,11,10)
    Assert ($stats.Count -eq 20 -and $stats.Median -eq 10.5 -and $stats.P95 -eq 19 -and $stats.Maximum -eq 20) 'Incorrect latency statistics'
    Assert ((Get-EvaluationLatency @(7)).Median -eq 7) 'Single observation median failed'
}
Run-Test 'Coverage shows observed, missed, untested and failed techniques' {
    $data=Read-Fixture
    $data.Cases[2].Category='Emulation'; $data.Cases[2].TechniqueId='T1047'
    $summary=Get-SentinelEvaluationSummary $data
    $coverage=$summary.Sources.Sentinel.AttackCoverage
    Assert ($coverage.ScopeTechniqueCount -eq 3 -and $coverage.TestedTechniqueCount -eq 2 -and $coverage.DetectedTechniqueCount -eq 1 -and $coverage.DetectedFractionOfTested -eq 0.5) 'Wrong coverage denominator'
    Assert ($coverage.Techniques[0].Status -eq 'DetectedInAllTrials' -and $coverage.Techniques[1].Status -eq 'TestedNoDetection') 'Wrong tested technique states'
    Assert ($coverage.Techniques[2].Status -eq 'NotTested' -and $coverage.Techniques[2].ErrorTrials -eq 1) 'Failed technique became tested'
    $copy=((Read-Fixture).Cases[5] | ConvertTo-Json -Depth 10 | ConvertFrom-Json); $copy.Id='second-emulation'; $copy.Alerts=@(); $data.Cases+=@($copy)
    $summary=Get-SentinelEvaluationSummary $data
    Assert ($summary.Sources.Sentinel.AttackCoverage.Techniques[0].Status -eq 'DetectedInSomeTrials') 'Partial coverage became complete'
}
Run-Test 'Synthetic reports cannot appear as measured performance' {
    $summary=Get-SentinelEvaluationSummary (Read-Fixture)
    $markdown=ConvertTo-SentinelEvaluationMarkdown $summary
    Assert ($summary.IsSynthetic -and $markdown.Contains('SYNTHETIC DATA') -and $markdown.Contains('not measured security performance')) 'Synthetic disclaimer missing'
    $data=Read-Fixture; $data.Run.EvidenceType='Measured'; $summary=Get-SentinelEvaluationSummary $data
    Assert (-not $summary.IsSynthetic -and (ConvertTo-SentinelEvaluationMarkdown $summary).Contains('independent review')) 'Measured evidence review caveat missing'
}
Run-Test 'Report escapes operator-supplied Markdown and HTML' {
    $data=Read-Fixture; $data.Run.CorpusId='<script>|[link](https://example.invalid)*'
    $markdown=ConvertTo-SentinelEvaluationMarkdown (Get-SentinelEvaluationSummary $data)
    Assert (-not $markdown.Contains('<script>') -and $markdown.Contains('&lt;script&gt;&#124;&#91;link&#93;')) 'Report rendered untrusted markup'
}
Run-Test 'Duplicate trial and technique IDs are rejected' {
    $data=Read-Fixture; $data.Cases[1].Id=$data.Cases[0].Id; Assert-Rejected $data 'Duplicate case ID'
    $data=Read-Fixture; $data.Run.AttackScope+=@('T1047'); Assert-Rejected $data 'Duplicate ATT&CK'
}
Run-Test 'Schema typos and non-object or scalar collections are rejected' {
    $data=Read-Fixture; $data.Cases[0] | Add-Member NoteProperty Alertz @(); Assert-Rejected $data 'unknown field'
    $data=Read-Fixture; $data.Cases=$data.Cases[0]; Assert-Rejected $data 'Cases must be an array'
    $data=Read-Fixture; $data.Cases[0].Alerts=$null; Assert-Rejected $data 'Alerts must be an array'
    $data=Read-Fixture; $data.Cases[0].Alerts=@('bad'); Assert-Rejected $data 'must be a JSON object'
    $data=Read-Fixture; $data.Schema='1'; Assert-Rejected $data 'Unsupported evaluation schema'
}
Run-Test 'Unknown sources, categories and evidence types are rejected' {
    $data=Read-Fixture; $data.Cases[0].Alerts[0].Source='Combined'; Assert-Rejected $data 'invalid alert source'
    $data=Read-Fixture; $data.Cases[0].Category='malware'; Assert-Rejected $data 'Invalid category'
    $data=Read-Fixture; $data.Run.EvidenceType='Unknown'; Assert-Rejected $data 'EvidenceType'
}
Run-Test 'Naive, invalid, backwards and out-of-window times are rejected' {
    $data=Read-Fixture; $data.Cases[0].StartedAt='2026-01-01T00:00:00'; Assert-Rejected $data 'explicit timezone'
    $data=Read-Fixture; $data.Cases[0].StartedAt='2026-99-01T00:00:00Z'; Assert-Rejected $data 'valid timestamp'
    $data=Read-Fixture; $data.Cases[0].EndedAt=$data.Cases[0].StartedAt; Assert-Rejected $data 'must follow'
    $data=Read-Fixture; $data.Cases[0].Alerts[0].Timestamp='2025-12-31T23:59:59Z'; Assert-Rejected $data 'outside the observation window'
    $data=Read-Fixture; $data.Cases[0].Alerts[0].Timestamp='2026-01-01T00:01:01Z'; Assert-Rejected $data 'outside the observation window'
}
Run-Test 'Errors, evidence references and artifact identity are mandatory' {
    $data=Read-Fixture; $data.Cases[2].Error=''; Assert-Rejected $data 'Error must be nonempty'
    $data=Read-Fixture; $data.Cases[0].Alerts[0].EvidenceRef=''; Assert-Rejected $data 'EvidenceRef must be nonempty'
    $data=Read-Fixture; $data.Cases[0].ArtifactSHA256='invalid'; Assert-Rejected $data 'invalid ArtifactSHA256'
    $data=Read-Fixture; $data.Cases[0].PSObject.Properties.Remove('ArtifactSHA256'); Assert-Rejected $data 'requires ArtifactSHA256'
    $data=Read-Fixture; $data.Run.ConfigSHA256='invalid'; Assert-Rejected $data 'ConfigSHA256'
}
Run-Test 'Technique attribution requires a single emulation target in the declared scope' {
    $data=Read-Fixture; $data.Cases[5].TechniqueId='T9999'; Assert-Rejected $data 'in AttackScope'
    $data=Read-Fixture; $data.Cases[5].TechniqueId='t1059.001'; Assert-Rejected $data 'in AttackScope'
    $data=Read-Fixture; $data.Cases[0].TechniqueId='T1059.001'; Assert-Rejected $data 'only emulation'
    $data=Read-Fixture; $data.Run.AttackScope=@('t1059.001'); Assert-Rejected $data 'Invalid ATT&CK'
}
Run-Test 'CLI exports auditable input and JSON plus Markdown without overwriting' {
    $output=Join-Path $ScratchRoot 'valid-report'
    & (Join-Path $toolRoot 'Export-SentinelEvaluation.ps1') -InputPath (Join-Path $toolRoot 'synthetic-example.json') -OutputDirectory $output
    foreach($name in @('results.json','summary.json','summary.md')) { Assert (Test-Path -LiteralPath (Join-Path $output $name)) ('Missing '+$name) }
    $summary=Get-Content (Join-Path $output 'summary.json') -Raw | ConvertFrom-Json
    Assert ($summary.IsSynthetic -and $summary.Sources.Sentinel.Categories.Malware.AlertRate -eq 0.5) 'Serialized summary lost results'
    $message=$null
    try { & (Join-Path $toolRoot 'Export-SentinelEvaluation.ps1') -InputPath (Join-Path $toolRoot 'synthetic-example.json') -OutputDirectory $output } catch { $message=$_.Exception.Message }
    Assert ($message -like '*already exists*') 'Existing reports can be overwritten'
}
Run-Test 'CLI validates before creating any output' {
    $data=Read-Fixture; $data.Cases[0].Alerts[0].Source='bad'
    $inputFile=Join-Path $ScratchRoot 'invalid.json'; $data | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $inputFile -Encoding UTF8
    $output=Join-Path $ScratchRoot 'invalid-report'; $message=$null
    try { & (Join-Path $toolRoot 'Export-SentinelEvaluation.ps1') -InputPath $inputFile -OutputDirectory $output } catch { $message=$_.Exception.Message }
    Assert ($null -ne $message -and -not (Test-Path -LiteralPath $output)) 'Invalid input created a report'
}

$results.ToArray() | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ScratchRoot 'test-results.json') -Encoding UTF8
$failed=@($results | Where-Object { -not $_.Passed }).Count
Write-Host ('Evaluation tests: '+($results.Count-$failed)+' passed; '+$failed+' failed. Results: '+$ScratchRoot)
if($failed) { exit 1 }
exit 0
