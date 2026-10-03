# Offline aggregation only: this file never executes a trial or changes Windows settings.
function Assert-EvaluationFields($Value,[string[]]$Required,[string[]]$Optional=@(),[string]$Context='Value') {
    if($null -eq $Value -or $Value -isnot [pscustomobject]) { throw "$Context must be a JSON object." }
    $names=@($Value.PSObject.Properties.Name)
    foreach($name in $Required) { if($name -cnotin $names) { throw "$Context is missing $name." } }
    foreach($name in $names) { if($name -cnotin @($Required+$Optional)) { throw "$Context has unknown field $name." } }
}

function Assert-EvaluationText($Value,[string]$Context) {
    if($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or $Value -match '[\x00-\x1f]') { throw "$Context must be nonempty text without control characters." }
}

function ConvertTo-EvaluationTimestamp($Value,[string]$Context) {
    if($Value -isnot [string] -or $Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+-]\d{2}:\d{2})$') { throw "$Context must be an ISO 8601 timestamp with an explicit timezone." }
    $parsed=[DateTimeOffset]::MinValue
    if(-not [DateTimeOffset]::TryParse($Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed)) { throw "$Context is not a valid timestamp." }
    return $parsed
}

function Assert-SentinelEvaluationInput($InputData) {
    Assert-EvaluationFields $InputData @('Schema','Run','Cases')
    if($InputData.Schema -isnot [int] -or $InputData.Schema -ne 1) { throw 'Unsupported evaluation schema; expected integer 1.' }
    $run=$InputData.Run
    Assert-EvaluationFields $run @('Id','EvidenceType','SentinelVersion','ConfigSHA256','WindowsVersion','DefenderVersion','SysmonVersion','CorpusId','AttackVersion','AttackScope') -Context 'Run'
    foreach($name in @('Id','SentinelVersion','WindowsVersion','DefenderVersion','SysmonVersion','CorpusId','AttackVersion')) { Assert-EvaluationText $run.$name "Run.$name" }
    if($run.EvidenceType -isnot [string] -or $run.EvidenceType -cnotin @('Synthetic','Measured')) { throw 'Run.EvidenceType must be Synthetic or Measured.' }
    if($run.ConfigSHA256 -isnot [string] -or $run.ConfigSHA256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Run.ConfigSHA256 must contain 64 hexadecimal characters.' }
    if($run.AttackScope -isnot [array]) { throw 'Run.AttackScope must be an array.' }
    $scope=@{}
    foreach($technique in $run.AttackScope) {
        if($technique -isnot [string] -or $technique -cnotmatch '^T\d{4}(\.\d{3})?$') { throw 'Invalid ATT&CK technique ID in Run.AttackScope.' }
        if($scope.ContainsKey($technique)) { throw "Duplicate ATT&CK technique $technique." }
        $scope[$technique]=$true
    }
    if($InputData.Cases -isnot [array]) { throw 'Cases must be an array.' }
    $ids=@{}
    foreach($case in $InputData.Cases) {
        Assert-EvaluationFields $case @('Id','Category','Status','StartedAt','EndedAt','TechniqueId','Alerts') @('ArtifactSHA256','Error') 'Case'
        Assert-EvaluationText $case.Id 'Case.Id'
        if($ids.ContainsKey($case.Id)) { throw "Duplicate case ID $($case.Id)." }
        $ids[$case.Id]=$true
        if($case.Category -isnot [string] -or $case.Category -cnotin @('Malware','Benign','Emulation')) { throw "Invalid category for $($case.Id)." }
        if($case.Status -isnot [string] -or $case.Status -cnotin @('Completed','Error')) { throw "Invalid status for $($case.Id)." }
        $start=ConvertTo-EvaluationTimestamp $case.StartedAt "$($case.Id).StartedAt"
        $end=ConvertTo-EvaluationTimestamp $case.EndedAt "$($case.Id).EndedAt"
        if($end -le $start) { throw "$($case.Id): EndedAt must follow StartedAt." }
        if($case.Category -ceq 'Emulation') {
            if($case.TechniqueId -isnot [string] -or $case.TechniqueId -cnotin $run.AttackScope) { throw "$($case.Id): emulation requires one technique in AttackScope." }
        } elseif($null -ne $case.TechniqueId) { throw "$($case.Id): only emulation cases can assert technique coverage." }
        if($case.Category -ceq 'Malware' -and $case.ArtifactSHA256 -isnot [string]) { throw "$($case.Id): malware requires ArtifactSHA256." }
        if($case.PSObject.Properties['ArtifactSHA256'] -and ($case.ArtifactSHA256 -isnot [string] -or $case.ArtifactSHA256 -notmatch '^[a-fA-F0-9]{64}$')) { throw "$($case.Id): invalid ArtifactSHA256." }
        if($case.Status -ceq 'Error') { Assert-EvaluationText $case.Error "$($case.Id).Error" }
        elseif($case.PSObject.Properties['Error']) { throw "$($case.Id): Completed case cannot have Error." }
        if($case.Alerts -isnot [array]) { throw "$($case.Id): Alerts must be an array." }
        foreach($alert in $case.Alerts) {
            Assert-EvaluationFields $alert @('Source','Timestamp','EvidenceRef') -Context 'Alert'
            if($alert.Source -isnot [string] -or $alert.Source -cnotin @('Sentinel','Defender')) { throw "$($case.Id): invalid alert source." }
            Assert-EvaluationText $alert.EvidenceRef "$($case.Id).EvidenceRef"
            $timestamp=ConvertTo-EvaluationTimestamp $alert.Timestamp "$($case.Id).Alert.Timestamp"
            if($timestamp -lt $start -or $timestamp -gt $end) { throw "$($case.Id): alert is outside the observation window." }
        }
    }
}

function Get-EvaluationRate([int]$Numerator,[int]$Denominator) {
    if($Denominator -eq 0) { return $null }
    return [math]::Round($Numerator/[double]$Denominator,6)
}

function Get-EvaluationLatency([double[]]$Seconds) {
    $sorted=@($Seconds | Sort-Object)
    if(-not $sorted.Count) { return [ordered]@{Count=0;Median=$null;P95=$null;Maximum=$null} }
    $middle=[int][math]::Floor($sorted.Count/2)
    $median=$sorted[$middle]
    if($sorted.Count % 2 -eq 0) { $median=($sorted[$middle-1]+$sorted[$middle])/2 }
    return [ordered]@{Count=$sorted.Count;Median=[math]::Round($median,6);P95=[math]::Round($sorted[[int][math]::Ceiling(0.95*$sorted.Count)-1],6);Maximum=[math]::Round($sorted[-1],6)}
}

function Get-EvaluationFirstAlert($Case,[string]$Source) {
    return @($Case.Alerts | Where-Object { $_.Source -ceq $Source } | Sort-Object { ConvertTo-EvaluationTimestamp $_.Timestamp 'Alert.Timestamp' } | Select-Object -First 1)
}

function Get-SentinelEvaluationSummary($InputData) {
    Assert-SentinelEvaluationInput $InputData
    $sources=[ordered]@{}
    foreach($source in @('Sentinel','Defender')) {
        $categories=[ordered]@{}
        foreach($category in @('Malware','Benign','Emulation')) {
            $trials=@($InputData.Cases | Where-Object { $_.Category -ceq $category })
            $completed=@($trials | Where-Object { $_.Status -ceq 'Completed' })
            $latencies=[Collections.Generic.List[double]]::new()
            foreach($case in $completed) {
                $first=@(Get-EvaluationFirstAlert $case $source)
                if($first.Count) {
                    $start=ConvertTo-EvaluationTimestamp $case.StartedAt 'StartedAt'
                    $detected=ConvertTo-EvaluationTimestamp $first[0].Timestamp 'Timestamp'
                    $latencies.Add(($detected-$start).TotalSeconds)
                }
            }
            $categories[$category]=[ordered]@{
                TotalTrials=$trials.Count;CompletedTrials=$completed.Count;ErrorTrials=$trials.Count-$completed.Count
                AlertedTrials=$latencies.Count;NoAlertTrials=$completed.Count-$latencies.Count
                AlertRate=(Get-EvaluationRate $latencies.Count $completed.Count)
                TimeToFirstAlertSeconds=(Get-EvaluationLatency $latencies.ToArray())
            }
        }
        $coverage=@(foreach($technique in $InputData.Run.AttackScope) {
            $trials=@($InputData.Cases | Where-Object { $_.Category -ceq 'Emulation' -and $_.TechniqueId -ceq $technique })
            $completed=@($trials | Where-Object { $_.Status -ceq 'Completed' })
            $alerted=@($completed | Where-Object { @(Get-EvaluationFirstAlert $_ $source).Count -gt 0 }).Count
            $status='NotTested'
            if($completed.Count) {
                $status='TestedNoDetection'
                if($alerted -eq $completed.Count) { $status='DetectedInAllTrials' }
                elseif($alerted -gt 0) { $status='DetectedInSomeTrials' }
            }
            [ordered]@{TechniqueId=$technique;CompletedTrials=$completed.Count;ErrorTrials=$trials.Count-$completed.Count;AlertedTrials=$alerted;Status=$status}
        })
        $tested=@($coverage | Where-Object { $_.CompletedTrials -gt 0 }).Count
        $observed=@($coverage | Where-Object { $_.AlertedTrials -gt 0 }).Count
        $sources[$source]=[ordered]@{
            Categories=$categories
            AttackCoverage=[ordered]@{ScopeTechniqueCount=$coverage.Count;TestedTechniqueCount=$tested;DetectedTechniqueCount=$observed;DetectedFractionOfTested=(Get-EvaluationRate $observed $tested);Techniques=$coverage}
        }
    }
    return [ordered]@{Schema=1;Run=$InputData.Run;IsSynthetic=($InputData.Run.EvidenceType -ceq 'Synthetic');Sources=$sources}
}

function ConvertTo-EvaluationMarkdownText($Value) {
    return ([string]$Value).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('|','&#124;').Replace('`','&#96;').Replace('[','&#91;').Replace(']','&#93;').Replace('*','&#42;').Replace('_','&#95;').Replace('\','&#92;')
}

function Format-EvaluationNumber($Value,[switch]$Rate) {
    if($null -eq $Value) { return 'N/A' }
    if($Rate) { return ([double]$Value*100).ToString('0.00',[Globalization.CultureInfo]::InvariantCulture)+'%' }
    return ([double]$Value).ToString('0.######',[Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-SentinelEvaluationMarkdown($Summary) {
    $lines=[Collections.Generic.List[string]]::new()
    $lines.Add('# SentinelLocal evaluation')
    $lines.Add('')
    if($Summary.IsSynthetic) { $lines.Add('**SYNTHETIC DATA - aggregation example only; not measured security performance.**') }
    else { $lines.Add('Measured input supplied by the operator; evidence and trial attribution require independent review.') }
    $lines.Add('')
    $lines.Add('Run: '+(ConvertTo-EvaluationMarkdownText $Summary.Run.Id))
    $lines.Add('')
    $lines.Add('Corpus: '+(ConvertTo-EvaluationMarkdownText $Summary.Run.CorpusId))
    $lines.Add('')
    $lines.Add('Sentinel: '+(ConvertTo-EvaluationMarkdownText $Summary.Run.SentinelVersion)+'; Windows: '+(ConvertTo-EvaluationMarkdownText $Summary.Run.WindowsVersion)+'; Defender: '+(ConvertTo-EvaluationMarkdownText $Summary.Run.DefenderVersion)+'; Sysmon: '+(ConvertTo-EvaluationMarkdownText $Summary.Run.SysmonVersion))
    $lines.Add('')
    $lines.Add('Config SHA256: '+$Summary.Run.ConfigSHA256)
    $lines.Add('')
    $lines.Add('Rates are per completed trial. Error trials are excluded and listed. No-alert trials are included in the rate denominator; latency covers alerted trials only. No completed trials means N/A.')
    foreach($source in @('Sentinel','Defender')) {
        $lines.Add('');$lines.Add('## '+$source);$lines.Add('')
        $lines.Add('| Trial category | Completed | Errors | Alerted | No alert | Rate | TTD median (s) | TTD p95 (s) | TTD max (s) |')
        $lines.Add('| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |')
        foreach($category in @('Malware','Benign','Emulation')) {
            $entry=$Summary.Sources[$source].Categories[$category]
            $label=@{Malware='Malware detection';Benign='Benign false positives';Emulation='Emulation detection'}[$category]
            $values=@($label,$entry.CompletedTrials,$entry.ErrorTrials,$entry.AlertedTrials,$entry.NoAlertTrials,(Format-EvaluationNumber $entry.AlertRate -Rate),(Format-EvaluationNumber $entry.TimeToFirstAlertSeconds.Median),(Format-EvaluationNumber $entry.TimeToFirstAlertSeconds.P95),(Format-EvaluationNumber $entry.TimeToFirstAlertSeconds.Maximum))
            $lines.Add('| '+($values -join ' | ')+' |')
        }
        $attack=$Summary.Sources[$source].AttackCoverage
        $lines.Add('');$lines.Add('ATT&CK '+(ConvertTo-EvaluationMarkdownText $Summary.Run.AttackVersion)+': '+$attack.DetectedTechniqueCount+'/'+$attack.TestedTechniqueCount+' tested techniques had an alert ('+(Format-EvaluationNumber $attack.DetectedFractionOfTested -Rate)+'); scope contains '+$attack.ScopeTechniqueCount+' techniques.')
        $lines.Add('');$lines.Add('| Technique | Completed | Errors | Alerted | Status |');$lines.Add('| --- | ---: | ---: | ---: | --- |')
        foreach($entry in $attack.Techniques) { $lines.Add('| '+(@($entry.TechniqueId,$entry.CompletedTrials,$entry.ErrorTrials,$entry.AlertedTrials,$entry.Status) -join ' | ')+' |') }
    }
    $lines.Add('');$lines.Add('ATT&CK results describe the supplied single-technique emulation trials, not every implementation of a technique or the full ATT&CK framework. An alert is not proof of prevention. p95 uses the nearest-rank method.')
    return ($lines -join [Environment]::NewLine)+[Environment]::NewLine
}
