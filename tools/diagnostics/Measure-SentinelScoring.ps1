param(
    [string]$Root='C:\ProgramData\SentinelLocal',
    [string]$OutputDirectory=(Join-Path ([IO.Path]::GetTempPath()) ('SentinelLocal-scoring-diagnostic-'+[guid]::NewGuid().ToString('N'))),
    [ValidateRange(1,30)][int]$SampleCount=12
)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5){throw 'Use Windows PowerShell 5.1.'}
$repo=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repo 'src\Common.ps1')
$rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\');$Root=$rootPath
$output=[IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
if($output -ieq $rootPath -or $output.StartsWith($rootPath+'\',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $output)){throw 'Choose a new output folder outside the installation.'}
Assert-SentinelLogPath $output
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'src\Watcher.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Reviewed Watcher source has parse errors.'}
# Import only these function definitions, never the Watcher startup/loop or installed scripts.
foreach($name in @('Get-ProcessScore','Get-FileSignatureStatus','Test-RandomishSegment')){
    $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    if(-not $definition){throw ('Scoring definition missing: '+$name)}
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:ProbeErrors=[Collections.Generic.List[object]]::new()
# Scoring failures belong to this diagnostic only; do not append production logs.
function Write-SentinelError {
    param($Root,$Component,$Operation,$Exception,$Context,$Severity)
    $script:ProbeErrors.Add([pscustomobject]@{Component=$Component;Operation=$Operation;Error=$Exception.Message})
}
$directory=Join-Path $rootPath 'state\sysmon-analysis'
Assert-SentinelSysmonDataPath $directory
$selected=[Collections.Generic.List[object]]::new();$snapshotBytes=0L;$unitsRead=0
$mutex=Enter-SentinelLogLock (Join-Path $rootPath 'state\sysmon-analysis.queue')
try{
    $files=@(foreach($lane in @('processing','pending')){
        $lanePath=Join-Path $directory $lane;Assert-SentinelSysmonDataPath $lanePath
        if(Test-Path -LiteralPath $lanePath){Get-ChildItem -LiteralPath $lanePath -Filter '*.json' -File -ErrorAction Stop | Sort-Object Name}
    })
    foreach($file in @($files | Select-Object -First 4)){
        Assert-SentinelSysmonDataPath $file.FullName
        $snapshotBytes+=$file.Length
        if($snapshotBytes -gt 8MB){throw 'Selected diagnostic prefix exceeds the 8 MiB snapshot budget; no queue changes were made.'}
        $unit=Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        Assert-SentinelSysmonQueueUnit $unit
        [void](Read-SentinelSysmonAnalysisProgress $file.FullName $unit)
        $unitsRead++
        for($index=[int]$unit.NextIndex;$index -lt @($unit.Events).Count -and $selected.Count -lt $SampleCount;$index++){
            if([int]$unit.Events[$index].Id -eq 1){$selected.Add($unit.Events[$index])}
        }
        if($selected.Count -ge $SampleCount){break}
    }
}finally{$mutex.ReleaseMutex();$mutex.Dispose()}
# All potentially slow file/Authenticode work runs after the queue lock is released.
$rows=[Collections.Generic.List[object]]::new();$timer=[Diagnostics.Stopwatch]::StartNew()
foreach($event in $selected){
    $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=4MB
    $text=[IO.StringReader]::new([string]$event.Xml);$reader=[Xml.XmlReader]::Create($text,$settings)
    try{$document=[Xml.XmlDocument]::new();$document.XmlResolver=$null;$document.Load($reader)}finally{$reader.Dispose();$text.Dispose()}
    $data=@{};foreach($node in $document.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")){$data[[string]$node.GetAttribute('Name')]=[string]$node.InnerText}
    $process=ConvertFrom-SentinelSysmonProcess $data
    foreach($pass in 1..2){
        $details=New-SentinelScoringTimings;$phase=[Diagnostics.Stopwatch]::StartNew();$score=Get-ProcessScore $process -Timings $details -RecordedIdentity
        $row=[pscustomobject]@{RecordId=[long]$event.RecordId;EventTime=[string]$event.TimeCreated;Image=[IO.Path]::GetFileName([string]$process.ExecutablePath);PathSHA256=(Get-SentinelStringHash ([string]$process.ExecutablePath));Pass=$pass;Seconds=$phase.Elapsed.TotalSeconds;Score=[int]$score.Score;ScoringDetails=$details;SignatureAssessment=$score.SignatureAssessment}
        $rows.Add($row)
        Write-Host ('Scoring sample: '+($row | ConvertTo-Json -Depth 5 -Compress))
    }
    if($timer.Elapsed.TotalSeconds -ge 60){break}
}
New-Item -ItemType Directory -Path $output | Out-Null
$report=[ordered]@{Schema=1;CheckedAt=[datetimeoffset]::Now.ToString('o');ReadOnly=$true;TrialProcessesLaunched=$false;QueueAcknowledged=$false;UnitsRead=$unitsRead;SelectedProcessEvents=$selected.Count;ProfiledProcessEvents=($rows.Count/2);Seconds=$timer.Elapsed.TotalSeconds;Rows=$rows.ToArray();Errors=$script:ProbeErrors.ToArray();Scope='Current files for an unacknowledged FIFO prefix; second pass uses this diagnostic process cache. Not historical signature truth, sustained throughput, or detection performance.'}
Write-SentinelAtomicJson (Join-Path $output 'scoring.json') $report
Write-Host ('Diagnostic folder: '+$output)
Write-Host ('Profiled process events: '+($rows.Count/2)+'; errors='+$script:ProbeErrors.Count+'. No updates, queue acknowledgements, trials or configuration changes.')
