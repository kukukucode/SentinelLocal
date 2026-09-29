param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-tests-'+[guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$packageRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $packageRoot 'src\Common.ps1')
. (Get-SentinelSourcePath $packageRoot 'SysmonMonitoring.ps1')
. (Get-SentinelSourcePath $packageRoot 'Status.ps1')
if (Test-Path -LiteralPath $ScratchRoot) { throw 'Test directory already exists; refusing to overwrite.' }
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$results=[Collections.Generic.List[object]]::new()
function Assert([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Run-Test([string]$Name,[scriptblock]$Body) {
    try { & $Body; $results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'}); Write-Host ('PASS '+$Name) }
    catch { $results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message}); Write-Host ('FAIL '+$Name+': '+$_.Exception.Message) -ForegroundColor Red }
}
function New-ProbeRoot([string]$Name) {
    $path=Join-Path $ScratchRoot $Name
    New-Item -ItemType Directory -Path $path | Out-Null
    Copy-Item -LiteralPath (Get-SentinelSourcePath $packageRoot 'Config.json') -Destination $path
    return $path
}
function Add-Probe([string]$Path,[int]$Number) { Assert (Write-SentinelJsonLine -Path $Path -Data ([ordered]@{Type='Probe';Number=$Number})) 'Probe append failed' }
function Mock-NoEvents {
    $record=[Management.Automation.ErrorRecord]::new([Exception]::new('No matching events'),'NoMatchingEventsFound',[Management.Automation.ErrorCategory]::ObjectNotFound,$null)
    throw $record
}
function New-FakeEvents([int]$Count,[int]$Start=1,[datetime]$Base=[datetime]'2026-01-01T00:00:00Z') {
    return @(for ($index=$Start;$index -lt $Start+$Count;$index++) { [pscustomobject]@{RecordId=[long]$index;Id=1116;TimeCreated=$Base.AddSeconds($index)} })
}
function Select-FakeEvents($Events,[string]$FilterXPath,[long]$MaxEvents,[switch]$Oldest) {
    $items=@($Events)
    if ($FilterXPath -match 'EventRecordID=(\d+)') { $items=@($items | Where-Object { $_.RecordId -eq [long]$Matches[1] }) }
    elseif ($FilterXPath -match 'EventRecordID > (\d+)') { $minimum=[long]$Matches[1]; $items=@($items | Where-Object { $_.RecordId -gt $minimum }) }
    $items=@($items | Sort-Object RecordId -Descending:(-not $Oldest) | Select-Object -First $MaxEvents)
    if (-not $items.Count) { Mock-NoEvents }
    return $items
}
function Start-ProbeProcess([string]$Command) {
    $info=[Diagnostics.ProcessStartInfo]::new(); $info.FileName=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new(); $process.StartInfo=$info; [void]$process.Start()
    return [pscustomobject]@{Process=$process;Out=$process.StandardOutput.ReadToEndAsync();Err=$process.StandardError.ReadToEndAsync()}
}

Run-Test 'All package scripts parse on Windows PowerShell' {
    foreach ($file in Get-ChildItem -LiteralPath $packageRoot -Recurse -Filter '*.ps1') {
        $tokens=$null; $errors=$null; [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
        Assert ($errors.Count -eq 0) ($file.Name+': '+(($errors | ForEach-Object Message)-join '; '))
    }
    foreach ($name in Get-SentinelPackageFiles) { Assert (Test-Path -LiteralPath (Get-SentinelSourcePath $packageRoot $name)) ('Package file missing: '+$name) }
}
Run-Test 'Valid chained records pass checkpoint verification' {
    $root=New-ProbeRoot 'valid'; $path=Join-Path $root 'logs\probe.jsonl'; Add-Probe $path 1; Add-Probe $path 2
    $check=Get-SentinelLogVerification $path; Assert ($check.Valid -and $check.Lines -eq 2) $check.Detail
}
Run-Test 'Suffix deletion is detected and writer refuses reanchoring' {
    $root=New-ProbeRoot 'truncated'; $path=Join-Path $root 'logs\probe.jsonl'; Add-Probe $path 1; Add-Probe $path 2
    $lines=[IO.File]::ReadAllLines($path); [IO.File]::WriteAllText($path,$lines[0]+[Environment]::NewLine,[Text.UTF8Encoding]::new($true))
    Assert (-not (Get-SentinelLogVerification $path).Valid) 'Truncation passed verification'
    function Write-EventLog { }
    Assert (-not (Write-SentinelJsonLine $path ([ordered]@{Type='Probe';Number=3}))) 'Writer accepted a truncated log'
}
Run-Test 'Entire log deletion is detected through remaining checkpoint' {
    $root=New-ProbeRoot 'deleted'; $path=Join-Path $root 'logs\probe.jsonl'; Add-Probe $path 1
    Remove-Item -LiteralPath $path
    Assert (-not (Get-SentinelLogVerification $path).Valid) 'Missing log passed verification'
}
Run-Test 'Prefix deletion and record modification are detected' {
    $root=New-ProbeRoot 'prefix'; $path=Join-Path $root 'logs\probe.jsonl'; Add-Probe $path 1; Add-Probe $path 2
    $lines=[IO.File]::ReadAllLines($path); [IO.File]::WriteAllText($path,$lines[1]+[Environment]::NewLine,[Text.UTF8Encoding]::new($true))
    Assert (-not (Get-SentinelLogVerification $path).Valid) 'Prefix removal passed verification'
    $root=New-ProbeRoot 'modified'; $path=Join-Path $root 'logs\probe.jsonl'; Add-Probe $path 1
    $line=[IO.File]::ReadAllText($path).Replace('"Number":1','"Number":9'); [IO.File]::WriteAllText($path,$line,[Text.UTF8Encoding]::new($true))
    Assert (-not (Get-SentinelLogVerification $path).Valid) 'Modified record passed verification'
}
Run-Test 'Retention trims only a contiguous prefix and keeps chain anchored' {
    $root=New-ProbeRoot 'retention'; $path=Join-Path $root 'logs\probe.jsonl'
    Add-SentinelChainedRecord $path ([ordered]@{Type='Old';Timestamp=(Get-Date).AddDays(-60).ToString('o')})
    Add-Probe $path 1
    Add-SentinelChainedRecord $path ([ordered]@{Type='ClockMovedBack';Timestamp=(Get-Date).AddDays(-60).ToString('o')})
    Invoke-SentinelJsonRetention $path (Get-Date).AddDays(-30)
    $check=Get-SentinelLogVerification $path; Assert ($check.Valid -and $check.Lines -eq 2) $check.Detail
    Add-Probe $path 2; Assert (Get-SentinelLogVerification $path).Valid 'Append after retention failed'
}
Run-Test 'Empty retained stream preserves anchor for later appends' {
    $root=New-ProbeRoot 'empty-retention'; $path=Join-Path $root 'logs\probe.jsonl'
    Add-SentinelChainedRecord $path ([ordered]@{Type='Old';Timestamp=(Get-Date).AddDays(-60).ToString('o')})
    Invoke-SentinelJsonRetention $path (Get-Date).AddDays(-30)
    Assert (Get-SentinelLogVerification $path).Valid 'Empty retained log failed'
    Add-Probe $path 1; Assert (Get-SentinelLogVerification $path).Valid 'New append lost retained anchor'
}
Run-Test 'Legacy checkpoint is migrated without resetting its last hash' {
    $root=New-ProbeRoot 'legacy'; $path=Join-Path $root 'logs\probe.jsonl'; Add-Probe $path 1
    $statePath=Get-SentinelChainPath $path; $old=Get-Content $statePath -Raw | ConvertFrom-Json
    Write-SentinelAtomicJson $statePath ([ordered]@{LastHash=$old.LastHash;LastUpdated=$old.LastUpdated;LogPath=$path})
    Add-Probe $path 2
    Assert (Get-SentinelLogVerification $path).Valid 'Legacy checkpoint migration failed'
}
Run-Test 'Missing checkpoint cannot silently authorize existing log' {
    $root=New-ProbeRoot 'missing-checkpoint'; $path=Join-Path $root 'logs\probe.jsonl'; Add-Probe $path 1
    Remove-Item -LiteralPath (Get-SentinelChainPath $path)
    Assert (-not (Get-SentinelLogVerification $path).Valid) 'Unanchored log accepted'
}
Run-Test 'Interrupted append recovers committed log using pending checkpoint' {
    $root=New-ProbeRoot 'recovery'; $path=Join-Path $root 'logs\probe.jsonl'; Add-Probe $path 1
    $state=Get-SentinelChainPath $path; $before=Get-Content $state -Raw | ConvertFrom-Json
    Add-Probe $path 2; $after=Get-Content $state -Raw | ConvertFrom-Json
    Write-SentinelAtomicJson $state $before; Write-SentinelAtomicJson ($state+'.pending') ([ordered]@{Before=$before;After=$after;Operation='Append'})
    Assert (Get-SentinelLogVerification $path).Valid 'Committed append was not recovered'
    Assert (-not (Test-Path -LiteralPath ($state+'.pending'))) 'Pending transaction was not removed'
}
Run-Test 'Concurrent writers and retention do not lose records' {
    $root=New-ProbeRoot 'concurrent'
    for ($number=0;$number -lt 4;$number++) { Add-SentinelChainedRecord (Join-Path $root ('logs\concurrent'+$number+'.jsonl')) ([ordered]@{Type='Old';Timestamp=(Get-Date).AddDays(-60).ToString('o')}) }
    $children=@()
    try {
        foreach ($role in @('Writer','Writer','Retention')) {
            $id=$children.Count
            $command="& '{0}' -PackageRoot '{1}' -ScratchRoot '{2}' -Role '{3}' -WriterId {4}" -f (Join-Path $PSScriptRoot 'ConcurrentLogProbe.ps1').Replace("'","''"),$packageRoot.Replace("'","''"),$root.Replace("'","''"),$role,$id
            $children+=Start-ProbeProcess $command
        }
        foreach ($child in $children) { Assert ($child.Process.WaitForExit(45000)) 'Concurrency probe timed out'; Assert ($child.Process.ExitCode -eq 0) $child.Err.Result }
        for ($number=0;$number -lt 4;$number++) {
            $path=Join-Path $root ('logs\concurrent'+$number+'.jsonl'); Invoke-SentinelJsonRetention $path (Get-Date).AddDays(-30)
            $check=Get-SentinelLogVerification $path; Assert ($check.Valid -and $check.Lines -eq 24) ('Lost current records: '+$check.Detail+' count='+$check.Lines)
        }
    } finally { foreach ($child in $children) { if (-not $child.Process.HasExited) { $child.Process.Kill() }; $child.Process.Dispose() } }
}
Run-Test 'Defender scan failure propagates to worker retry path' {
    $root=New-ProbeRoot 'scan-failed'; $file=Join-Path $root 'harmless.txt'; Set-Content $file 'harmless'
    function Start-MpScan { [CmdletBinding()]param($ScanType,$ScanPath); throw 'Mock scan failure' }
    function Write-EventLog { }
    $failed=$false
    try { & (Get-SentinelSourcePath $packageRoot 'Response.ps1') -Root $root -FilePath $file -Score 40 | Out-Null } catch { $failed=$_.Exception.Message -like '*Mock scan failure*' }
    Assert $failed 'Response returned success after failed scan'
}
Run-Test 'Missing target and completed scan have distinct outcomes' {
    $root=New-ProbeRoot 'scan-outcomes'
    function Start-MpScan { [CmdletBinding()]param($ScanType,$ScanPath) }
    function Get-MpThreatDetection { [CmdletBinding()]param(); return @() }
    function Start-Sleep { }
    $missing=& (Get-SentinelSourcePath $packageRoot 'Response.ps1') -Root $root -FilePath (Join-Path $root 'missing.txt') -Score 40
    Assert ($missing.Status -eq 'TargetMissing' -and -not $missing.DefenderCustomScanStarted) 'Missing target was marked scanned'
    $file=Join-Path $root 'harmless.txt'; Set-Content $file 'harmless'
    $scanned=& (Get-SentinelSourcePath $packageRoot 'Response.ps1') -Root $root -FilePath $file -Score 40
    Assert ($scanned.Status -eq 'Completed' -and $scanned.DefenderCustomScanStarted) 'Completed scan not recorded'
}
Run-Test 'More than 300 unread events are consumed without gaps' {
    $fakeEvents=New-FakeEvents 650
    function Get-WinEvent { [CmdletBinding()]param($LogName,$FilterXPath,[long]$MaxEvents,[switch]$Oldest); Select-FakeEvents $fakeEvents $FilterXPath $MaxEvents -Oldest:$Oldest }
    $seen=@(); $cursor=0L; $time=''
    do { $batch=Get-SentinelEventBatch -LogName Fake -Cursor $cursor -CursorTime $time -Ids @(1116); $seen+=@($batch.Events | ForEach-Object RecordId); if ($batch.Events.Count) { $last=$batch.Events[-1]; $cursor=$last.RecordId; $time=$last.TimeCreated.ToString('o') } } while ($batch.Events.Count)
    Assert ($seen.Count -eq 650 -and ($seen -join ',') -eq ((1..650)-join ',')) 'Oldest-first batching skipped or reordered records'
}
Run-Test 'Cleared/refilled log and overwritten cursor are detected' {
    $fakeEvents=New-FakeEvents 650 -Base ([datetime]'2026-02-01T00:00:00Z')
    function Get-WinEvent { [CmdletBinding()]param($LogName,$FilterXPath,[long]$MaxEvents,[switch]$Oldest); Select-FakeEvents $fakeEvents $FilterXPath $MaxEvents -Oldest:$Oldest }
    $batch=Get-SentinelEventBatch -LogName Fake -Cursor 600 -CursorTime ([datetime]'2026-01-01T00:10:00Z').ToString('o') -Ids @(1116)
    Assert ($batch.Reset -and $batch.Gap -and $batch.Events[0].RecordId -eq 1) 'Refilled log with reused RecordIDs was not detected'
    $fakeEvents=New-FakeEvents 151 -Start 500
    $batch=Get-SentinelEventBatch -LogName Fake -Cursor 100 -CursorTime ([datetime]'2026-01-01T00:01:40Z').ToString('o') -Ids @(1116)
    Assert ($batch.Reset -and $batch.Events.Count -eq 151) 'Overwritten cursor anchor was not detected'
}
Run-Test 'Event access failure is not mistaken for an empty log' {
    function Get-WinEvent { [CmdletBinding()]param($LogName,$FilterXPath,[long]$MaxEvents,[switch]$Oldest); throw 'Access denied mock' }
    $failed=$false; try { Get-SentinelEventBatch -LogName Fake -Cursor 1 -Ids @(1116) | Out-Null } catch { $failed=$true }
    Assert $failed 'Event access error was hidden'
}
Run-Test 'Busy process requires fresh heartbeat and bounded request time' {
    $heartbeat=[pscustomobject]@{Status='Busy';ResponseWorkerProcessId=$PID;LastUpdated=[datetimeoffset]::Now.AddSeconds(-100).ToString('o');RequestStartedAt=[datetimeoffset]::Now.ToString('o')}
    Assert (-not (Test-SentinelHeartbeat $heartbeat 30 180).Healthy) 'Stale Busy heartbeat accepted'
    $heartbeat.LastUpdated=[datetimeoffset]::Now.ToString('o'); $heartbeat.RequestStartedAt=[datetimeoffset]::Now.AddSeconds(-200).ToString('o')
    Assert (-not (Test-SentinelHeartbeat $heartbeat 30 180).Healthy) 'Overdue live process accepted'
    $heartbeat.RequestStartedAt=[datetimeoffset]::Now.ToString('o'); Assert (Test-SentinelHeartbeat $heartbeat 30 180).Healthy 'Fresh bounded progress rejected'
}
Run-Test 'Response subprocess success and timeout are both handled' {
    $root=New-ProbeRoot 'bounded'
    foreach ($name in @('Common.ps1','LogIntegrity.ps1','EventMonitoring.ps1','ResponseExecution.ps1','OperationalSafety.ps1','Deployment.ps1','PackageTrust.ps1','PolicyManagement.ps1','DetectionSafety.ps1','TaskIntegrity.ps1','Invoke-SentinelResponse.ps1')) { Copy-Item -LiteralPath (Get-SentinelSourcePath $packageRoot $name) -Destination $root }
    $request=Join-Path $root 'request.json'; Set-Content $request '{}'
    $responsePath=Join-Path $root 'Response.ps1'; Set-Content $responsePath 'param($Root,$RequestFile); [pscustomobject]@{Status="Completed"}' -Encoding UTF8
    $completed=Invoke-SentinelBoundedResponse -Root $root -RequestFile $request -TimeoutSeconds 20 -HeartbeatSeconds 1
    Assert ($completed.Status -eq 'Completed') 'Subprocess result not propagated'
    Set-Content $responsePath 'param($Root,$RequestFile); Start-Sleep -Seconds 30; [pscustomobject]@{Status="Completed"}' -Encoding UTF8
    $timedOut=$false; $watch=[Diagnostics.Stopwatch]::StartNew()
    try { Invoke-SentinelBoundedResponse -Root $root -RequestFile $request -TimeoutSeconds 1 -HeartbeatSeconds 1 | Out-Null } catch { $timedOut=$_.Exception.Message -like '*timed out*' }
    Assert ($timedOut -and $watch.Elapsed.TotalSeconds -lt 10) 'Hung response did not terminate within timeout'
}
Run-Test 'Script arguments are extracted without executing or downloading them' {
    $targets=@(Get-SentinelScriptTargets 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' 'powershell.exe -File "C:\Users\Test User\demo.ps1"')
    Assert ($targets.Count -eq 1 -and $targets[0] -eq 'C:\Users\Test User\demo.ps1') 'Quoted script path not extracted'
    $targets=@(Get-SentinelScriptTargets 'C:\Windows\System32\cmd.exe' 'cmd.exe /c C:\Temp\demo.cmd')
    Assert ($targets.Count -eq 1) 'cmd script path not extracted'
    Assert (@(Get-SentinelScriptTargets 'C:\Windows\powershell.exe' 'powershell -File .\relative.ps1').Count -eq 0) 'Relative path incorrectly interpreted as SYSTEM working directory'
    Assert (@(Get-SentinelScriptTargets 'C:\Windows\powershell.exe' 'powershell -Command https://example.invalid/demo.ps1').Count -eq 0) 'Remote script treated as a local target'
}
Run-Test 'Exceptions require a matching hash, reason and unexpired lifetime' {
    $root=New-ProbeRoot 'exceptions'; $file=Join-Path $root 'harmless.txt'; Set-Content $file 'harmless'
    $entry=[pscustomobject]@{SHA256=(Get-FileHash $file).Hash;Reason='Test';ExpiresAt=[datetimeoffset]::Now.AddHours(1).ToString('o');SignerThumbprint=''}
    $config=[pscustomobject]@{Exceptions=@($entry)}
    Assert (Test-SentinelException $file $config) 'Active exact-hash exception rejected'
    $entry.ExpiresAt=[datetimeoffset]::Now.AddHours(-1).ToString('o'); Assert (-not (Test-SentinelException $file $config)) 'Expired exception accepted'
    $entry.ExpiresAt=[datetimeoffset]::Now.AddHours(1).ToString('o'); Set-Content $file 'changed'; Assert (-not (Test-SentinelException $file $config)) 'Changed file accepted'
}
Run-Test 'Disabled Sysmon integration does not query or alter its channel' {
    function Get-WinEvent { throw 'Should not query disabled Sysmon' }
    Read-SentinelSysmon -Root $ScratchRoot -Config ([pscustomobject]@{Sysmon=[pscustomobject]@{Enabled=$false}})
}
Run-Test 'Audit export creates independently verifiable snapshots' {
    $root=New-ProbeRoot 'export'; $path=Join-Path $root 'logs\probe.jsonl'; Add-Probe $path 1; Add-Probe $path 2
    $destination=Join-Path $ScratchRoot 'collector'
    $snapshot=& (Get-SentinelSourcePath $packageRoot 'Export-SentinelAudit.ps1') -Root $root -DestinationPath $destination
    Assert (Test-Path -LiteralPath (Join-Path $snapshot 'manifest.json')) 'Export manifest missing'
    Assert (Get-SentinelLogVerification (Join-Path $snapshot 'logs\probe.jsonl')).Valid 'Exported chain does not verify'
    $manifest=Get-Content (Join-Path $snapshot 'manifest.json') -Raw | ConvertFrom-Json
    Assert ($manifest.Files[0].SHA256 -eq (Get-FileHash (Join-Path $snapshot 'logs\probe.jsonl')).Hash) 'Snapshot digest mismatch'
    $failed=$false; try { & (Get-SentinelSourcePath $packageRoot 'Export-SentinelAudit.ps1') -Root $root -DestinationPath (Join-Path $root 'self-export') | Out-Null } catch { $failed=$true }
    Assert $failed 'Export recursively targeted installation folder'
}
Run-Test 'Self-generated response command cannot cause a scan feedback loop' {
    $root=New-ProbeRoot 'internal-response'; $task=Join-Path $root 'Invoke-SentinelResponse.ps1'; Copy-Item -LiteralPath (Get-SentinelSourcePath $packageRoot 'Invoke-SentinelResponse.ps1') -Destination $task
    foreach($name in Get-SentinelCriticalFileNames) {Copy-Item -LiteralPath (Get-SentinelSourcePath $packageRoot $name) -Destination (Join-Path $root $name) -Force}
    $entries=@(foreach($name in Get-SentinelCriticalFileNames){[ordered]@{Name=$name;Path=(Join-Path $root $name);SHA256=(Get-FileHash -LiteralPath (Join-Path $root $name)).Hash}})
    Write-SentinelAtomicJson (Join-Path $root 'state\integrity-baseline.json') ([ordered]@{Files=$entries})
    $request=Join-Path $root 'state\response-queue\processing\20260101000000000_11111111-1111-1111-1111-111111111111.json'
    $command="& '{0}' -Root '{1}' -RequestFile '{2}' -ResultPath '{3}'" -f $task,$root,$request,($request+'.result')
    $info=[pscustomobject]@{ExecutablePath=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe');CommandLine='powershell.exe -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))}
    Assert (Test-SentinelInternalResponse $root $info) 'Our verified command would be rescanned'
    $modified=$command+'; Write-Output extra'
    $info.CommandLine='powershell.exe -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($modified))
    Assert (-not (Test-SentinelInternalResponse $root $info)) 'Additional commands received an internal exemption'
}
Run-Test 'Enabled Sysmon records events and queues literal script arguments' {
    $root=New-ProbeRoot 'sysmon-enabled'; $scriptFile=Join-Path $root 'test script.ps1'; Set-Content $scriptFile '# harmless'
    $data=[ordered]@{ProcessId='1234';ParentProcessId='100';Image=(Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe');CommandLine=('powershell -File "'+$scriptFile+'"');UtcTime='2026-01-01 00:00:00.000';ProcessGuid='{11111111-1111-1111-1111-111111111111}'}
    $xml='<Event><EventData>'+(@($data.Keys | ForEach-Object { '<Data Name="'+$_+'">'+[Security.SecurityElement]::Escape([string]$data[$_])+'</Data>' })-join '')+'</EventData></Event>'
    $event=[pscustomobject]@{RecordId=1L;Id=1;TimeCreated=[datetime]'2026-01-01T00:00:00Z';Xml=$xml}; $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
    $fakeEvents=@($event)
    function Get-WinEvent { [CmdletBinding()]param($LogName,$FilterXPath,[long]$MaxEvents,[switch]$Oldest); Select-FakeEvents $fakeEvents $FilterXPath $MaxEvents -Oldest:$Oldest }
    $config=Get-Content (Join-Path $root 'Config.json') -Raw | ConvertFrom-Json; $config.Sysmon.Enabled=$true
    $queued=[Collections.Generic.List[string]]::new()
    Read-SentinelSysmon -Root $root -Config $config -ScoreProcess {param($process) [pscustomobject]@{Score=55;Reasons=@('Mock')}} -QueueResponse {param($path,$processIdValue,$score,$process) $queued.Add($path)}
    Assert ($queued.Count -eq 2 -and $queued.Contains($scriptFile)) 'Sysmon did not queue the actual local script'
    Assert (Get-SentinelLogVerification (Join-Path $root 'logs\sysmon-events.jsonl')).Valid 'Sysmon log failed verification'
    Assert ((Get-Content (Join-Path $root 'state\sysmon-cursor.json') -Raw | ConvertFrom-Json).RecordId -eq 1) 'Sysmon cursor not committed'
}
Run-Test 'Worker retries failed scan and deduplicates only completed scans' {
    $root=New-ProbeRoot 'worker-integration'
    foreach ($name in @('Common.ps1','LogIntegrity.ps1','EventMonitoring.ps1','ResponseExecution.ps1','OperationalSafety.ps1','Deployment.ps1','PackageTrust.ps1','PolicyManagement.ps1','DetectionSafety.ps1','TaskIntegrity.ps1','ResponseWorker.ps1','Invoke-SentinelResponse.ps1')) { Copy-Item -LiteralPath (Get-SentinelSourcePath $packageRoot $name) -Destination $root }
    [IO.File]::AppendAllText((Join-Path $root 'Common.ps1'),"`nfunction Write-EventLog { }`n")
    $workerPath=Join-Path $root 'ResponseWorker.ps1'
    $workerText=[IO.File]::ReadAllText($workerPath).Replace('Global\SentinelLocalResponseWorker','Global\SentinelLocalTestWorker_'+[guid]::NewGuid().ToString('N'))
    [IO.File]::WriteAllText($workerPath,$workerText,[Text.UTF8Encoding]::new($true))
    $config=Get-Content (Join-Path $root 'Config.json') -Raw | ConvertFrom-Json
    $config.ResponseRetryDelaySeconds=1; $config.ResponseTimeoutSeconds=10; $config.NormalResponseTimeoutSeconds=10; $config.ResponseWorkerHeartbeatSeconds=1
    Write-SentinelAtomicJson (Join-Path $root 'Config.json') $config
    $response=@'
param($Root,$RequestFile)
$request=Get-Content -LiteralPath $RequestFile -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$request.Attempts -eq 0) { throw 'Mock first scan fails' }
[pscustomobject]@{Status='Completed';File=[pscustomobject]@{SHA256=(Get-FileHash -LiteralPath $request.FilePath -Algorithm SHA256).Hash}}
'@
    Set-Content -LiteralPath (Join-Path $root 'Response.ps1') -Value $response -Encoding UTF8
    $target=Join-Path $root 'harmless.txt'; Set-Content $target 'harmless worker fixture'
    $requestPath=Join-Path $root 'state\response-queue\high\probe.json'
    Write-SentinelAtomicJson $requestPath ([ordered]@{RequestId='test';FilePath=$target;Score=80;ProcessIdValue=0;Priority='High';Attempts=0})
    $command="& '{0}' -Root '{1}'" -f $workerPath.Replace("'","''"),$root.Replace("'","''")
    $child=Start-ProbeProcess $command
    try {
        $deadline=(Get-Date).AddSeconds(25); $completed=$false
        do {
            Start-Sleep -Milliseconds 200
            $alerts=Join-Path $root 'logs\alerts.jsonl'
            if (Test-Path $alerts) { $entries=@(Get-Content $alerts -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json }); $completed=@($entries | Where-Object Type -eq 'ResponseRequestCompleted').Count -gt 0 }
        } until ($completed -or (Get-Date) -gt $deadline -or $child.Process.HasExited)
        Assert $completed ('Worker did not complete retry; '+$(if($child.Process.HasExited){$child.Err.Result}else{'deadline'}))
        Assert (@($entries | Where-Object Type -eq 'ResponseRequestRetry').Count -eq 1) 'Failed scan was not retried exactly once'
        $hashState=Get-Content (Join-Path $root 'state\response-hash-dedupe.json') -Raw | ConvertFrom-Json
        Assert (@($hashState).Count -eq 1 -and $hashState.SHA256 -eq (Get-FileHash $target).Hash) 'Completed scan did not populate dedupe state'
        Assert (-not (Test-Path $requestPath)) 'Completed request still in queue'
    } finally { if (-not $child.Process.HasExited) { $child.Process.Kill() }; $child.Process.Dispose() }
}
Run-Test 'EncodedCommand capture is inert and preserves script content' {
    $root=New-ProbeRoot 'encoded-command'; $marker=Join-Path $root 'must-not-exist.txt'
    $content="Set-Content -LiteralPath '"+$marker+"' -Value 'must not execute'"
    $command='powershell -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($content))
    $path=Save-SentinelDecodedCommand $root $command
    Assert ([IO.File]::ReadAllText($path) -ceq $content) 'Captured command changed'
    Assert (-not (Test-Path -LiteralPath $marker)) 'Captured command was executed'
    Assert ($null -eq (Save-SentinelDecodedCommand $root 'powershell -enc AAA')) 'Invalid Base64 did not remain a nonfatal visibility limitation'
    Assert ($null -eq (Save-SentinelDecodedCommand $root $command -ExecutablePath 'C:\Tools\Other.exe')) 'Non-PowerShell command was decoded'
}
Run-Test 'Lightweight status detects checkpoint/log deletion' {
    $root=New-ProbeRoot 'log-health'; $path=Join-Path $root 'logs\probe.jsonl'; Add-Probe $path 1
    Assert (@(Get-SentinelLogHealth $root | Where-Object { -not $_.Healthy }).Count -eq 0) 'Valid log reported unhealthy'
    Remove-Item -LiteralPath $path
    Assert (@(Get-SentinelLogHealth $root | Where-Object { -not $_.Healthy }).Count -eq 1) 'Deleted log missing from status'
}
Run-Test 'GUI constructs and disposes without showing a window in smoke mode' {
    $root=New-ProbeRoot 'ui'
    $command="& '{0}' -Root '{1}' -SmokeTest" -f (Get-SentinelSourcePath $packageRoot 'Show-SentinelStatus.ps1').Replace("'","''"),$root.Replace("'","''")
    $child=Start-ProbeProcess $command
    try { Assert ($child.Process.WaitForExit(30000)) 'GUI construction timed out'; Assert ($child.Process.ExitCode -eq 0) $child.Err.Result }
    finally { if (-not $child.Process.HasExited) { $child.Process.Kill() }; $child.Process.Dispose() }
}
$results | Format-Table -AutoSize
Write-SentinelAtomicJson (Join-Path $ScratchRoot 'test-results.json') @($results)
Write-Host ('Results saved to '+$ScratchRoot)
if (@($results | Where-Object { -not $_.Passed }).Count) { exit 1 }
exit 0
