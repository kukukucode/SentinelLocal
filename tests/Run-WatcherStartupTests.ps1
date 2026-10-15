param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-watcher-startup-'+[guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$packageRoot=Split-Path -Parent $PSScriptRoot
. (Join-Path $packageRoot 'src\Common.ps1')
if(Test-Path -LiteralPath $ScratchRoot) { throw 'Scratch directory already exists.' }
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$results=[Collections.Generic.List[object]]::new()
function Assert([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message } }
function Test([string]$Name,[scriptblock]$Body) {
    try { & $Body; $results.Add([pscustomobject]@{Test=$Name;Passed=$true;Detail='OK'}); Write-Host ('PASS '+$Name) }
    catch { $results.Add([pscustomobject]@{Test=$Name;Passed=$false;Detail=$_.Exception.Message}); Write-Host ('FAIL '+$Name+': '+$_.Exception.Message) }
}
$tokens=$null;$parseErrors=$null
$watcherPath=Join-Path $packageRoot 'src\Watcher.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($watcherPath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count) { throw 'Watcher source has syntax errors.' }
$snapshotFunction=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-PersistenceSnapshot'},$true)
. ([scriptblock]::Create($snapshotFunction.Extent.Text))
$loop=$ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.WhileStatementAst] } | Select-Object -First 1
if(-not $loop) { throw 'Cannot locate Watcher monitoring loop.' }
# Run the actual startup path, ending before the infinite loop. Isolate the
# singleton name and release it; all system telemetry is mocked below.
$source=[IO.File]::ReadAllText($watcherPath)
$startupBody=$source.Substring($ast.ParamBlock.Extent.EndOffset,$loop.Extent.StartOffset-$ast.ParamBlock.Extent.EndOffset)
$startupBody=$startupBody.Replace('Global\SentinelLocalWatcher',('Local\SentinelLocalWatcherTest_'+[guid]::NewGuid().ToString('N')))
$startupSource=$ast.ParamBlock.Extent.Text+"`ntry {`n"+$startupBody+"`n} finally { if (`$watcherMutex) { `$watcherMutex.ReleaseMutex(); `$watcherMutex.Dispose() } }"
function Fixture([string]$Name) {
    $root=Join-Path $ScratchRoot $Name
    New-Item -ItemType Directory -Path $root | Out-Null
    foreach($file in Get-SentinelPackageFiles) { Copy-Item -LiteralPath (Get-SentinelSourcePath $packageRoot $file) -Destination (Join-Path $root $file) }
    [IO.File]::WriteAllText((Join-Path $root 'Watcher-startup-fixture.ps1'),$startupSource,[Text.UTF8Encoding]::new($true))
    return $root
}
function Test-Path {
    [CmdletBinding()]param([Parameter(Position=0)]$Path,$LiteralPath,$PathType)
    if($Path -like 'Registry::*' -or $Path -eq 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp') { return $false }
    $arguments=@{}
    if($PSBoundParameters.ContainsKey('Path')) { $arguments.Path=$Path }
    if($PSBoundParameters.ContainsKey('LiteralPath')) { $arguments.LiteralPath=$LiteralPath }
    if($PSBoundParameters.ContainsKey('PathType')) { $arguments.PathType=$PathType }
    Microsoft.PowerShell.Management\Test-Path @arguments
}
function Get-ChildItem {
    [CmdletBinding()]param([Parameter(Position=0)]$Path,$LiteralPath,[switch]$Directory,[switch]$Force,[switch]$File,[switch]$Recurse,$Filter)
    if($Path -eq 'Registry::HKEY_USERS' -or $Path -eq 'C:\Users') { return }
    $arguments=@{}
    foreach($key in $PSBoundParameters.Keys) { $arguments[$key]=$PSBoundParameters[$key] }
    Microsoft.PowerShell.Management\Get-ChildItem @arguments
}
function Get-ScheduledTask {
    [CmdletBinding()]param()
    if(-not $script:EmptyTelemetry) {
        [pscustomobject]@{TaskName='Fixture';TaskPath='\';Actions=@(
            [pscustomobject]@{Execute='C:\Windows\fixture.exe';Arguments='first'},
            [pscustomobject]@{Execute='C:\Windows\fixture.exe';Arguments='second'}
        )}
    }
}
function Get-CimInstance {
    [CmdletBinding()]param([Parameter(Position=0)]$ClassName)
    if($ClassName -ne 'Win32_Service') { throw 'Unexpected CIM probe.' }
    if(-not $script:EmptyTelemetry) { [pscustomobject]@{Name='Fixture';StartName='LocalSystem';StartMode='Auto';PathName='C:\Windows\fixture.exe'} }
}
function Register-CimIndicationEvent {
    [CmdletBinding()]param($Query,$SourceIdentifier)
    if($Query -ne 'SELECT * FROM Win32_ProcessStartTrace') { throw 'Unexpected subscription.' }
}
function Get-WinEvent {
    [CmdletBinding()]param($LogName,$MaxEvents)
    if($LogName -ne 'Microsoft-Windows-Windows Defender/Operational') { throw 'Unexpected event probe.' }
    [pscustomobject]@{RecordId=42L;TimeCreated=Get-Date}
}
function Write-EventLog {} # No host event-log writes or Defender scans.

Test 'Persistence snapshot returns all generic-list entries without the PS 5.1 binder error' {
    $script:EmptyTelemetry=$false
    $snapshot=@(Get-PersistenceSnapshot)
    Assert ($snapshot.Count -eq 3) 'Task actions or service missing from snapshot.'
    Assert (@($snapshot | Where-Object Type -eq Task).Count -eq 2) 'Multiple task actions collapsed.'
    Assert ($snapshot[2].Type -eq 'Service' -and $snapshot[2].Value -eq 'LocalSystem|Auto|C:\Windows\fixture.exe') 'Service identity changed.'
    $script:EmptyTelemetry=$true
    Assert (@(Get-PersistenceSnapshot).Count -eq 0) 'Empty telemetry did not return an empty sequence.'
}
Test 'Actual Watcher startup commits persistence and writes its first live heartbeat' {
    $root=Fixture 'success';$script:EmptyTelemetry=$false
    & (Join-Path $root 'Watcher-startup-fixture.ps1') -Root $root
    $heartbeat=Get-Content -LiteralPath (Join-Path $root 'state\watcher-heartbeat.json') -Raw | ConvertFrom-Json
    Assert ($heartbeat.Status -eq 'Running' -and $heartbeat.WatcherProcessId -eq $PID -and $heartbeat.LastDefenderRecordId -eq 42) 'Initial heartbeat missing or invalid.'
    $snapshot=Get-Content -LiteralPath (Join-Path $root 'state\persistence-snapshot.json') -Raw | ConvertFrom-Json
    Assert ($snapshot.Schema -eq 1 -and @($snapshot.Items).Count -eq 3) 'Initial persistence was not durably saved.'
    $check=Get-SentinelLogVerification (Join-Path $root 'logs\alerts.jsonl')
    Assert ($check.Valid -and $check.Lines -eq 3) 'Initial persistence alerts failed chain verification.'
    Assert (-not (Test-Path -LiteralPath (Join-Path $root 'logs\errors.jsonl'))) 'Startup logged unexpected errors.'
}
Test 'Fatal initial persistence failure is logged with phase and rethrown without a Running heartbeat' {
    $root=Fixture 'failure';$script:EmptyTelemetry=$false
    Write-SentinelAtomicJson (Join-Path $root 'state\persistence-snapshot.json') @{Schema=999;Items=@()}
    $failed=$false
    try { & (Join-Path $root 'Watcher-startup-fixture.ps1') -Root $root } catch { $failed=$_.Exception.Message -like '*Invalid durable persistence snapshot*' }
    Assert $failed 'Startup swallowed a persistence failure.'
    Assert (-not (Test-Path -LiteralPath (Join-Path $root 'state\watcher-heartbeat.json'))) 'Failed startup claimed Running.'
    $errorRecord=Get-Content -LiteralPath (Join-Path $root 'logs\errors.jsonl') -Tail 1 | ConvertFrom-Json
    Assert ($errorRecord.Operation -eq 'Initialize monitoring' -and $errorRecord.Context.Phase -eq 'Commit initial persistence comparison' -and $errorRecord.Context.ScriptStackTrace) 'Fatal startup lacked phase/stack diagnostics.'
    Assert ((Get-SentinelLogVerification (Join-Path $root 'logs\errors.jsonl')).Valid) 'Diagnostic chain is invalid.'
}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $ScratchRoot 'test-results.json') -Encoding UTF8
$failed=@($results | Where-Object { -not $_.Passed }).Count
Write-Host ('Watcher startup tests: '+($results.Count-$failed)+'/'+$results.Count+' passed')
if($failed) { exit 1 } else { exit 0 }
