param([string]$ScratchRoot=(Join-Path $env:TEMP ('SentinelLocal-sysmon-integration-'+[guid]::NewGuid().ToString('N'))))
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'src\Common.ps1')
. (Join-Path $repo 'src\SysmonMonitoring.ps1')
. (Join-Path $repo 'tools\sysmon\SysmonSetup.ps1')
. (Join-Path $repo 'tools\evaluation\DurableObservation.ps1')
. (Join-Path $repo 'tools\evaluation\BenignBenchmark.ps1')
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Real Sysmon integration requires an administrator CI token.'}
if(Test-Path $ScratchRoot){throw 'Scratch directory exists.'}
New-Item -ItemType Directory -Path $ScratchRoot | Out-Null
$results=@();$installed=$null
try {
    $zip=Join-Path $ScratchRoot 'Sysmon.zip'
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
    Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $ScratchRoot 'vendor')
    $binary=Join-Path $ScratchRoot 'vendor\Sysmon64.exe'
    # Reviewed Microsoft Sysmon 15.22, 2026-10-03. A vendor update requires
    # reviewing the new signature/version and changing this independent pin.
    $hash='83D31F2478DC6716CFDBF69E5C384BF043072B5F0D8D7B2EEA365F709FDA4352'
    $installed=Install-SentinelSysmon -BinaryPath $binary -ExpectedSHA256 $hash -Apply -AcceptEula
    $config=Get-Content (Join-Path $repo 'config\Config.json') -Raw | ConvertFrom-Json;$config.Sysmon.Enabled=$true
    if((Initialize-SentinelProcessMonitor $config) -ne 'Sysmon'){throw 'Installed source did not initialize.'}
    $root=Join-Path $ScratchRoot 'recorded';New-Item -ItemType Directory -Path $root | Out-Null
    $trials=@()
    foreach($command in @(@('hostname.exe',''),@('whoami.exe',''),@('cmd.exe','/d /c echo SentinelLocal durable smoke'))){
        $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=Join-Path $env:WINDIR ('System32\'+$command[0]);$info.Arguments=$command[1]
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $child=[Diagnostics.Process]::new();$child.StartInfo=$info
        try {
            $start=[datetimeoffset]::Now;[void]$child.Start();$stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
            if(-not $child.WaitForExit(10000)){$child.Kill();$child.WaitForExit();throw 'Benign integration command timed out.'}
            $child.WaitForExit();if($child.ExitCode -ne 0){throw 'Benign integration command failed.'}
            $trials+=@([pscustomobject]@{Id=$command[0];ProcessId=$child.Id;Image=$info.FileName;SHA256=(Get-FileHash $info.FileName).Hash;StartedAt=$start;EndedAt=[datetimeoffset]::Now;ProcessCreatedAt=$child.StartTime.ToUniversalTime().ToString('o');Arguments=$command[1]})
        } finally {$child.Dispose()}
    }
    # Every process has already exited before the reader starts. The test fails
    # if the implementation tries to recover metadata from a live CIM query.
    function Get-CimInstance {throw 'Integration must use durable creation data.'}
    $timer=[Diagnostics.Stopwatch]::StartNew();$matched=@()
    do {
        Read-SentinelSysmon $root $config {param($p) [pscustomobject]@{Score=0;Reasons=@()}} {throw 'No real Defender/response actions are allowed in integration.'}
        $records=@(Get-Content (Join-Path $root 'logs\process-events.jsonl') -ErrorAction SilentlyContinue | ForEach-Object {$_ | ConvertFrom-Json})
        $matched=@(foreach($trial in $trials){
            $candidates=@($records | Where-Object {$_.MetadataComplete -and $_.Process.ProcessId -eq $trial.ProcessId -and $_.Process.ExecutablePath -ieq $trial.Image -and $_.Process.ObservedSHA256 -ieq $trial.SHA256 -and [datetimeoffset]$_.Process.CreationDate -ge $trial.StartedAt.AddSeconds(-1) -and [datetimeoffset]$_.Process.CreationDate -le $trial.EndedAt.AddSeconds(1)})
            if($candidates.Count -eq 1){[pscustomobject]@{Command=$trial.Id;ProcessId=$trial.ProcessId;ProcessGuid=$candidates[0].Process.ProcessGuid;CommandLine=$candidates[0].Process.CommandLine;SHA256=$candidates[0].Process.ObservedSHA256}}
        })
        if($matched.Count -eq 3){break};Start-Sleep -Milliseconds 500
    } while($timer.Elapsed.TotalSeconds -lt 30)
    if($matched.Count -ne 3){throw ('Only '+$matched.Count+'/3 exited commands retained complete metadata.')}
    $packet=[pscustomobject]@{Kind='BenignObservationPacket';CommandsSucceeded=$true;Root=$root;Trials=@($trials | ForEach-Object {[pscustomobject]@{Id=$_.Id;ProcessId=$_.ProcessId;ExecutablePath=$_.Image;SHA256=$_.SHA256;ProcessCreatedAt=$_.ProcessCreatedAt;Arguments=$_.Arguments}})}
    $proof=Get-SentinelDurableObservation $packet
    if(-not $proof.Complete){throw 'Durable proof did not match all three native process creation times and command arguments.'}
    foreach($trial in $packet.Trials){$trial | Add-Member NoteProperty StartedAt (@($trials | Where-Object Id -eq $trial.Id)[0].StartedAt.ToString('o'));$trial | Add-Member NoteProperty ObservationEndedAt ([datetimeoffset]::Now.AddSeconds(120).ToString('o'))}
    $measurement=Get-SentinelBenchmarkSummary $packet.Trials $records $true
    if(-not $measurement.ObservationValid -or $measurement.CapturedTrials -ne 3 -or $measurement.CaptureFraction -ne 1 -or $measurement.DetectionPerformanceMeasured){throw 'Real Sysmon measurement matching failed or claimed malware efficacy.'}
    if(-not (Get-SentinelLogVerification (Join-Path $root 'logs\process-events.jsonl')).Valid){throw 'Recorded identity chain failed.'}
    $matched | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $ScratchRoot 'captured-processes.json') -Encoding UTF8
    $results+=@([pscustomobject]@{Test='Real Sysmon retains complete metadata for three exited Windows commands';Passed=$true;Detail='3/3; no live CIM metadata lookup or Defender scans';Version=$installed.Binary.Version})
    Write-Host 'PASS Real Sysmon retained complete identity for 3/3 exited commands.'
} catch {
    $results+=@([pscustomobject]@{Test='Real Sysmon retains complete metadata for three exited Windows commands';Passed=$false;Detail=$_.Exception.Message})
    Write-Host ('FAIL '+$_.Exception.Message)
} finally {
    if($installed){
        $exe=Join-Path $installed.StageRoot 'Sysmon64.exe'
        & $exe -u | Out-Host
        if($LASTEXITCODE -ne 0){$results+=@([pscustomobject]@{Test='CI Sysmon cleanup';Passed=$false;Detail='Uninstall failed'})}
    }
    $results | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $ScratchRoot 'test-results.json') -Encoding UTF8
}
if(@($results | Where-Object {-not $_.Passed}).Count){exit 1}else{exit 0}
