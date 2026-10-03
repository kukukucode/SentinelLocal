. (Join-Path $PSScriptRoot 'Readiness.ps1')

function Get-SentinelBenignScenarios {
    # Fixed, local commands only. Never accept a user-supplied executable,
    # command string, downloaded sample, or script payload here.
    @(
        [pscustomobject]@{Id='hostname';FileName='hostname.exe';Arguments=''},
        [pscustomobject]@{Id='identity';FileName='whoami.exe';Arguments=''},
        [pscustomobject]@{Id='shell-echo';FileName='cmd.exe';Arguments='/d /c echo SentinelLocal benign smoke'}
    )
}
function Invoke-SentinelBenignCommand($Scenario) {
    $path=Join-Path $env:WINDIR ('System32\'+$Scenario.FileName)
    $signature=Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
    if([string]$signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') { throw ('Expected a valid Microsoft Windows binary: '+$path) }
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$path;$info.Arguments=$Scenario.Arguments
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info
    try {
        $started=[datetimeoffset]::Now
        [void]$process.Start()
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(10000)) { $process.Kill();$process.WaitForExit();throw ('Benign command exceeded 10 seconds: '+$Scenario.Id) }
        $process.WaitForExit()
        $ended=[datetimeoffset]::Now
        if($process.ExitCode -ne 0) { throw ('Benign command failed: '+$Scenario.Id+'; exit='+$process.ExitCode) }
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -ne $hash) { throw 'Executable changed during the observation.' }
        return [pscustomobject]@{
            Id=$Scenario.Id;ExecutablePath=$path;Arguments=$Scenario.Arguments;SHA256=$hash
            Signer=$signature.SignerCertificate.Subject;ProcessId=$process.Id
            ProcessCreatedAt=$process.StartTime.ToUniversalTime().ToString('o')
            StartedAt=$started.ToString('o');ProcessEndedAt=$ended.ToString('o');ExitCode=$process.ExitCode
            StandardOutput=$stdout.Result;StandardError=$stderr.Result;TelemetryReviewed=$false
        }
    } finally { $process.Dispose() }
}
function Wait-SentinelObservationBaseline([string]$Root,[int]$TimeoutSeconds=60) {
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        $report=Get-SentinelEvaluationReadiness -Root $Root
        if($report.ReadyForBenignTrials) { return $report }
        $unready=@($report.Checks | Where-Object { $_.State -ne 'Pass' })
        # The runner itself may be queued for referenced-script scanning.
        # Wait only for a Busy worker, with every other baseline check passing.
        # Do not tolerate stopped tasks, stale heartbeats or access failures.
        if($unready.Count -ne 1 -or $unready[0].Name -ne 'ResponseWorker heartbeat/process' -or [string]$unready[0].Value -notlike '*status is "Busy"*' -or $timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) { return $report }
        Start-Sleep -Seconds 2
    } while($true)
}
function Invoke-SentinelBenignObservation([string]$Root,[string]$OutputDirectory) {
    $rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\')
    $outputPath=[IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
    if($outputPath -ieq $rootPath -or $outputPath.StartsWith($rootPath+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Write observations outside the monitored installation.' }
    foreach($candidate in @($rootPath,$outputPath)) {
        $ancestor=$candidate
        while($ancestor) {
            if((Test-Path -LiteralPath $ancestor -ErrorAction Stop) -and ((Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Observation paths must not traverse reparse points.' }
            $parent=Split-Path -Parent $ancestor
            if($parent -eq $ancestor) { break };$ancestor=$parent
        }
    }
    if(Test-Path -LiteralPath $outputPath) { throw 'Output directory already exists; choose a new observation directory.' }
    $before=Wait-SentinelObservationBaseline -Root $rootPath
    [void](New-Item -ItemType Directory -Path $outputPath -ErrorAction Stop)
    Write-SentinelAtomicJson (Join-Path $outputPath 'readiness-before.json') $before
    $trials=@();$failure=$null;$after=$null
    if(-not $before.ReadyForBenignTrials) { $failure='Measurement preflight failed; no trial commands were started.' }
    else {
        foreach($scenario in Get-SentinelBenignScenarios) {
            try {
                $trial=Invoke-SentinelBenignCommand $scenario
                # Give asynchronous telemetry a short observation window. This
                # window is recorded, never presented as proof of no detection.
                Start-Sleep -Seconds 5
                $trial | Add-Member -NotePropertyName ObservationEndedAt -NotePropertyValue ([datetimeoffset]::Now.ToString('o'))
                $trials+=@($trial)
                Write-SentinelAtomicJson (Join-Path $outputPath 'commands.json') $trials
            } catch { $failure=$_.Exception.Message;break }
        }
        $after=Wait-SentinelObservationBaseline -Root $rootPath
        Write-SentinelAtomicJson (Join-Path $outputPath 'readiness-after.json') $after
        if(-not $after.ReadyForBenignTrials -or $after.Environment.ConfigSHA256 -ne $before.Environment.ConfigSHA256) {
            $failure='Postflight is unready or configuration changed; trial telemetry requires investigation.'
        }
    }
    $packet=[ordered]@{
        Schema=1;Kind='BenignObservationPacket';Root=$rootPath;CapturedAt=[datetimeoffset]::Now.ToString('o')
        PerformanceMeasured=$false;ReviewRequired=$true
        CommandsSucceeded=($null -eq $failure -and $trials.Count -eq 3)
        Error=$failure;Environment=$before.Environment;Trials=$trials
        Scope='Three local benign command launches with pre/postflight. No automatic alert correlation or false-positive rate. Continuous telemetry and alert attribution require review; short processes may escape CIM metadata capture.'
    }
    Write-SentinelAtomicJson (Join-Path $outputPath 'observation.json') $packet
    return [pscustomobject]$packet
}
