function Invoke-SentinelBoundedResponse {
    param([string]$Root,[string]$RequestFile,[int]$TimeoutSeconds,[int]$HeartbeatSeconds=5,[scriptblock]$Heartbeat)
    if ($TimeoutSeconds -lt 1 -or $HeartbeatSeconds -lt 1) { throw 'Invalid response timeout/heartbeat interval.' }
    $resultPath = $RequestFile + '.result'
    if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath -Force }
    $task = Join-Path $Root 'Invoke-SentinelResponse.ps1'
    $command = "& '{0}' -Root '{1}' -RequestFile '{2}' -ResultPath '{3}'" -f $task.Replace("'","''"),$Root.Replace("'","''"),$RequestFile.Replace("'","''"),$resultPath.Replace("'","''")
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $child = [System.Diagnostics.Process]::new(); $child.StartInfo=$info
    $started = [datetimeoffset]::Now; $lastBeat=$started.AddSeconds(-$HeartbeatSeconds); $hasStarted=$false
    try {
        [void]$child.Start()
        $hasStarted=$true
        $stdout=$child.StandardOutput.ReadToEndAsync(); $stderr=$child.StandardError.ReadToEndAsync()
        while (-not $child.HasExited) {
            if (([datetimeoffset]::Now - $started).TotalSeconds -ge $TimeoutSeconds) {
                $child.Kill(); [void]$child.WaitForExit(5000)
                throw ('Response timed out after {0} seconds.' -f $TimeoutSeconds)
            }
            if (([datetimeoffset]::Now - $lastBeat).TotalSeconds -ge $HeartbeatSeconds) {
                if ($Heartbeat) { & $Heartbeat $child.Id $started.ToString('o') }
                $lastBeat=[datetimeoffset]::Now
            }
            [void]$child.WaitForExit(250)
        }
        if ($child.ExitCode -ne 0) { throw ('Response child failed: ' + $stderr.Result) }
        if (-not (Test-Path -LiteralPath $resultPath)) { throw 'Response child did not produce a result.' }
        $result=Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        if ($result.Status -notin @('Completed','TargetMissing','NoScanRequired','Excepted')) { throw 'Response child returned an unsuccessful result.' }
        return $result
    } finally {
        if ($hasStarted -and -not $child.HasExited) { $child.Kill(); [void]$child.WaitForExit(5000) }
        $child.Dispose()
        if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath -Force }
    }
}
