. (Join-Path $PSScriptRoot 'Readiness.ps1')

function Compare-SentinelDurableObservation($Packet,$Records) {
    if($Packet.Kind -ne 'BenignObservationPacket' -or -not $Packet.CommandsSucceeded -or @($Packet.Trials).Count -ne 3){throw 'A successful three-command observation packet is required.'}
    $matches=@(foreach($trial in $Packet.Trials){
        $created=[datetimeoffset]::Parse([string]$trial.ProcessCreatedAt)
        $candidates=@($Records | Where-Object {
            $_.Type -eq 'ProcessCreated' -and $_.Source -eq 'Sysmon' -and $_.MetadataComplete -and
            $_.Process.ProcessId -eq $trial.ProcessId -and $_.Process.ExecutablePath -ieq $trial.ExecutablePath -and
            $_.Process.ObservedSHA256 -ieq $trial.SHA256 -and
            [math]::Abs(([datetimeoffset]::Parse([string]$_.Process.CreationDate)-$created).TotalMilliseconds) -le 100 -and
            [string]$_.Process.CommandLine -match ([regex]::Escape([string]$trial.Arguments)+'\s*$')
        })
        [pscustomobject]@{Id=$trial.Id;ProcessId=$trial.ProcessId;State=$(if($candidates.Count -eq 1){'Captured'}else{'Unverified'});MatchingRecords=$candidates.Count;Evidence=$(if($candidates.Count -eq 1){$candidates[0]}else{$null})}
    })
    $captured=@($matches | Where-Object State -eq Captured)
    $unique=@($captured | ForEach-Object {$_.Evidence.Process.ProcessGuid} | Sort-Object -Unique)
    return [pscustomobject]@{Schema=1;Kind='DurableProcessObservation';CapturedAt=[datetimeoffset]::Now.ToString('o');CapturedCount=$captured.Count;Complete=($captured.Count -eq 3 -and $unique.Count -eq 3);Trials=$matches;PerformanceMeasured=$false;ReviewRequired=$true;Scope='Process identity capture only; no malware detection, false-positive rate or continuous-coverage claim.'}
}

function Get-SentinelDurableObservation($Packet) {
    $path=Join-Path ([IO.Path]::GetFullPath([string]$Packet.Root)) 'logs\process-events.jsonl'
    $mutex=Enter-SentinelLogLock $path
    try {
        $checkpoint=Get-SentinelChainPath $path
        if(Test-Path -LiteralPath ($checkpoint+'.pending')){throw 'Process log transaction is pending; retry without repairing it.'}
        if(-not (Get-SentinelLogVerification $path).Valid){throw 'Process evidence log failed chain verification.'}
        $records=@(Get-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop | ForEach-Object {$_ | ConvertFrom-Json -ErrorAction Stop})
        return Compare-SentinelDurableObservation $Packet $records
    } finally {$mutex.ReleaseMutex();$mutex.Dispose()}
}
