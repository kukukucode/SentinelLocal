param([string]$Root='C:\ProgramData\SentinelLocal',[Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'BenignObservation.ps1')
$packet=Invoke-SentinelBenignObservation -Root $Root -OutputDirectory $OutputDirectory
$packet.Trials | Select-Object Id,ProcessId,ExitCode,StartedAt,ObservationEndedAt | Format-Table -AutoSize
Write-Host ('Observation packet: '+(Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) 'observation.json'))
Write-Host ('Commands succeeded: '+$packet.CommandsSucceeded+'. Telemetry review is required; no performance rate was calculated.')
if($packet.Error) {
    Write-Host $packet.Error
    foreach($file in @('readiness-before.json','readiness-after.json')) {
        $path=Join-Path $OutputDirectory $file
        if(Test-Path -LiteralPath $path) {
            $report=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
            $unready=@($report.Checks | Where-Object { $_.State -ne 'Pass' })
            if($unready.Count) { Write-Host ('Checks requiring attention ('+$file+'):');$unready | Select-Object Name,State,Value | Format-List }
        }
    }
    exit 2
}
exit 0
