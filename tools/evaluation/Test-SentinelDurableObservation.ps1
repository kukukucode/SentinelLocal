param([Parameter(Mandatory=$true)][string]$ObservationDirectory)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'DurableObservation.ps1')
$packet=Get-Content -LiteralPath (Join-Path $ObservationDirectory 'observation.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$report=Get-SentinelDurableObservation $packet
$report.Trials | Select-Object Id,ProcessId,State,MatchingRecords | Format-Table | Out-Host
Write-Host ('Durable process capture: '+$report.CapturedCount+'/3; Complete='+$report.Complete+'. No performance rate was calculated.')
$report
if(-not $report.Complete){exit 2}
