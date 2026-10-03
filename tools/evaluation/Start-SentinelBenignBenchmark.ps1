#Requires -RunAsAdministrator
param([string]$Root='C:\ProgramData\SentinelLocal',[string]$OutputDirectory=(Join-Path $env:TEMP ('SentinelLocal-benchmark-'+[guid]::NewGuid().ToString('N'))),[ValidateRange(1,100)][int]$Rounds=10,[ValidateRange(60,600)][int]$ObservationSeconds=120,[switch]$PreflightOnly)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'BenignBenchmark.ps1')
$packet=Invoke-SentinelBenignBenchmark -Root $Root -OutputDirectory $OutputDirectory -Rounds $Rounds -ObservationSeconds $ObservationSeconds -PreflightOnly:$PreflightOnly
Write-Host ('Measurement folder: '+$OutputDirectory)
if($packet.Status -in @('PreflightPassed','PreflightFailed')){
    Write-Host ('Preflight: '+$packet.Status+'. No trial commands were started; performance: N/A.')
    if($packet.Errors.Count){Write-Host 'Checks requiring attention:';foreach($reason in $packet.Errors){Write-Host $reason}}
    Write-Host ('Readiness report: '+(Join-Path $OutputDirectory 'readiness-before.json'))
    if($packet.Status -eq 'PreflightFailed'){exit 2}else{exit 0}
}
Write-Host ('Observation valid: '+$packet.Capture.ObservationValid+'; capture: '+$packet.Capture.CapturedTrials+'/'+$packet.Capture.TrialCount)
Write-Host ('Persist delay median / p95 / max seconds: '+$packet.Capture.PersistDelaySeconds.Median+' / '+$packet.Capture.PersistDelaySeconds.P95+' / '+$packet.Capture.PersistDelaySeconds.Maximum)
Write-Host 'Alert attribution still requires review; no detection performance rate was calculated.'
if(-not $packet.Capture.ObservationValid){$packet.Errors | Out-Host;exit 2}
