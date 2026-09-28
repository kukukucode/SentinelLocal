#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true)]
param([Parameter(Mandatory=$true,ParameterSetName='Apply')][string]$PolicyPath,[Parameter(Mandatory=$true,ParameterSetName='Restore')][string]$RestoreBackupPath,[Parameter(Mandatory=$true)][string]$Reason,[string]$Root='C:\ProgramData\SentinelLocal',[switch]$RestartTasks)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$config=Get-Content -LiteralPath (Join-Path $Root 'Config.json') -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
if($PSCmdlet.ParameterSetName -eq 'Restore') {
    $backup=Get-Content -LiteralPath $RestoreBackupPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if($backup.Schema -ne 1 -or -not $backup.ConfigBase64) { throw 'Invalid policy backup.' }
    $candidate=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($backup.ConfigBase64)).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
    if($candidate.Version -ne $config.Version) { throw 'Policy restore must match the installed package version.' }
} else {
    $patch=Get-Content -LiteralPath $PolicyPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $candidate=Merge-SentinelPolicy $config $patch
}
Assert-SentinelConfig $candidate
[void](Assert-SentinelBaseline $Root)
if($PSCmdlet.ShouldProcess($Root,'Save validated policy, configuration backup and administration audit')) {
    Set-SentinelConfigTransaction $Root $candidate $Reason
    if($RestartTasks) {
        Stop-SentinelDeploymentTasks $Root
        $started=[datetimeoffset]::Now
        foreach($name in @('SentinelLocal Response Worker','SentinelLocal Watcher','SentinelLocal Integrity Monitor')) { Start-ScheduledTask -TaskName $name -ErrorAction Stop }
        Wait-SentinelDeploymentReady $Root $candidate.Version $started
    }
}
