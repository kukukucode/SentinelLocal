param([Parameter(Mandatory=$true)][string]$BinaryPath,[Parameter(Mandatory=$true)][string]$ExpectedSHA256,[switch]$Apply,[switch]$AcceptEula)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'SysmonSetup.ps1')
Install-SentinelSysmon -BinaryPath $BinaryPath -ExpectedSHA256 $ExpectedSHA256 -Apply:$Apply -AcceptEula:$AcceptEula
