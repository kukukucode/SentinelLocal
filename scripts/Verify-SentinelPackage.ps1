param([string]$Root=$PSScriptRoot,[string]$TrustedSignerThumbprint,[switch]$AllowUnsignedPackage)
$ErrorActionPreference='Stop'
$commonPath=Join-Path $PSScriptRoot 'Common.ps1'
if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) { $commonPath=Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Common.ps1' }
. $commonPath
if(-not $PSBoundParameters.ContainsKey('Root')) { $Root=Get-SentinelSourceRoot $PSScriptRoot }
Test-SentinelPackage -Root $Root -TrustedSignerThumbprint $TrustedSignerThumbprint -AllowUnsigned:$AllowUnsignedPackage
