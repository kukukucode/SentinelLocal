param([string]$Root=$PSScriptRoot,[string]$TrustedSignerThumbprint,[switch]$AllowUnsignedPackage)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
Test-SentinelPackage -Root $Root -TrustedSignerThumbprint $TrustedSignerThumbprint -AllowUnsigned:$AllowUnsignedPackage
