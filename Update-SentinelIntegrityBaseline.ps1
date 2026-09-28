#Requires -RunAsAdministrator
param(
    [string]$Root = "C:\ProgramData\SentinelLocal"
)

$ErrorActionPreference = "Stop"
. (Join-Path $Root "Common.ps1")

$stateDir = Join-Path $Root "state"
New-Item $stateDir -ItemType Directory -Force | Out-Null
$baselinePath = Join-Path $stateDir "integrity-baseline.json"

$entries = @()
foreach ($name in Get-SentinelCriticalFileNames) {
    $path = Join-Path $Root $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }

    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop
    $entries += [pscustomobject]@{
        Name=$name
        Path=$path
        SHA256=$hash.Hash
        Length=[long]$item.Length
        LastWriteTimeUtc=$item.LastWriteTimeUtc.ToString("o")
    }
}

Write-SentinelAtomicJson $baselinePath ([ordered]@{
    Version="1.2.0"
    CreatedAt=(Get-Date).ToString("o")
    Root=$Root
    Files=$entries
})

Write-Host "SentinelLocal integrity baseline updated:"
Write-Host $baselinePath
