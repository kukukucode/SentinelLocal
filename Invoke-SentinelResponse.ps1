param([string]$Root,[string]$RequestFile,[string]$ResultPath)
$ErrorActionPreference='Stop'
try {
    . (Join-Path $PSScriptRoot 'Common.ps1')
    $result = & (Join-Path $PSScriptRoot 'Response.ps1') -Root $Root -RequestFile $RequestFile
    Write-SentinelAtomicJson -Path $ResultPath -Data $result
    exit 0
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
