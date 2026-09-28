#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][string]$FilePath,[Parameter(Mandatory=$true)][string]$Reason,[Parameter(Mandatory=$true)][datetimeoffset]$ExpiresAt,[switch]$RequireSigner,[string]$Root='C:\ProgramData\SentinelLocal')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
if (-not $Reason.Trim() -or $ExpiresAt -le [datetimeoffset]::Now) { throw 'A reason and a future expiration are required.' }
if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { throw 'Exception target must be an existing file.' }
$configPath=Join-Path $Root 'Config.json'
$baselinePath=Join-Path $Root 'state\integrity-baseline.json'
$baseline=Get-Content -LiteralPath $baselinePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
$entry=@($baseline.Files | Where-Object { $_.Name -eq 'Config.json' })
if ($entry.Count -ne 1 -or $entry[0].SHA256 -ne (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash) { throw 'Configuration differs from its integrity baseline; review that change before adding an exception.' }
$hash=(Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
$thumbprint=''
if ($RequireSigner) {
    $signature=Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw 'The file has no valid Authenticode signer.' }
    $thumbprint=$signature.SignerCertificate.Thumbprint
}
$config=Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
$config.Exceptions=@($config.Exceptions | Where-Object { $_.SHA256 -ine $hash }) + [pscustomobject]@{SHA256=$hash;SignerThumbprint=$thumbprint;Reason=$Reason;ExpiresAt=$ExpiresAt.ToString('o')}
Write-SentinelAtomicJson $configPath $config
# Update only the reviewed configuration entry, never rebaseline other files.
$item=Get-Item -LiteralPath $configPath
$entry[0].SHA256=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
$entry[0].Length=$item.Length; $entry[0].LastWriteTimeUtc=$item.LastWriteTimeUtc.ToString('o')
Write-SentinelAtomicJson $baselinePath $baseline
Write-Output 'Hash-bound exception added. Restart SentinelLocal tasks to reload configuration. Defender-confirmed detections are not exempted.'
