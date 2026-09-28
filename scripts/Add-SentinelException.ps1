#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][string]$FilePath,[Parameter(Mandatory=$true)][string]$Reason,[Parameter(Mandatory=$true)][datetimeoffset]$ExpiresAt,[switch]$RequireSigner,[string]$Root='C:\ProgramData\SentinelLocal')
$ErrorActionPreference='Stop'
$commonPath=Join-Path $PSScriptRoot 'Common.ps1'
if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) { $commonPath=Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Common.ps1' }
. $commonPath
if (-not $Reason.Trim() -or $ExpiresAt -le [datetimeoffset]::Now) { throw 'A reason and a future expiration are required.' }
if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { throw 'Exception target must be an existing file.' }
$configPath=Join-Path $Root 'Config.json'
$hash=(Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
$thumbprint=''
if ($RequireSigner) {
    $signature=Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw 'The file has no valid Authenticode signer.' }
    $thumbprint=$signature.SignerCertificate.Thumbprint
}
$config=Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
$config.Exceptions=@($config.Exceptions | Where-Object { $_.SHA256 -ine $hash }) + [pscustomobject]@{SHA256=$hash;SignerThumbprint=$thumbprint;Reason=$Reason;ExpiresAt=$ExpiresAt.ToString('o')}
[void](Set-SentinelConfigTransaction -Root $Root -Candidate $config -Reason ('Add hash exception: '+$Reason))
Write-Output 'Hash-bound exception added. Restart SentinelLocal tasks to reload configuration. Defender-confirmed detections are not exempted.'
