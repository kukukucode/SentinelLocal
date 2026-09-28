param([string]$Root=$PSScriptRoot,[Parameter(Mandatory=$true)][string]$OutputDirectory,[string]$CertificateThumbprint)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
if(Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory already exists; refusing to overwrite a package.' }
$base=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
$output=[IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')+'\'
if($output.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)) { throw 'Package output must be outside source root.' }
$certificate=$null
if($CertificateThumbprint) {
    if($CertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Invalid certificate thumbprint.' }
    $certificate=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$CertificateThumbprint) -ErrorAction Stop
    if(-not $certificate.HasPrivateKey -or @($certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' }).Count -eq 0) { throw 'A code-signing certificate with a private key is required.' }
}
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$files=@()
foreach($name in @((Get-SentinelPackageFiles)+@('README.md','README_JP.txt','CHANGELOG.txt','docs/OPERATIONS_JP.md','docs/PILOT_JP.md'))) {
    $source=Get-SentinelPackagePath $Root $name
    $destination=Join-Path $OutputDirectory $name
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination
    $files += [ordered]@{Name=$name;SHA256=(Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash;Length=(Get-Item -LiteralPath $destination).Length}
}
$config=Get-Content -LiteralPath (Join-Path $Root 'Config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$manifestPath=Join-Path $OutputDirectory 'package.manifest.json'
Write-SentinelAtomicJson $manifestPath ([ordered]@{Schema=1;Version=$config.Version;CreatedAt=(Get-Date).ToString('o');Files=$files})
if($certificate) {
    Add-Type -AssemblyName System.Security
    $cms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($manifestPath)),$true)
    $signer=[Security.Cryptography.Pkcs.CmsSigner]::new($certificate)
    $signer.DigestAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    $cms.ComputeSignature($signer);[IO.File]::WriteAllBytes($manifestPath+'.p7s',$cms.Encode())
}
Test-SentinelPackage -Root $OutputDirectory -TrustedSignerThumbprint $CertificateThumbprint -AllowUnsigned:(-not $certificate)
