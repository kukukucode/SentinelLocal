function Get-SentinelPackagePath {
    param([string]$Root,[string]$Name)
    if($Name -notin @(Get-SentinelPackageFiles) -and $Name -notin @('README.md','README_JP.txt','CHANGELOG.txt','docs/OPERATIONS_JP.md','docs/PILOT_JP.md')) { throw 'Unexpected package path.' }
    $base=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    $path=[IO.Path]::GetFullPath((Join-Path $base $Name))
    if(-not $path.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)) { throw 'Package path escaped root.' }
    $current=Get-Item -LiteralPath $base -ErrorAction Stop
    if($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package root cannot be a reparse point.' }
    foreach($part in $Name.Split([char[]]@('\','/'))) {
        $current=Get-Item -LiteralPath (Join-Path $current.FullName $part) -ErrorAction Stop
        if($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Package cannot contain reparse points.' }
    }
    return $path
}

function Test-SentinelPackage {
    param([string]$Root,[string]$TrustedSignerThumbprint,[switch]$AllowUnsigned)
    Add-Type -AssemblyName System.Security
    $manifestPath=Join-Path $Root 'package.manifest.json'
    $bytes=[IO.File]::ReadAllBytes($manifestPath)
    $manifest=[Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
    if($manifest.Schema -ne 1 -or -not $manifest.Version -or @($manifest.Files).Count -lt @(Get-SentinelPackageFiles).Count) { throw 'Incomplete package manifest.' }
    $signaturePath=$manifestPath+'.p7s';$signed=Test-Path -LiteralPath $signaturePath
    if($signed) {
        if($TrustedSignerThumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'An independently supplied signer thumbprint is required.' }
        $cms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($bytes),$true)
        $cms.Decode([IO.File]::ReadAllBytes($signaturePath));$cms.CheckSignature($true)
        if($cms.SignerInfos.Count -ne 1 -or $cms.SignerInfos[0].Certificate.Thumbprint -ine $TrustedSignerThumbprint) { throw 'Package signer does not match the pinned certificate.' }
        if($cms.SignerInfos[0].DigestAlgorithm.Value -ne '2.16.840.1.101.3.4.2.1') { throw 'Package signatures must use SHA-256.' }
        $certificate=$cms.SignerInfos[0].Certificate
        $codeSigning=@($certificate.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } | ForEach-Object { $_.EnhancedKeyUsages } | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' })
        if($codeSigning.Count -eq 0) { throw 'Package signer is not a code-signing certificate.' }
        if((Get-Date) -lt $certificate.NotBefore -or (Get-Date) -gt $certificate.NotAfter) { throw 'Package signing certificate is not currently valid.' }
    } elseif(-not $AllowUnsigned -or $TrustedSignerThumbprint) { throw 'Unsigned package refused. Pilot packages require explicit -AllowUnsignedPackage.' }
    $seen=@{}
    foreach($file in $manifest.Files) {
        if($seen.ContainsKey([string]$file.Name)) { throw 'Duplicate package file.' }
        $seen[[string]$file.Name]=$true
        $path=Get-SentinelPackagePath $Root ([string]$file.Name)
        if($file.SHA256 -notmatch '^[A-Fa-f0-9]{64}$' -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $file.SHA256 -or (Get-Item -LiteralPath $path).Length -ne [long]$file.Length) { throw ('Package file verification failed: '+$file.Name) }
    }
    foreach($name in Get-SentinelPackageFiles) { if(-not $seen.ContainsKey($name)) { throw ('Manifest omitted package file: '+$name) } }
    $config=Get-Content -LiteralPath (Join-Path $Root 'Config.json') -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    Assert-SentinelConfig $config
    if($manifest.Version -ne $config.Version) { throw 'Manifest/config version mismatch.' }
    return [pscustomobject]@{Valid=$true;Signed=$signed;Version=$manifest.Version;Files=@($manifest.Files).Count;SignerThumbprint=$TrustedSignerThumbprint;FileEntries=@($manifest.Files)}
}
