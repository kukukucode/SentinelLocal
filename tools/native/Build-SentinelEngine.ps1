param([string]$RepoRoot=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),[string]$Target='',[string]$SigningCertificateThumbprint)
$ErrorActionPreference='Stop'
$arguments=@('build','--release','--locked','--manifest-path',(Join-Path $RepoRoot 'native\Cargo.toml'))
if($Target){$arguments+=@('--target',$Target)}
& cargo @arguments
if($LASTEXITCODE -ne 0){throw 'Rust engine build failed.'}
$artifacts=Join-Path $RepoRoot ('native\target\'+$(if($Target){$Target+'\'}else{''})+'release')
$output=Join-Path $RepoRoot 'native\bin';New-Item -ItemType Directory -Path $output -Force | Out-Null
foreach($name in @('sentinel_engine.dll','sentinel-core.exe')){Copy-Item -LiteralPath (Join-Path $artifacts $name) -Destination (Join-Path $output $name) -Force}
if($SigningCertificateThumbprint){
    $certificate=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$SigningCertificateThumbprint) -ErrorAction Stop
    if(-not $certificate.HasPrivateKey){throw 'Native signing requires a code-signing certificate with a private key.'}
    foreach($name in @('sentinel_engine.dll','sentinel-core.exe')){if((Set-AuthenticodeSignature -FilePath (Join-Path $output $name) -Certificate $certificate -HashAlgorithm SHA256).Status -ne 'Valid'){throw 'Native Authenticode signing was not validated.'}}
}
$dependencyData=(& cargo metadata --locked --format-version 1 --manifest-path (Join-Path $RepoRoot 'native\Cargo.toml')) -join "`n"
if($LASTEXITCODE -ne 0){throw 'Dependency license metadata unavailable.'}
$notice=[Text.StringBuilder]::new();[void]$notice.AppendLine('SentinelLocal native dependency notices; exact versions are pinned in Cargo.lock.')
foreach($package in (($dependencyData | ConvertFrom-Json).packages | Where-Object name -ne 'sentinel-engine' | Sort-Object name)){
    [void]$notice.AppendLine(('--- '+$package.name+' '+$package.version+' ('+$package.license+') ---'))
    foreach($license in Get-ChildItem -LiteralPath (Split-Path $package.manifest_path) -File | Where-Object {$_.Name -match '^(LICENSE|COPYING|COPYRIGHT)'}){[void]$notice.AppendLine([IO.File]::ReadAllText($license.FullName))}
}
[IO.File]::WriteAllText((Join-Path $output 'NATIVE-NOTICES.txt'),$notice.ToString(),[Text.UTF8Encoding]::new($true))
$inputs=@(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'native\src') -Recurse -File | Sort-Object FullName | ForEach-Object {[ordered]@{Name=$_.FullName.Substring($RepoRoot.Length+1).Replace('\','/');SHA256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
$metadata=[ordered]@{Schema=1;ABI=1;Architecture='x64';DLL='sentinel_engine.dll';SHA256=(Get-FileHash -LiteralPath (Join-Path $output 'sentinel_engine.dll')).Hash;CargoLockSHA256=(Get-FileHash -LiteralPath (Join-Path $RepoRoot 'native\Cargo.lock')).Hash;Inputs=$inputs}
[IO.File]::WriteAllText((Join-Path $output 'sentinel-engine.json'),($metadata | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($true))
Write-Host ('Built native engine: '+$output)
