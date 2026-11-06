param([string]$RepoRoot=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),[string]$Target='')
$ErrorActionPreference='Stop'
$arguments=@('build','--release','--locked','--manifest-path',(Join-Path $RepoRoot 'native\Cargo.toml'))
if($Target){$arguments+=@('--target',$Target)}
& cargo @arguments
if($LASTEXITCODE -ne 0){throw 'Rust engine build failed.'}
$artifacts=Join-Path $RepoRoot ('native\target\'+$(if($Target){$Target+'\'}else{''})+'release')
$output=Join-Path $RepoRoot 'native\bin';New-Item -ItemType Directory -Path $output -Force | Out-Null
foreach($name in @('sentinel_engine.dll','sentinel-core.exe')){Copy-Item -LiteralPath (Join-Path $artifacts $name) -Destination (Join-Path $output $name) -Force}
$inputs=@(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'native\src') -Recurse -File | Sort-Object FullName | ForEach-Object {[ordered]@{Name=$_.FullName.Substring($RepoRoot.Length+1).Replace('\','/');SHA256=(Get-FileHash -LiteralPath $_.FullName).Hash}})
$metadata=[ordered]@{Schema=1;ABI=1;Architecture='x64';DLL='sentinel_engine.dll';SHA256=(Get-FileHash -LiteralPath (Join-Path $output 'sentinel_engine.dll')).Hash;CargoLockSHA256=(Get-FileHash -LiteralPath (Join-Path $RepoRoot 'native\Cargo.lock')).Hash;Inputs=$inputs}
[IO.File]::WriteAllText((Join-Path $output 'sentinel-engine.json'),($metadata | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($true))
Write-Host ('Built native engine: '+$output)
