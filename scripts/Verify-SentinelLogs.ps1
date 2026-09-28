param(
    [string]$Root = "C:\ProgramData\SentinelLocal",
    [string]$ReferenceManifestPath = ''
)

$ErrorActionPreference = "Stop"
$commonPath=Join-Path $PSScriptRoot 'Common.ps1'
if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) { $commonPath=Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Common.ps1' }
. $commonPath

$logDir = Join-Path $Root "logs"
$results = @()

$names=@(Get-ChildItem -LiteralPath $logDir -File -Filter '*.jsonl' -ErrorAction SilentlyContinue | ForEach-Object Name)
$names+=@(Get-ChildItem -LiteralPath (Join-Path $Root 'state\log-chain') -File -Filter '*.jsonl.state' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.Substring(0,$_.Name.Length-6) })
foreach ($name in @($names | Sort-Object -Unique)) {
    $results+=Get-SentinelLogVerification -Path (Join-Path $logDir $name)
}
if ($results.Count -eq 0) { $results += [pscustomobject]@{Log='(none)';Valid=$false;Lines=0;Detail='No logs or checkpoints found.'} }
if ($ReferenceManifestPath) {
    $manifest=Get-Content -LiteralPath $ReferenceManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    foreach ($entry in @($manifest.Files)) {
        if ([string]$entry.Name -notmatch '^[A-Za-z0-9_.-]+\.jsonl$') { throw 'Invalid manifest log name.' }
        $path=Join-Path $logDir $entry.Name
        $match=(Test-Path -LiteralPath $path) -and ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq $entry.SHA256)
        $results += [pscustomobject]@{Log=$entry.Name;Valid=[bool]$match;Lines=$entry.LineCount;Detail='External manifest SHA-256 comparison (exact exported snapshot)'}
    }
}

$results | Format-Table -AutoSize
if (@($results | Where-Object { -not $_.Valid }).Count -gt 0) { exit 1 } else { exit 0 }
