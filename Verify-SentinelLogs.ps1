param(
    [string]$Root = "C:\ProgramData\SentinelLocal"
)

$ErrorActionPreference = "Stop"
. (Join-Path $Root "Common.ps1")

$logDir = Join-Path $Root "logs"
$results = @()

foreach ($file in @(Get-ChildItem $logDir -File -Filter "*.jsonl" -ErrorAction SilentlyContinue)) {
    $lineNumber = 0
    $previousHash = $null
    $valid = $true
    $detail = "OK"

    foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
        $lineNumber++
        try {
            $object = $line | ConvertFrom-Json -ErrorAction Stop
            if (-not $object._ChainHash -or -not $object._ChainPrev -or [string]$object._ChainAlg -ne "SHA256") {
                throw "Missing hash-chain fields."
            }

            if ($null -ne $previousHash -and [string]$object._ChainPrev -ne $previousHash) {
                throw "Previous hash mismatch at line $lineNumber."
            }

            $payload = [ordered]@{}
            foreach ($property in $object.PSObject.Properties) {
                if ($property.Name -notin @("_ChainAlg","_ChainPrev","_ChainHash")) {
                    $payload[$property.Name] = $property.Value
                }
            }
            $canonical = $payload | ConvertTo-Json -Depth 14 -Compress
            $computed = Get-SentinelStringHash (([string]$object._ChainPrev) + "`n" + $canonical)

            if ($computed -ne [string]$object._ChainHash) {
                throw "Hash mismatch at line $lineNumber."
            }
            $previousHash = [string]$object._ChainHash
        } catch {
            $valid = $false
            $detail = $_.Exception.Message
            break
        }
    }

    $results += [pscustomobject]@{
        Log=$file.Name
        Valid=$valid
        Lines=$lineNumber
        Detail=$detail
    }
}

$results | Format-Table -AutoSize
if (@($results | Where-Object { -not $_.Valid }).Count -gt 0) { exit 1 } else { exit 0 }
