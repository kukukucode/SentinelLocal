param([string]$PackageRoot,[string]$ScratchRoot,[ValidateSet('Writer','Retention')][string]$Role,[int]$WriterId,[long]$MaxSegmentBytes=0)
$ErrorActionPreference='Stop'
. (Join-Path $PackageRoot 'src\Common.ps1')
try {
    for ($iteration=0;$iteration -lt 12;$iteration++) {
        for ($number=0;$number -lt 4;$number++) {
            $path=Join-Path $ScratchRoot ('logs\concurrent'+$number+'.jsonl')
            if ($Role -eq 'Writer') {
                if($MaxSegmentBytes -gt 0){Add-SentinelChainedRecord $path ([ordered]@{Type='Probe';Writer=$WriterId;Number=$iteration;Timestamp=[datetimeoffset]::Now.ToString('o')}) -MaxFileBytes $MaxSegmentBytes -MaxTotalBytes 1000000}
                elseif (-not (Write-SentinelJsonLine -Path $path -Data ([ordered]@{Type='Probe';Writer=$WriterId;Number=$iteration}))) { throw 'Concurrent append failed' }
            } else { Invoke-SentinelJsonRetention -Path $path -Cutoff (Get-Date).AddDays(-30) }
        }
    }
    exit 0
} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
