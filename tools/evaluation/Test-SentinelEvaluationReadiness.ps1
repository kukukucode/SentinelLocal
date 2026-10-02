param(
    [string]$Root='C:\ProgramData\SentinelLocal',
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Readiness.ps1')
$rootPath=[IO.Path]::GetFullPath($Root).TrimEnd('\')
$outputPath=[IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
if($outputPath -ieq $rootPath -or $outputPath.StartsWith($rootPath+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Write diagnostics outside the monitored installation.' }
foreach($candidate in @($rootPath,$outputPath)) {
    $ancestor=$candidate
    while($ancestor) {
        if((Test-Path -LiteralPath $ancestor -ErrorAction Stop) -and ((Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Diagnostic paths must not traverse reparse points.' }
        $parent=Split-Path -Parent $ancestor
        if($parent -eq $ancestor) { break }
        $ancestor=$parent
    }
}
if(Test-Path -LiteralPath $outputPath) { throw 'Output directory already exists; choose a new report directory.' }
$report=Get-SentinelEvaluationReadiness -Root $rootPath
[void](New-Item -ItemType Directory -Path $outputPath -ErrorAction Stop)
[IO.File]::WriteAllText((Join-Path $outputPath 'readiness.json'),($report | ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
$report.Checks | Select-Object Name,State,NextStep | Format-Table -AutoSize
Write-Host ('Readiness report: '+(Join-Path $outputPath 'readiness.json'))
Write-Host ('Ready for benign trials: '+$report.ReadyForBenignTrials+'. No performance measurements were made.')
if(-not $report.ReadyForBenignTrials) { exit 2 }
exit 0
