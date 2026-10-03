param(
    [Parameter(Mandatory=$true)][string]$InputPath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Evaluation.ps1')
$inputText=[IO.File]::ReadAllText((Resolve-Path -LiteralPath $InputPath).ProviderPath,[Text.Encoding]::UTF8)
$data=$inputText | ConvertFrom-Json
$summary=Get-SentinelEvaluationSummary $data
if(Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory already exists; choose a new report directory.' }
$destination=New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop
$encoding=[Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $destination.FullName 'results.json'),$inputText,$encoding)
[IO.File]::WriteAllText((Join-Path $destination.FullName 'summary.json'),($summary | ConvertTo-Json -Depth 20),$encoding)
[IO.File]::WriteAllText((Join-Path $destination.FullName 'summary.md'),(ConvertTo-SentinelEvaluationMarkdown $summary),$encoding)
Write-Host ('Evaluation report: '+$destination.FullName)
