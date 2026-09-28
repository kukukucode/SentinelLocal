param([string]$Root='C:\ProgramData\SentinelLocal',[Parameter(Mandatory=$true)][string]$OutputDirectory,[ValidateRange(10,10000)][int]$MaxEvents=1000,[string]$Search)
$ErrorActionPreference='Stop'
$commonPath=Join-Path $PSScriptRoot 'Common.ps1'
if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) { $commonPath=Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Common.ps1' }
. $commonPath
. (Get-SentinelSourcePath (Get-SentinelSourceRoot $PSScriptRoot) 'Status.ps1')
if(Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory exists; refusing to overwrite a report.' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$events=[Collections.Generic.List[object]]::new();$verification=@()
foreach($file in @(Get-ChildItem -LiteralPath (Join-Path $Root 'logs') -File -Filter '*.jsonl' -ErrorAction SilentlyContinue)) {
    $lock=Enter-SentinelLogLock $file.FullName
    try {
        $check=Get-SentinelLogVerification $file.FullName
        $verification += [pscustomobject]@{Log=$file.Name;Valid=$check.Valid;Detail=$check.Detail}
        foreach($line in @(Get-Content -LiteralPath $file.FullName -Tail $MaxEvents -Encoding UTF8)) {
            try {
                $event=$line | ConvertFrom-Json -ErrorAction Stop
                if($Search -and $line.IndexOf($Search,[StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
                $events.Add([pscustomobject]@{Time=[string]$event.Timestamp;Type=[string]$event.Type;Severity=[string]$event.Severity;Source=$file.Name;Data=$event;Verified=$check.Valid})
            } catch { $events.Add([pscustomobject]@{Time='';Type='UnreadableLog';Severity='HIGH';Source=$file.Name;Data=$line;Verified=$false}) }
        }
    } finally { $lock.ReleaseMutex();$lock.Dispose() }
}
$timeline=@($events | Sort-Object Time -Descending | Select-Object -First $MaxEvents)
$status=Get-SentinelStatus $Root
$report=[ordered]@{Schema=1;ComputerName=$env:COMPUTERNAME;CapturedAt=(Get-Date).ToString('o');Status=$status;Verification=$verification;Timeline=$timeline;Limit=$MaxEvents;Search=$Search;Scope='Bounded log timeline. A valid hash chain is not proof against a fully compromised local administrator.'}
Write-SentinelAtomicJson (Join-Path $OutputDirectory 'report.json') $report
$rows=foreach($event in $timeline) { '<tr><td>'+ (ConvertTo-SentinelHtml $event.Time)+'</td><td>'+ (ConvertTo-SentinelHtml $event.Severity)+'</td><td>'+ (ConvertTo-SentinelHtml $event.Type)+'</td><td>'+ (ConvertTo-SentinelHtml $event.Source)+'</td><td>'+ (ConvertTo-SentinelHtml $event.Verified)+'</td><td><details><summary>Details</summary><p>'+ (ConvertTo-SentinelHtml $event.Data.Reason)+'</p><pre>'+ (ConvertTo-SentinelHtml ($event.Data | ConvertTo-Json -Depth 20))+'</pre></details></td></tr>' }
$html='<!doctype html><html lang="ja"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src '+ "'none'; style-src 'unsafe-inline'"+'"><meta name="viewport" content="width=device-width"><title>SentinelLocal report</title><style>body{font:16px system-ui;margin:24px;background:#101722;color:#edf2fb}table{width:100%;border-collapse:collapse}td,th{padding:10px;border-bottom:1px solid #344255;text-align:left;vertical-align:top}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-width:70ch}.panel{padding:16px;background:#1b2737;border-radius:10px;margin-bottom:20px}</style><h1>SentinelLocal 調査レポート</h1><div class="panel"><b>'+ (ConvertTo-SentinelHtml $env:COMPUTERNAME)+'</b><p>取得時刻: '+ (ConvertTo-SentinelHtml $report.CapturedAt)+'</p><p>稼働状態 Healthy: '+ (ConvertTo-SentinelHtml $status.Healthy)+'</p><p>最大 '+$MaxEvents+' 件。検索条件: '+ (ConvertTo-SentinelHtml $Search)+'</p><p>ログ検証: '+(ConvertTo-SentinelHtml ($verification | ConvertTo-Json -Depth 5))+'</p></div><table><thead><tr><th>時刻</th><th>重要度</th><th>イベント</th><th>記録元</th><th>検証</th><th>内容</th></tr></thead><tbody>'+($rows -join '')+'</tbody></table></html>'
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'index.html'),$html,[Text.UTF8Encoding]::new($true))
Write-Output (Join-Path $OutputDirectory 'index.html')
