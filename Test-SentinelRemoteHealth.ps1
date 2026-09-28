param([Parameter(Mandatory=$true)][string]$ComputerName,[string]$Root='C:\ProgramData\SentinelLocal',[int]$TimeoutSeconds=20)
$ErrorActionPreference='Stop'
if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 300) { throw 'Invalid remote timeout.' }
try {
    $option=New-PSSessionOption -OpenTimeout ($TimeoutSeconds*1000) -OperationTimeout ($TimeoutSeconds*1000)
    $job=Invoke-Command -ComputerName $ComputerName -SessionOption $option -AsJob -ScriptBlock {
        param($InstallRoot)
        . (Join-Path $InstallRoot 'Common.ps1')
        . (Join-Path $InstallRoot 'Status.ps1')
        Get-SentinelStatus -Root $InstallRoot
    } -ArgumentList $Root -ErrorAction Stop
    if (-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)) { throw 'Remote health check timed out.' }
    $status=Receive-Job -Job $job -ErrorAction Stop
    if (-not $status) { throw 'Remote health check returned no status.' }
    $status
    if (-not $status.Healthy) { exit 1 }
    exit 0
} catch { [Console]::Error.WriteLine('Remote observer: '+$_.Exception.Message); exit 2 }
finally { if ($job) { Stop-Job -Job $job -ErrorAction SilentlyContinue; Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } }
