param([string]$Root='C:\ProgramData\SentinelLocal',[string]$OutputPath)
$ErrorActionPreference='Stop'
$commonPath=Join-Path $PSScriptRoot 'Common.ps1'
if(-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) { $commonPath=Join-Path (Split-Path -Parent $PSScriptRoot) 'src\Common.ps1' }
. $commonPath
$checks=[Collections.Generic.List[object]]::new()
function Check([string]$Name,[scriptblock]$Probe,[scriptblock]$Judge,[string]$Recommendation) {
    try { $value=& $Probe;$checks.Add([pscustomobject]@{Name=$Name;State=$(if(& $Judge $value){'Pass'}else{'Review'});Value=$value;Recommendation=$Recommendation}) }
    catch { $checks.Add([pscustomobject]@{Name=$Name;State='Unverified';Value=$_.Exception.Message;Recommendation=$Recommendation}) }
}
Check 'Windows version' { $os=Get-CimInstance Win32_OperatingSystem;[pscustomobject]@{Caption=$os.Caption;Version=$os.Version;Build=$os.BuildNumber} } {param($value) $value.Caption -match 'Windows 11|Server 2022|Server 2025'} 'Pilot acceptance targets Windows 11. Server CI is a separate test.'
Check 'Defender real-time protection' { $mp=Get-MpComputerStatus -ErrorAction Stop;[pscustomobject]@{Mode=$mp.AMRunningMode;Antivirus=$mp.AntivirusEnabled;RealTime=$mp.RealTimeProtectionEnabled;Behavior=$mp.BehaviorMonitorEnabled;SignatureAge=$mp.AntivirusSignatureAge} } {param($value) $value.Mode -eq 'Normal' -and $value.Antivirus -and $value.RealTime -and $value.Behavior -and $value.SignatureAge -le 1} 'Review Windows Security and definition updates; other antivirus products may put Defender in passive mode.'
Check 'Tamper protection' { (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected } {param($value) $value -eq $true} 'Use Windows Security or organization policy to enable tamper protection.'
Check 'Firewall profiles' { @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled) } {param($value) @($value | Where-Object { -not $_.Enabled }).Count -eq 0} 'Review disabled firewall profiles; do not apply a blanket inbound block without testing.'
Check 'Secure Boot' { Confirm-SecureBootUEFI -ErrorAction Stop } {param($value) $value -eq $true} 'Confirm firmware support and recovery-key availability before changing firmware settings.'
Check 'Memory integrity' { @(Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop).SecurityServicesRunning } {param($value) 2 -in @($value)} 'Check driver compatibility before enabling memory integrity.'
Check 'Disk encryption' { @(Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,ProtectionStatus,VolumeStatus) } {param($value) @($value | Where-Object { $_.MountPoint -eq $env:SystemDrive -and [string]$_.ProtectionStatus -eq 'On' }).Count -eq 1} 'Confirm that the recovery key is backed up before enabling encryption.'
Check 'Sentinel configuration' { $candidate=Get-Content -LiteralPath (Join-Path $Root 'Config.json') -Raw -Encoding UTF8 | ConvertFrom-Json;Assert-SentinelConfig $candidate;[string]$candidate.Version } {param($value) [bool]$value} 'Install the package and validate configuration before enabling tasks.'
Check 'Sentinel runtime' { . (Get-SentinelSourcePath (Get-SentinelSourceRoot $PSScriptRoot) 'Status.ps1');Get-SentinelStatus $Root } {param($value) $value.Healthy} 'If not installed, this check is expected to require review. Installation and actual scans are separate acceptance steps.'
$result=[pscustomobject]@{Schema=1;ComputerName=$env:COMPUTERNAME;CapturedAt=(Get-Date).ToString('o');ReadOnly=$true;AllChecksPass=(@($checks | Where-Object { $_.State -ne 'Pass' }).Count -eq 0);Checks=@($checks)}
if($OutputPath) { Write-SentinelAtomicJson $OutputPath $result }
$result
