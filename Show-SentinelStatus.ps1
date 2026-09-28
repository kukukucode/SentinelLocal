param([string]$Root='C:\ProgramData\SentinelLocal',[switch]$SmokeTest)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
. (Join-Path $PSScriptRoot 'Status.ps1')
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$form=[Windows.Forms.Form]::new(); $form.Text='SentinelLocal - Windows status'; $form.Width=1100; $form.Height=760
$label=[Windows.Forms.Label]::new(); $label.Dock='Top'; $label.Height=60
$notify=[Windows.Forms.CheckBox]::new(); $notify.Text='Desktop notifications while this window is open'; $notify.Dock='Top'; $notify.Height=30; $notify.Checked=$false
$text=[Windows.Forms.TextBox]::new(); $text.Dock='Fill'; $text.Multiline=$true; $text.ReadOnly=$true; $text.ScrollBars='Both'; $text.WordWrap=$false; $text.Font=[Drawing.Font]::new('Consolas',10)
$form.Controls.Add($text); $form.Controls.Add($notify); $form.Controls.Add($label)
$tray=[Windows.Forms.NotifyIcon]::new(); $tray.Icon=[Drawing.SystemIcons]::Warning; $tray.Text='SentinelLocal'; $tray.Visible=(-not $SmokeTest)
$timer=[Windows.Forms.Timer]::new(); $timer.Interval=5000
$seen=@{}; $lastHealth=$null; $initialized=$false
$refresh={
    try {
        $status=Get-SentinelStatus -Root $Root
        $label.Text=('SentinelLocal {0} | {1} | {2} | {3}' -f $status.Version,$status.ComputerName,$status.CapturedAt,$(if($status.Healthy){'Healthy'}else{'Needs attention'}))
        $label.ForeColor=if($status.Healthy){[Drawing.Color]::DarkGreen}else{[Drawing.Color]::DarkRed}
        $text.Text=($status.Components | Format-Table -AutoSize | Out-String)+($status.Queues | Format-Table -AutoSize | Out-String)+($status.Logs | Format-Table -AutoSize | Out-String)+($status.Defender | Format-List | Out-String)+"`r`nRecent alerts:`r`n"+($status.Alerts | ConvertTo-Json -Depth 8)
        if ($notify.Checked -and $script:initialized -and -not $status.Healthy -and $script:lastHealth -ne $false) { $tray.ShowBalloonTip(10000,'SentinelLocal','Monitoring or Defender needs attention.',[Windows.Forms.ToolTipIcon]::Warning) }
        foreach ($alert in $status.Alerts) {
            $key=if($alert._ChainHash){[string]$alert._ChainHash}else{[string]$alert.Timestamp+[string]$alert.Type}
            if ($notify.Checked -and $script:initialized -and -not $seen.ContainsKey($key) -and $alert.Severity -in @('HIGH','CRITICAL')) { $tray.ShowBalloonTip(10000,'SentinelLocal alert',([string]$alert.Type+' '+[string]$alert.Reason),[Windows.Forms.ToolTipIcon]::Warning) }
            $seen[$key]=$true
        }
        if ($seen.Count -gt 2000) {
            $seen.Clear()
            foreach ($alert in $status.Alerts) { $key=if($alert._ChainHash){[string]$alert._ChainHash}else{[string]$alert.Timestamp+[string]$alert.Type}; $seen[$key]=$true }
        }
        $script:lastHealth=$status.Healthy; $script:initialized=$true
    } catch {
        $label.Text='Status refresh failed: '+$_.Exception.Message; $label.ForeColor=[Drawing.Color]::DarkRed
        if ($notify.Checked -and $script:lastHealth -ne $false) { $tray.ShowBalloonTip(10000,'SentinelLocal','Status cannot be refreshed.',[Windows.Forms.ToolTipIcon]::Error) }
        $script:lastHealth=$false
    }
}
$timer.Add_Tick($refresh)
try {
    & $refresh
    if (-not $SmokeTest) { $timer.Start(); [void]$form.ShowDialog() }
} finally { $timer.Stop(); $timer.Dispose(); $tray.Visible=$false; $tray.Dispose(); $form.Dispose() }
