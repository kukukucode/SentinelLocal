function Get-SentinelEventData {
    param($Event)
    [xml]$xml = $Event.ToXml()
    $data = @{}
    foreach ($node in $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
        $data[[string]$node.GetAttribute('Name')] = [string]$node.InnerText
    }
    return $data
}

function Get-SentinelEventBatch {
    param([string]$LogName,[long]$Cursor,[string]$CursorTime='',[int[]]$Ids,[int]$BatchSize=300)
    if ($BatchSize -lt 1 -or $Cursor -lt 0 -or $Ids.Count -eq 0) { throw 'Invalid event cursor or batch size.' }
    $reset = $false; $gap = $false
    try { $latest = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return [pscustomobject]@{Events=@();Reset=($Cursor -gt 0);Gap=($Cursor -gt 0);Cursor=0L} }; throw }
    if ([long]$latest.RecordId -lt $Cursor) { $reset=$true; $gap=$true; $Cursor=0L }
    elseif ($Cursor -gt 0 -and $CursorTime) {
        try {
            $anchor = Get-WinEvent -LogName $LogName -FilterXPath ("*[System[EventRecordID={0}]]" -f $Cursor) -MaxEvents 1 -ErrorAction Stop
            if ([datetime]$anchor.TimeCreated -ne [datetimeoffset]::Parse($CursorTime).LocalDateTime) { $reset=$true; $gap=$true; $Cursor=0L }
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
            $reset=$true; $gap=$true; $Cursor=0L
        }
    }
    $idFilter = ($Ids | ForEach-Object { 'EventID=' + [int]$_ }) -join ' or '
    $xpath = '*[System[EventRecordID > {0} and ({1})]]' -f $Cursor,$idFilter
    try { $events = @(Get-WinEvent -LogName $LogName -FilterXPath $xpath -Oldest -MaxEvents $BatchSize -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events=@() } else { throw } }
    return [pscustomobject]@{Events=$events;Reset=$reset;Gap=$gap;Cursor=$Cursor}
}

function Get-SentinelScriptTargets {
    param([string]$ExecutablePath,[string]$CommandLine)
    $name = [IO.Path]::GetFileName($ExecutablePath)
    if ($name -notmatch '(?i)^(powershell|pwsh|wscript|cscript|mshta|cmd)\.exe$') { return @() }
    # Extract literal local script arguments; never execute, expand expressions,
    # download URLs, or treat a relative path as relative to our SYSTEM process.
    $targets = @()
    $matches = [regex]::Matches($CommandLine,'(?i)(?:"(?<path>[A-Z]:\\[^"\r\n]+\.(?:ps1|psm1|vbs|js|hta|bat|cmd))"|''(?<path>[A-Z]:\\[^''\r\n]+\.(?:ps1|psm1|vbs|js|hta|bat|cmd))''|(?<!\S)(?<path>[A-Z]:\\[^\s"'';|]+\.(?:ps1|psm1|vbs|js|hta|bat|cmd))(?=\s|$))')
    foreach ($match in $matches) {
        $candidate = $match.Groups['path'].Value
        if ([IO.Path]::IsPathRooted($candidate)) { $targets += [IO.Path]::GetFullPath($candidate) }
    }
    return @($targets | Sort-Object -Unique)
}

function Test-SentinelInternalResponse {
    param([string]$Root,$ProcessInfo)
    # Exempt only our exact generated invocation and baselined wrapper, never
    # powershell.exe generally by its signer or installation directory.
    if ([string]$ProcessInfo.ExecutablePath -ine (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe')) { return $false }
    $match=[regex]::Match([string]$ProcessInfo.CommandLine,'(?i)-EncodedCommand\s+([A-Za-z0-9+/=]+)(?:\s|$)')
    if (-not $match.Success) { return $false }
    try {
        $decoded=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($match.Groups[1].Value))
        $tokens=$null; $errors=$null; $ast=[Management.Automation.Language.Parser]::ParseInput($decoded,[ref]$tokens,[ref]$errors)
        $commands=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))
        if ($errors.Count -or $commands.Count -ne 1) { return $false }
        $elements=$commands[0].CommandElements
        if ($elements.Count -ne 7) { return $false }
        foreach ($index in @(0,2,4,6)) { if ($elements[$index] -isnot [Management.Automation.Language.StringConstantExpressionAst]) { return $false } }
        $task=Join-Path $Root 'Invoke-SentinelResponse.ps1'
        $request=[string]$elements[4].Value; $result=[string]$elements[6].Value
        if ($elements[0].Value -ine $task -or $elements[2].Value -ine $Root -or $elements[1].ParameterName -ne 'Root' -or $elements[3].ParameterName -ne 'RequestFile' -or $elements[5].ParameterName -ne 'ResultPath') { return $false }
        if ([IO.Path]::GetDirectoryName($request) -ine (Join-Path $Root 'state\response-queue\processing') -or [IO.Path]::GetFileName($request) -notmatch '^\d{17}_[a-fA-F0-9-]{36}\.json$' -or $result -ine ($request+'.result')) { return $false }
        $expected="& '{0}' -Root '{1}' -RequestFile '{2}' -ResultPath '{3}'" -f $task.Replace("'","''"),$Root.Replace("'","''"),$request.Replace("'","''"),$result.Replace("'","''")
        if ($decoded -cne $expected) { return $false }
        $baseline=Read-SentinelBaseline $Root
        $entry=@($baseline.Files | Where-Object { $_.Name -eq 'Invoke-SentinelResponse.ps1' })
        return $entry.Count -eq 1 -and $entry[0].SHA256 -eq (Get-FileHash -LiteralPath $task -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { return $false }
}

function Save-SentinelDecodedCommand {
    param([string]$Root,[string]$CommandLine,[string]$ExecutablePath='powershell.exe')
    if ([IO.Path]::GetFileName($ExecutablePath) -notmatch '(?i)^(powershell|pwsh)\.exe$') { return $null }
    $match=[regex]::Match($CommandLine,'(?i)-(?:enc|encodedcommand)\s+["'']?([A-Za-z0-9+/=]+)["'']?(?:\s|$)')
    if (-not $match.Success) { return $null }
    if ($match.Groups[1].Value.Length -gt 65536) { return $null }
    try {
        $bytes=[Convert]::FromBase64String($match.Groups[1].Value)
        if ($bytes.Length % 2 -ne 0) { return $null }
        $text=[Text.UnicodeEncoding]::new($false,$false,$true).GetString($bytes)
    } catch [FormatException] { return $null }
    catch [Text.DecoderFallbackException] { return $null }
    $hash=Get-SentinelStringHash $text
    if($config -and $config.Resources) { Assert-SentinelStorage -Root $Root -Config $config -Evidence }
    $directory=Join-Path $Root ('evidence\decoded-'+$hash)
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $path=Join-Path $directory 'payload.ps1'
    # Capture as evidence for static scanning only. Never dot-source or invoke it.
    [IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($true))
    (Get-Item -LiteralPath $directory).LastWriteTime=Get-Date
    return $path
}

function Test-SentinelException {
    param([string]$Path,$Config)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    foreach ($entry in @($Config.Exceptions)) {
        if (-not $entry -or -not $entry.Reason -or -not $entry.ExpiresAt -or -not $entry.SHA256) { continue }
        try {
            if ([datetimeoffset]::Parse([string]$entry.ExpiresAt) -le [datetimeoffset]::Now) { continue }
            if ([string]$entry.SHA256 -notmatch '^[A-Fa-f0-9]{64}$') { continue }
            if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash -ine [string]$entry.SHA256) { continue }
            if ($entry.SignerThumbprint) {
                $signature = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
                if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ine [string]$entry.SignerThumbprint) { continue }
            }
            return $true
        } catch { continue }
    }
    return $false
}

function Test-SentinelHeartbeat {
    param($Heartbeat,[int]$StaleSeconds,[int]$BusyTimeoutSeconds=180)
    $age = ([datetimeoffset]::Now - [datetimeoffset]::Parse([string]$Heartbeat.LastUpdated)).TotalSeconds
    $processIdValue = if ($Heartbeat.WatcherProcessId) { [int]$Heartbeat.WatcherProcessId } elseif ($Heartbeat.ResponseWorkerProcessId) { [int]$Heartbeat.ResponseWorkerProcessId } elseif ($Heartbeat.IntegrityMonitorProcessId) { [int]$Heartbeat.IntegrityMonitorProcessId } else { 0 }
    $alive = $processIdValue -gt 0 -and [bool](Get-Process -Id $processIdValue -ErrorAction SilentlyContinue)
    $healthy = $alive -and $age -ge -5 -and $age -le $StaleSeconds -and $Heartbeat.Status -ne 'Stopped'
    if ($Heartbeat.Status -eq 'Busy') {
        if (-not $Heartbeat.RequestStartedAt) { $healthy=$false }
        else { $elapsed=([datetimeoffset]::Now - [datetimeoffset]::Parse([string]$Heartbeat.RequestStartedAt)).TotalSeconds; $healthy=$healthy -and $elapsed -ge -5 -and $elapsed -le $BusyTimeoutSeconds }
    }
    return [pscustomobject]@{Healthy=[bool]$healthy;AgeSeconds=[math]::Round($age,1);ProcessAlive=[bool]$alive;ProcessId=$processIdValue}
}
