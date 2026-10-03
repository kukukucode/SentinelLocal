param(
    [string]$Root = "C:\ProgramData\SentinelLocal"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")
. (Join-Path $PSScriptRoot 'SysmonMonitoring.ps1')

$configPath = Join-Path $Root "Config.json"
try {
    $config = Get-Content $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-SentinelError -Root $Root -Component "Watcher" -Operation "Load config" -Exception $_.Exception
    throw
}

Assert-SentinelConfig $config
$logs = Join-Path $Root "logs"
$state = Join-Path $Root "state"
$evidence = Join-Path $Root "evidence"
New-Item $logs,$state,$evidence -ItemType Directory -Force | Out-Null
$watcherCreated=$false
$watcherMutex=[Threading.Mutex]::new($true,'Global\SentinelLocalWatcher',[ref]$watcherCreated)
if(-not $watcherCreated) { throw 'A SentinelLocal Watcher already owns this host; duplicate monitoring refused.' }

$eventLog = Join-Path $logs "events.log"
$alertLog = Join-Path $logs "alerts.jsonl"
$defenderLog = Join-Path $logs "defender-events.jsonl"
$asrLog = Join-Path $logs "asr-events.jsonl"
$cfaLog = Join-Path $logs "cfa-events.jsonl"
$networkProtectionLog = Join-Path $logs "network-protection-events.jsonl"
$lastDefenderState = Join-Path $state "defender-last-record.txt"
$defenderCursorPath = Join-Path $state 'defender-cursor.json'
$defenderCursorTime = ''
$sysmonCursorPath = Join-Path $state 'sysmon-cursor.json'
$heartbeatPath = Join-Path $state "watcher-heartbeat.json"
$integrityHeartbeatPath = Join-Path $state "integrity-monitor-heartbeat.json"
$responseQueueRoot = Join-Path $state "response-queue"
$responseQueueHigh = Join-Path $responseQueueRoot "high"
$responseQueueNormal = Join-Path $responseQueueRoot "normal"
$responseQueueProcessing = Join-Path $responseQueueRoot "processing"
$responseQueueFailed = Join-Path $responseQueueRoot "failed"
$responseDedupeStatePath = Join-Path $state "response-path-dedupe.json"
New-Item $responseQueueHigh,$responseQueueNormal,$responseQueueProcessing,$responseQueueFailed -ItemType Directory -Force | Out-Null

$responsePathDedupe = @{}
if (Test-Path -LiteralPath $responseDedupeStatePath) {
    try {
        foreach ($entry in @(Get-Content $responseDedupeStatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)) {
            if ($entry.Key) {
                $responsePathDedupe[[string]$entry.Key] = [pscustomobject]@{
                    LastQueued=[datetimeoffset]::Parse([string]$entry.LastQueued)
                    Score=[int]$entry.Score
                }
            }
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Load response path dedupe state" -Exception $_.Exception -Severity "MEDIUM"
    }
}

function Save-ResponsePathDedupe {
    try {
        $now = [datetimeoffset]::Now
        $maxAge = [Math]::Max([int]$config.ResponseQueueDedupeSeconds * 4, 3600)
        foreach ($key in @($responsePathDedupe.Keys)) {
            if (($now - $responsePathDedupe[$key].LastQueued).TotalSeconds -gt $maxAge) {
                [void]$responsePathDedupe.Remove($key)
            }
        }
        $rows = @($responsePathDedupe.Keys | ForEach-Object {
            [pscustomobject]@{
                Key=$_
                LastQueued=$responsePathDedupe[$_].LastQueued.ToString("o")
                Score=[int]$responsePathDedupe[$_].Score
            }
        })
        Write-SentinelAtomicJson $responseDedupeStatePath @($rows)
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Save response path dedupe state" -Exception $_.Exception -Severity "MEDIUM"
    }
}

function Write-TextLog {
    param([string]$Message)
    try {
        Add-Content -LiteralPath $eventLog -Value ("{0:o}`t{1}" -f (Get-Date),$Message) -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Write event log file" -Exception $_.Exception -Context @{Message=$Message}
    }
}

function Write-AppEvent {
    param([string]$Message,[int]$EventId=1001,[string]$EntryType="Warning")
    try {
        Write-EventLog -LogName Application -Source "SentinelLocal" -EventId $EventId -EntryType $EntryType -Message $Message -ErrorAction Stop
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Write Application event" -Exception $_.Exception -Context @{EventId=$EventId} -Severity "MEDIUM"
    }
}

function Write-Heartbeat {
    param(
        [long]$LastDefenderRecordId,
        [datetime]$StartedAt,
        [string]$Status = "Running"
    )
    $watcherProcessId = [System.Diagnostics.Process]::GetCurrentProcess().Id
    $heartbeat = [ordered]@{
        Version = [string]$config.Version
        Status = $Status
        WatcherProcessId = $watcherProcessId
        StartedAt = $StartedAt.ToString("o")
        LastUpdated = (Get-Date).ToString("o")
        LastDefenderRecordId = $LastDefenderRecordId
        ProcessMonitorMode = $processMonitorMode
    }
    try {
        Write-SentinelAtomicJson $heartbeatPath $heartbeat
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Write heartbeat" -Exception $_.Exception
    }
}


function Check-IntegrityMonitorHeartbeat {
    if (-not $config.SelfDefense.Enabled) { return }

    if (-not (Test-Path -LiteralPath $integrityHeartbeatPath)) {
        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
            Type="SentinelSelfDefense"
            Severity="HIGH"
            Component="IntegrityMonitor"
            Reason="Integrity Monitor heartbeat file is missing."
        }))
        return
    }

    try {
        $heartbeat = Get-Content $integrityHeartbeatPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $age = ((Get-Date) - ([datetimeoffset]::Parse([string]$heartbeat.LastUpdated)).LocalDateTime).TotalSeconds
        $processAlive = $false
        if ($heartbeat.IntegrityMonitorProcessId) {
            $processAlive = [bool](Get-Process -Id ([int]$heartbeat.IntegrityMonitorProcessId) -ErrorAction SilentlyContinue)
        }
        if ($age -gt [int]$config.SelfDefense.HeartbeatStaleSeconds -or -not $processAlive) {
            [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                Type="SentinelSelfDefense"
                Severity="CRITICAL"
                Component="IntegrityMonitor"
                AgeSeconds=[math]::Round($age,1)
                ProcessAlive=$processAlive
                Reason="Watcher detected a stale or dead Integrity Monitor."
            }))
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Check Integrity Monitor heartbeat" -Exception $_.Exception -Severity "HIGH"
    }
}

function Get-ProcessInfo {
    param([int]$ProcessIdValue)
    try {
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessIdValue" -ErrorAction Stop
        if (-not $process) { return $null }
        return [ordered]@{
            ProcessId=[int]$process.ProcessId
            ParentProcessId=[int]$process.ParentProcessId
            Name=$process.Name
            ExecutablePath=$process.ExecutablePath
            CommandLine=$process.CommandLine
            CreationDate=if($process.CreationDate){([datetime]$process.CreationDate).ToUniversalTime().ToString("o")}else{""}
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Read process information" -Exception $_.Exception -Context @{ProcessId=$ProcessIdValue} -Severity "MEDIUM"
        return $null
    }
}


function Test-ProcessIdentityMatch {
    param($ExpectedProcess)

    if (-not $ExpectedProcess -or -not $ExpectedProcess.ProcessId) { return $false }
    $current = Get-ProcessInfo ([int]$ExpectedProcess.ProcessId)
    if (-not $current) { return $false }

    return (
        ([string]$current.ExecutablePath -ieq [string]$ExpectedProcess.ExecutablePath) -and
        ([string]$current.CreationDate -eq [string]$ExpectedProcess.CreationDate)
    )
}

function Test-RandomishSegment {
    param([string]$Path)
    if (-not $Path) { return $false }
    foreach ($segment in ($Path -split '[\\/]')) {
        if ($segment -match '^[a-z0-9]{8,20}$' -and $segment -match '[a-z]' -and $segment -match '[0-9]') {
            return $true
        }
    }
    return $false
}

function Get-FileSignatureStatus {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        return (Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop).Status
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Read Authenticode signature" -Exception $_.Exception -Context @{Path=$Path} -Severity "MEDIUM"
        return $null
    }
}

function Get-ProcessScore {
    param($ProcessInfo)
    if (Test-SentinelInternalResponse -Root $Root -ProcessInfo $ProcessInfo) { return [pscustomobject]@{Score=0;Reasons=@('Verified SentinelLocal response invocation')} }
    $score=0
    $reasons=New-Object System.Collections.Generic.List[string]
    $path=[string]$ProcessInfo.ExecutablePath
    $name=[string]$ProcessInfo.Name
    $commandLine=[string]$ProcessInfo.CommandLine

    if ($name -ieq "EnergyDevice64.exe") { $score+=95; $reasons.Add("Known suspicious EnergyDevice64 filename") }
    if ($path -match '(?i)\\ProgramData\\InProcSvr32\\') { $score+=85; $reasons.Add("Executed from ProgramData\InProcSvr32") }

    if ($path -match '(?i)\\ProgramData\\Google\\(Chrome|Update)\\') {
        $score+=40; $reasons.Add("Executed from nonstandard ProgramData\Google subtree")
        if (Test-RandomishSegment $path) { $score+=35; $reasons.Add("Random-looking ProgramData\Google directory") }
    }

    if ($path -match '(?i)\\AppData\\Local\\Temp\\|\\Windows\\Temp\\') {
        $score+=45; $reasons.Add("Executable launched from Temp")
    }

    if ($name -match '(?i)^(cmd|mshta|wscript|cscript|powershell|pwsh|rundll32|regsvr32|certutil|bitsadmin)\.exe$') {
        $score+=10; $reasons.Add("Living-off-the-land binary")
        if ($commandLine -match '(?i)(-enc|-encodedcommand|frombase64string|downloadstring|invoke-webrequest|\biwr\b|\bcurl\b|https?://)') {
            $score+=45; $reasons.Add("Suspicious script/network command line")
        }
    }

    $signatureStatus = Get-FileSignatureStatus $path
    if ($signatureStatus -and [string]$signatureStatus -ne "Valid") {
        $score+=15; $reasons.Add("Executable is not validly signed")
    }

    try {
        if (Test-Path -LiteralPath $path) {
            $originalFilename = (Get-Item -LiteralPath $path -ErrorAction Stop).VersionInfo.OriginalFilename
            if ($originalFilename -and ([IO.Path]::GetFileName($path) -ne $originalFilename) -and $path -match '(?i)\\ProgramData\\') {
                $score+=25; $reasons.Add("Original filename differs while executing from ProgramData")
            }
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Read original filename" -Exception $_.Exception -Context @{Path=$path} -Severity "MEDIUM"
    }

    return [pscustomobject]@{Score=$score;Reasons=@($reasons)}
}

function Get-ImmediateNetworkSnapshot {
    param([int]$ProcessIdValue)

    if ($ProcessIdValue -le 0) { return @() }
    try {
        return @(Get-NetTCPConnection -OwningProcess $ProcessIdValue -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Timestamp=(Get-Date).ToString("o")
                ProcessId=$ProcessIdValue
                State=$_.State
                LocalAddress=$_.LocalAddress
                LocalPort=$_.LocalPort
                RemoteAddress=$_.RemoteAddress
                RemotePort=$_.RemotePort
                PTR=$null
            }
        })
    } catch {
        # A newly-created process often has no socket yet or exits immediately.
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Capture immediate network snapshot" -Exception $_.Exception -Context @{ProcessId=$ProcessIdValue} -Severity "MEDIUM"
        return @()
    }
}

function Queue-SentinelResponse {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [int]$ProcessIdValue = 0,
        [int]$Score = 0,
        [string[]]$Reasons = @(),
        [string]$Source = "Watcher",
        $ObservedProcess = $null
    )

    try {
        $normalizedPath = try { [IO.Path]::GetFullPath($FilePath).ToLowerInvariant() } catch { $FilePath.ToLowerInvariant() }
        $processIdentityPart = ""
        if ($ProcessIdValue -gt 0) {
            $creation = if ($ObservedProcess -and $ObservedProcess.CreationDate) { [string]$ObservedProcess.CreationDate } else { "" }
            $processIdentityPart = "|PID=" + $ProcessIdValue + "|CREATED=" + $creation
        }
        $contentIdentity = if($ObservedProcess -and $ObservedProcess.ObservedSHA256 -match '^[a-fA-F0-9]{64}$'){[string]$ObservedProcess.ObservedSHA256}else{Get-SentinelFileIdentity $FilePath}
        $pathKey = Get-SentinelStringHash ("PATH|" + $normalizedPath + $processIdentityPart + "|SHA256=" + $contentIdentity)
        $now = [datetimeoffset]::Now

        if ($responsePathDedupe.ContainsKey($pathKey)) {
            $previous = $responsePathDedupe[$pathKey]
            $age = ($now - $previous.LastQueued).TotalSeconds
            $priorityPromotion = (
                $Score -ge [int]$config.ResponseQueueHighScore -and
                [int]$previous.Score -lt [int]$config.ResponseQueueHighScore
            )
            if ($age -lt [int]$config.ResponseQueueDedupeSeconds -and -not $priorityPromotion) {
                [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                    Type="ResponseQueueDeduplicated"
                    FilePath=$FilePath
                    ProcessId=$ProcessIdValue
                    Score=$Score
                    PreviousScore=[int]$previous.Score
                    AgeSeconds=[math]::Round($age,1)
                    Reason="A recent request for the same normalized path/process identity is already within the dedupe window."
                }))
                return
            }
        }

        $requestId = [guid]::NewGuid().ToString()
        $priority = if ($Score -ge [int]$config.ResponseQueueHighScore) { "High" } else { "Normal" }
        $queueDirectory = if ($priority -eq "High") { $responseQueueHigh } else { $responseQueueNormal }

        Assert-SentinelQueueCapacity -Root $Root -Config $config -Priority $priority
        $initialConnections = if ($ProcessIdValue -gt 0 -and $Score -ge [int]$config.ScorePolicy.DefenderCustomScan) {
            @(Get-ImmediateNetworkSnapshot $ProcessIdValue)
        } else {
            @()
        }

        $snapshotPath=''
        try {$snapshotPath=Save-SentinelObservedFile -Root $Root -Path $FilePath -ObservedSHA256 $contentIdentity -RequestId $requestId -Config $config}
        catch {Write-SentinelError -Root $Root -Component Watcher -Operation 'Capture observed file' -Exception $_.Exception -Context @{RequestId=$requestId;Path=$FilePath} -Severity HIGH}
        $request = [ordered]@{
            RequestId=$requestId
            QueuedAt=(Get-Date).ToString("o")
            Attempts=0
            Priority=$priority
            Source=$Source
            FilePath=$FilePath
            NormalizedPath=$normalizedPath
            PathDedupeKey=$pathKey
            ObservedSHA256=$contentIdentity
            SnapshotPath=$snapshotPath
            ProcessIdValue=$ProcessIdValue
            Score=$Score
            Reasons=@($Reasons)
            ObservedProcess=$ObservedProcess
            InitialConnections=@($initialConnections)
        }

        $baseName = "{0}_{1}.json" -f (Get-Date -Format "yyyyMMddHHmmssfff"),$requestId
        $finalPath = Join-Path $queueDirectory $baseName
        $tempPath = "$finalPath.tmp"
        $request | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $tempPath -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $tempPath -Destination $finalPath -Force -ErrorAction Stop

        $responsePathDedupe[$pathKey] = [pscustomobject]@{LastQueued=$now;Score=$Score}
        Save-ResponsePathDedupe

        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
            Type="ResponseQueued"
            RequestId=$requestId
            Priority=$priority
            Source=$Source
            FilePath=$FilePath
            ProcessId=$ProcessIdValue
            Score=$Score
            InitialConnectionCount=$initialConnections.Count
        }))
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Queue response request" -Exception $_.Exception -Context @{FilePath=$FilePath;ProcessId=$ProcessIdValue;Score=$Score}
        throw
    }
}

function Get-PersistenceSnapshot {
    $items=New-Object System.Collections.Generic.List[object]
    try {
        $runPaths=@(
            "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
            "Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        )
        Get-ChildItem "Registry::HKEY_USERS" -ErrorAction Stop |
            Where-Object {$_.PSChildName -notmatch '_Classes$'} |
            ForEach-Object {
                $runPaths += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
            }

        foreach ($runPath in $runPaths) {
            if (Test-Path $runPath) {
                $object = Get-ItemProperty $runPath -ErrorAction Stop
                foreach ($property in $object.PSObject.Properties) {
                    if ($property.Name -notmatch '^PS') {
                        $items.Add([pscustomobject]@{Type="Run";Key="$runPath|$($property.Name)";Value=[string]$property.Value})
                    }
                }
            }
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Snapshot Run persistence" -Exception $_.Exception
        throw
    }

    try {
        $startupDirectories=@("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
        $startupDirectories += Get-ChildItem "C:\Users" -Directory -ErrorAction Stop | ForEach-Object {
            Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        }
        foreach ($startupDirectory in $startupDirectories) {
            if (Test-Path $startupDirectory) {
                Get-ChildItem $startupDirectory -Force -File -ErrorAction Stop | ForEach-Object {
                    $startupHash=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                    $items.Add([pscustomobject]@{Type="Startup";Key=$_.FullName;Value="$($_.Length)|$($_.LastWriteTimeUtc.Ticks)|$startupHash"})
                }
            }
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Snapshot Startup persistence" -Exception $_.Exception
        throw
    }

    try {
        Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $task=$_
            $actionIndex=0
            foreach ($action in $task.Actions) {
                $items.Add([pscustomobject]@{Type="Task";Key="$($task.TaskPath)$($task.TaskName)|Action=$actionIndex";Value=(("{0} {1}" -f $action.Execute,$action.Arguments).Trim())})
                $actionIndex++
            }
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Snapshot scheduled tasks" -Exception $_.Exception
        throw
    }

    try {
        Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object {
            $items.Add([pscustomobject]@{Type="Service";Key=$_.Name;Value=("{0}|{1}|{2}" -f $_.StartName,$_.StartMode,$_.PathName)})
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Snapshot services" -Exception $_.Exception
        throw
    }

    # New-Object wraps this generic list; PS 5.1's array binder can throw
    # "Argument types do not match". Convert explicitly before enumeration.
    return $items.ToArray()
}

function Get-PersistenceScore {
    param($Item)
    $score=0
    $reasons=New-Object System.Collections.Generic.List[string]
    $value=[string]$Item.Value
    $key=[string]$Item.Key

    if ($value -match '(?i)EnergyDevice64|\\ProgramData\\InProcSvr32\\') {
        $score+=95; $reasons.Add("Known EnergyDevice64/InProcSvr32 persistence")
    }
    if ($value -match '(?i)\\ProgramData\\Google\\(Chrome|Update)\\') {
        $score+=50; $reasons.Add("ProgramData\Google persistence")
        if (Test-RandomishSegment $value) { $score+=30; $reasons.Add("Random-looking ProgramData\Google directory") }
    }
    if ($Item.Type -eq "Startup" -and $key -match '(?i)\.(hta|bat|cmd|vbs|js|lnk)$') {
        $score+=45; $reasons.Add("Script or shortcut in Startup")
    }
    if ($Item.Type -eq "Service" -and $value -match '(?i)LocalSystem.*\\ProgramData\\') {
        $score+=40; $reasons.Add("LocalSystem service from ProgramData")
    }
    if ($value -match '(?i)\\AppData\\Local\\Temp\\|\\Windows\\Temp\\') {
        $score+=45; $reasons.Add("Persistence points into Temp")
    }
    return [pscustomobject]@{Score=$score;Reasons=@($reasons)}
}

function Compare-Persistence {
    param($Old,$New)
    $oldMap=@{}
    foreach ($item in $Old) { $oldMap["$($item.Type)|$($item.Key)"]=[string]$item.Value }

    foreach ($item in $New) {
        $identity="$($item.Type)|$($item.Key)"
        if ((-not $oldMap.ContainsKey($identity)) -or ($oldMap[$identity] -ne [string]$item.Value)) {
            if (-not (Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{Type='PersistenceChange';Severity='MEDIUM';Item=$item;PreviousValue=$oldMap[$identity]}))) { throw 'Cannot persist persistence change.' }
            $scoreResult=Get-PersistenceScore $item
            if ($scoreResult.Score -ge [int]$config.ScorePolicy.DefenderCustomScan) {
                if (-not (Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                    Type="Persistence";Score=$scoreResult.Score;Reasons=$scoreResult.Reasons;Item=$item
                }))) { throw "Cannot persist suspicious persistence entry." }
                Write-AppEvent ("Suspicious persistence: {0}`n{1}`n{2}" -f $item.Type,$item.Key,($scoreResult.Reasons -join "; "))
                $candidates=if($item.Type -eq 'Startup') {@($item.Key)} else {@(Get-SentinelPersistenceTargets $item.Value)}
                foreach($candidate in $candidates) {
                    if(Test-Path -LiteralPath $candidate -PathType Leaf) {
                        if(-not (Test-SentinelException -Path $candidate -Config $config)) {Queue-SentinelResponse -FilePath $candidate -Score $scoreResult.Score -Reasons $scoreResult.Reasons -Source Persistence}
                    }
                }
                if(-not $candidates.Count) {[void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{Type='PersistenceTargetUnresolved';Severity='HIGH';Item=$item;Reason='No literal local target; manual investigation required.'}))}

            }
        }
    }
    $newIdentities=@{}
    foreach($item in $New) { $newIdentities["$($item.Type)|$($item.Key)"]=$true }
    foreach($item in $Old) {
        if(-not $newIdentities.ContainsKey("$($item.Type)|$($item.Key)")) {
            if(-not (Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{Type='PersistenceRemoved';Severity='MEDIUM';Item=$item}))) { throw 'Cannot persist removed persistence entry.' }
        }
    }
}

function Get-DefenderLogPath {
    param([int]$EventId)
    switch ($EventId) {
        1121 { return $asrLog }
        1122 { return $asrLog }
        1129 { return $asrLog }
        1123 { return $cfaLog }
        1124 { return $cfaLog }
        1127 { return $cfaLog }
        1128 { return $cfaLog }
        1125 { return $networkProtectionLog }
        1126 { return $networkProtectionLog }
        default { return $defenderLog }
    }
}

$pendingDefenderDetections = @{}
$pendingDefenderStatePath = Join-Path $state "defender-pending.json"

function Get-NormalizedDefenderResources {
    param([string]$RawPath)
    if (-not $RawPath) { return @() }
    $resources = @()
    foreach ($part in ($RawPath -split ';\s*')) {
        $value = $part.Trim()
        $value = $value -replace '(?i)^(file|containerfile|regkey|runkey|service|taskscheduler|process):_', ''
        if ($value) { $resources += $value.ToLowerInvariant() }
    }
    return @($resources | Sort-Object -Unique)
}

function ConvertFrom-DefenderEvent {
    param($Event)
    try {
        [xml]$xml = $Event.ToXml()
        $data = @{}
        $nodes = $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")
        foreach ($node in $nodes) {
            $name = [string]$node.GetAttribute("Name")
            if ($name) { $data[$name] = [string]$node.InnerText }
        }

        $rawPath = [string]$data["Path"]
        return [pscustomobject]@{
            EventId = [int]$Event.Id
            RecordId = [long]$Event.RecordId
            TimeCreated = $Event.TimeCreated
            DetectionId = ([string]$data["Detection ID"]).Trim().ToLowerInvariant()
            ThreatId = ([string]$data["Threat ID"]).Trim()
            ThreatName = ([string]$data["Threat Name"]).Trim()
            SeverityName = ([string]$data["Severity Name"]).Trim()
            Path = $rawPath
            Resources = @(Get-NormalizedDefenderResources $rawPath)
            ActionId = ([string]$data["Action ID"]).Trim()
            ActionName = ([string]$data["Action Name"]).Trim()
            ErrorCode = ([string]$data["Error Code"]).Trim()
            ErrorDescription = ([string]$data["Error Description"]).Trim()
            PostCleanStatus = ([string]$data["Post Clean Status"]).Trim()
            AdditionalActions = ([string]$data["Additional Actions String"]).Trim()
            RemediationUser = ([string]$data["Remediation User"]).Trim()
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Parse Defender event XML" -Exception $_.Exception -Context @{EventId=$Event.Id;RecordId=$Event.RecordId}
        throw
    }
}

function Save-PendingDefenderDetections {
    try {
        $items = @($pendingDefenderDetections.Values | ForEach-Object {
            [ordered]@{
                RecordId=$_.RecordId
                DetectedAt=$_.DetectedAt.ToString("o")
                DetectionId=$_.DetectionId
                ThreatId=$_.ThreatId
                ThreatName=$_.ThreatName
                Path=$_.Path
                Resources=@($_.Resources)
                Alerted=[bool]$_.Alerted
            }
        })
        Write-SentinelAtomicJson $pendingDefenderStatePath @($items)
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Save pending Defender correlation state" -Exception $_.Exception -Severity "MEDIUM"
        throw
    }
}

function Load-PendingDefenderDetections {
    if (-not (Test-Path $pendingDefenderStatePath)) { return }
    try {
        $items = @(Get-Content $pendingDefenderStatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
        foreach ($item in $items) {
            if (-not $item.RecordId) { continue }
            $pendingDefenderDetections[[string]$item.RecordId] = [pscustomobject]@{
                RecordId=[long]$item.RecordId
                DetectedAt=[datetime]$item.DetectedAt
                DetectionId=[string]$item.DetectionId
                ThreatId=[string]$item.ThreatId
                ThreatName=[string]$item.ThreatName
                Path=[string]$item.Path
                Resources=@($item.Resources)
                Alerted=[bool]$item.Alerted
            }
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Load pending Defender correlation state" -Exception $_.Exception -Severity "MEDIUM"
    }
}

function Find-PendingDefenderDetection {
    param($Identity)
    $best = $null
    $bestScore = -1
    $windowSeconds = [int]$config.DefenderCorrelationWindowSeconds

    foreach ($candidate in @($pendingDefenderDetections.Values)) {
        $ageSeconds = ($Identity.TimeCreated - $candidate.DetectedAt).TotalSeconds
        if ($ageSeconds -lt -5 -or $ageSeconds -gt $windowSeconds) { continue }

        $score = 0
        if ($Identity.DetectionId -and $candidate.DetectionId) {
            if ($Identity.DetectionId -ne $candidate.DetectionId) { continue }
            $score += 10000
        } else {
            if ($Identity.ThreatId -and $candidate.ThreatId) {
                if ($Identity.ThreatId -ne $candidate.ThreatId) { continue }
                $score += 100
            }

            $intersection = @($Identity.Resources | Where-Object { $_ -in @($candidate.Resources) })
            if ($intersection.Count -gt 0) { $score += 50 + $intersection.Count }
            elseif (-not $Identity.ThreatId -or -not $candidate.ThreatId) { continue }

            if ($Identity.ThreatName -and $candidate.ThreatName -and $Identity.ThreatName -eq $candidate.ThreatName) {
                $score += 10
            }
        }

        # Prefer the closest earlier detection when identity scores tie.
        $score += [Math]::Max(0, 9 - [Math]::Floor([Math]::Abs($ageSeconds) / 30))
        if ($score -gt $bestScore) {
            $best = $candidate
            $bestScore = $score
        }
    }
    return $best
}

function Remove-PendingDefenderDetection {
    param($Pending)
    if ($Pending) {
        [void]$pendingDefenderDetections.Remove([string]$Pending.RecordId)
        Save-PendingDefenderDetections
    }
}

function Test-DefenderActionSuccess {
    param($Identity)
    return (-not $Identity.ErrorCode) -or $Identity.ErrorCode -in @("0","0x00000000")
}

function Get-DefenderActionClass {
    param($Identity)
    $actionName = [string]$Identity.ActionName
    $actionId = [string]$Identity.ActionId
    if ($actionName -match '^(?i)(Clean|Quarantine|Remove|Block)$' -or $actionId -in @("1","2","3","10")) { return "Neutralizing" }
    if ($actionName -match '^(?i)(Allow|NoAction|None)$' -or $actionId -in @("6","9","11")) { return "Permissive" }
    return "Unknown"
}

function Get-MatchingActiveThreats {
    param($Identity)
    try {
        $active = @(Get-MpThreat -ErrorAction Stop | Where-Object IsActive)
        if ($Identity.ThreatId) {
            return @($active | Where-Object { [string]$_.ThreatID -eq [string]$Identity.ThreatId })
        }
        if ($Identity.ThreatName) {
            return @($active | Where-Object { [string]$_.ThreatName -eq [string]$Identity.ThreatName })
        }
        return @()
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Read active Defender threats for event correlation" -Exception $_.Exception
        return @()
    }
}

function Handle-DefenderOutcome {
    param($Event,$Identity)

    $pending = Find-PendingDefenderDetection $Identity
    if (-not $pending) {
        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
            Type="DefenderCorrelationMiss"
            Severity="MEDIUM"
            EventId=$Event.Id
            RecordId=$Event.RecordId
            DetectionId=$Identity.DetectionId
            ThreatId=$Identity.ThreatId
            ThreatName=$Identity.ThreatName
            Path=$Identity.Path
        }))
    }

    if ($Event.Id -in @(1118,1119)) {
        if ($pending) { Remove-PendingDefenderDetection $pending }

        $severity = if ($Event.Id -eq 1119) { "CRITICAL" } else { "HIGH" }
        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
            Type="DefenderRemediationFailure"
            Severity=$severity
            EventId=$Event.Id
            RecordId=$Event.RecordId
            DetectionRecordId=if($pending){$pending.RecordId}else{$null}
            DetectionId=$Identity.DetectionId
            ThreatId=$Identity.ThreatId
            ThreatName=$Identity.ThreatName
            Path=$Identity.Path
            ActionId=$Identity.ActionId
            ActionName=$Identity.ActionName
            ErrorCode=$Identity.ErrorCode
            ErrorDescription=$Identity.ErrorDescription
            Reason=if($Event.Id -eq 1119){"Defender reported a critical remediation failure (1119)."}else{"Defender reported a remediation failure (1118)."}
        }))
        return
    }

    if ($Event.Id -ne 1117) { return }

    $actionClass = Get-DefenderActionClass $Identity
    $actionSucceeded = Test-DefenderActionSuccess $Identity

    if ($actionClass -eq "Unknown") {
        # Unknown/UserDefined actions are not assumed to be successful remediation.
        # Keep the pending detection so the unresolved timer can also surface it.
        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
            Type="DefenderUnknownAction"
            Severity=if($pending){"HIGH"}else{"MEDIUM"}
            RecordId=$Event.RecordId
            DetectionRecordId=if($pending){$pending.RecordId}else{$null}
            DetectionId=$Identity.DetectionId
            ThreatId=$Identity.ThreatId
            ThreatName=$Identity.ThreatName
            Path=$Identity.Path
            ActionId=$Identity.ActionId
            ActionName=$Identity.ActionName
            ErrorCode=$Identity.ErrorCode
            ErrorDescription=$Identity.ErrorDescription
            Reason="1117 contained an action SentinelLocal cannot classify as neutralizing or permissive. Pending state is retained."
        }))
        return
    }

    if ($actionClass -eq "Permissive") {
        if ($pending) { Remove-PendingDefenderDetection $pending }

        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
            Type="DefenderPermissiveAction"
            Severity="HIGH"
            RecordId=$Event.RecordId
            DetectionRecordId=if($pending){$pending.RecordId}else{$null}
            DetectionId=$Identity.DetectionId
            ThreatId=$Identity.ThreatId
            ThreatName=$Identity.ThreatName
            Path=$Identity.Path
            ActionId=$Identity.ActionId
            ActionName=$Identity.ActionName
            RemediationUser=$Identity.RemediationUser
            Reason="1117 recorded an Allow/NoAction/None-style outcome; do not treat this as successful neutralization."
        }))
        return
    }

    if (-not $actionSucceeded) {
        # Keep pending: 1118/1119 may follow, otherwise the unresolved timer alerts.
        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
            Type="DefenderActionError"
            Severity="HIGH"
            RecordId=$Event.RecordId
            DetectionRecordId=if($pending){$pending.RecordId}else{$null}
            DetectionId=$Identity.DetectionId
            ThreatId=$Identity.ThreatId
            ThreatName=$Identity.ThreatName
            Path=$Identity.Path
            ActionId=$Identity.ActionId
            ActionName=$Identity.ActionName
            ErrorCode=$Identity.ErrorCode
            ErrorDescription=$Identity.ErrorDescription
            Reason="1117 reported an error. Pending state is retained for a possible 1118/1119 or timeout."
        }))
        return
    }

    # A successful, recognized neutralizing action resolves the pending item.
    if ($pending) { Remove-PendingDefenderDetection $pending }

    if ($actionClass -eq "Neutralizing" -and $config.AutoContainDefenderDetections) {
        Start-Sleep -Seconds ([int]$config.DefenderRemediationGraceSeconds)
        $matchingActiveThreats = @(Get-MatchingActiveThreats $Identity)
        if ($matchingActiveThreats.Count -gt 0) {
            try {
                Invoke-SentinelGlobalThreatRemoval -Config $config -Identity $Identity -Threats $matchingActiveThreats -AlertLog $alertLog
            } catch {
                Write-SentinelError -Root $Root -Component "Watcher" -Operation "Post-1117 active-threat escalation" -Exception $_.Exception
            }
        }
    }
}

function Handle-DefenderEvents {
    param([ref]$LastRecordId)
    try {
        $ids=1116,1117,1118,1119,1121,1122,1123,1124,1125,1126,1127,1128,1129,5007
        $batch=Get-SentinelEventBatch -LogName 'Microsoft-Windows-Windows Defender/Operational' -Cursor $LastRecordId.Value -CursorTime $script:defenderCursorTime -Ids $ids -BatchSize ([int]$config.EventBatchSize)
        if ($batch.Reset) {
            if (-not (Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{Type='EventLogCursorReset';Severity='HIGH';Log='Defender';PreviousCursor=$LastRecordId.Value;Reason='Cursor anchor disappeared or changed; log cleared or overwritten.'}))) { throw 'Cannot record event-log gap.' }
            $LastRecordId.Value=0L; $script:defenderCursorTime=''
            Write-SentinelAtomicJson $defenderCursorPath ([ordered]@{RecordId=0L;TimeCreated=''})
        }
        $events=@($batch.Events)

        foreach ($event in $events) {
            $identity = ConvertFrom-DefenderEvent $event
            $eventWritten=Write-SentinelJsonLine -Path (Get-DefenderLogPath $event.Id) -Data ([ordered]@{
                Type="DefenderEvent"
                EventId=$event.Id
                RecordId=$event.RecordId
                DetectionId=$identity.DetectionId
                ThreatId=$identity.ThreatId
                ThreatName=$identity.ThreatName
                Path=$identity.Path
                ActionId=$identity.ActionId
                ActionName=$identity.ActionName
                ErrorCode=$identity.ErrorCode
                Message=$event.Message
            })
            if (-not $eventWritten) { throw 'Cannot persist Defender event; cursor not advanced.' }

            if ($event.Id -eq 1116) {
                $pendingDefenderDetections[[string]$event.RecordId] = [pscustomobject]@{
                    RecordId=[long]$event.RecordId
                    DetectedAt=$event.TimeCreated
                    DetectionId=$identity.DetectionId
                    ThreatId=$identity.ThreatId
                    ThreatName=$identity.ThreatName
                    Path=$identity.Path
                    Resources=@($identity.Resources)
                    Alerted=$false
                }
                Save-PendingDefenderDetections
            }

            if ($event.Id -in @(1117,1118,1119)) {
                Handle-DefenderOutcome -Event $event -Identity $identity
            }

            if ($event.Id -eq 5007) {
                try {
                    & (Join-Path $Root "DefenderHealth.ps1") -Root $Root -Quiet
                } catch {
                    Write-SentinelError -Root $Root -Component "Watcher" -Operation "Health check after Defender configuration change" -Exception $_.Exception
                }
            }

            Write-SentinelAtomicJson $defenderCursorPath ([ordered]@{RecordId=[long]$event.RecordId;TimeCreated=$event.TimeCreated.ToString('o')})
            $LastRecordId.Value=[long]$event.RecordId
            $script:defenderCursorTime=$event.TimeCreated.ToString('o')
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Read Defender Operational events" -Exception $_.Exception
    }
}

function Check-UnresolvedDefenderDetections {
    $now = Get-Date
    $stateChanged = $false

    foreach ($key in @($pendingDefenderDetections.Keys)) {
        $item = $pendingDefenderDetections[$key]
        $ageSeconds = ($now - $item.DetectedAt).TotalSeconds

        if (-not $item.Alerted -and $ageSeconds -ge [int]$config.UnresolvedDefenderDetectionAlertSeconds) {
            [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                Type="DefenderRemediationPending"
                Severity="HIGH"
                DetectionRecordId=$item.RecordId
                DetectionId=$item.DetectionId
                ThreatId=$item.ThreatId
                ThreatName=$item.ThreatName
                Path=$item.Path
                DetectedAt=$item.DetectedAt.ToString("o")
                AgeSeconds=[math]::Round($ageSeconds,1)
                Reason="1116 has not yet been correlated with 1117, 1118, or 1119. No broad Remove-MpThreat action was taken."
            }))
            $item.Alerted=$true
            $stateChanged = $true
        }

        if ($ageSeconds -gt [int]$config.DefenderCorrelationWindowSeconds) {
            [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                Type="DefenderPendingExpired"
                Severity="MEDIUM"
                DetectionRecordId=$item.RecordId
                DetectionId=$item.DetectionId
                ThreatId=$item.ThreatId
                ThreatName=$item.ThreatName
                Path=$item.Path
                DetectedAt=$item.DetectedAt.ToString("o")
                AgeSeconds=[math]::Round($ageSeconds,1)
                CorrelationWindowSeconds=[int]$config.DefenderCorrelationWindowSeconds
                Reason="The Defender correlation window expired. The pending record was archived to logs and removed from active pending state."
            }))
            [void]$pendingDefenderDetections.Remove([string]$key)
            $stateChanged = $true
        }
    }

    if ($stateChanged) {
        Save-PendingDefenderDetections
    }
}

try {
    $startupPhase='Load pending Defender detections'
    Load-PendingDefenderDetections

    $startedAt = Get-Date
    Write-TextLog "SentinelLocal v1.2.1 watcher started."

    $startupPhase='Register process-start monitor'
    $processMonitorMode=Initialize-SentinelProcessMonitor $config

    $startupPhase='Capture initial persistence snapshot'
    $initialSnapshot=Get-PersistenceSnapshot
    $startupPhase='Commit initial persistence comparison'
    Update-SentinelPersistenceSnapshot -Root $Root -Current $initialSnapshot -Compare { param($old,$new) Compare-Persistence $old $new }
    $lastPersistence=Get-Date
    $lastHealth=(Get-Date).AddSeconds(-1 * [int]$config.DefenderHealthPollSeconds)
    $lastHeartbeat=(Get-Date).AddSeconds(-1 * [int]$config.HeartbeatSeconds)
    $lastRetention=(Get-Date).AddHours(-13)
    $lastFirewallCleanup=(Get-Date).AddSeconds(-1 * [int]$config.FirewallCleanupSeconds)

    $startupPhase='Initialize Defender cursor'
    $lastDefenderRecord=0L
    if (Test-Path -LiteralPath $defenderCursorPath) {
        $savedCursor=Get-Content -LiteralPath $defenderCursorPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        $lastDefenderRecord=[long]$savedCursor.RecordId
        $defenderCursorTime=[string]$savedCursor.TimeCreated
    }
    if (-not (Test-Path -LiteralPath $defenderCursorPath) -and (Test-Path $lastDefenderState)) {
        try {
            $lastDefenderRecord=[long](Get-Content -LiteralPath $lastDefenderState -Raw -ErrorAction Stop)
        } catch {
            Write-SentinelError -Root $Root -Component "Watcher" -Operation "Read Defender record cursor" -Exception $_.Exception -Severity "MEDIUM"
        }
    } elseif (-not (Test-Path -LiteralPath $defenderCursorPath)) {
        try {
            $event=Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 1 -ErrorAction Stop
            if ($event) { $lastDefenderRecord=[long]$event.RecordId; $defenderCursorTime=$event.TimeCreated.ToString('o'); Write-SentinelAtomicJson $defenderCursorPath ([ordered]@{RecordId=$lastDefenderRecord;TimeCreated=$defenderCursorTime}) }
        } catch {
            Write-SentinelError -Root $Root -Component "Watcher" -Operation "Initialize Defender record cursor" -Exception $_.Exception
        }
    }

    $startupPhase='Write initial heartbeat'
    Write-Heartbeat -LastDefenderRecordId $lastDefenderRecord -StartedAt $startedAt
} catch {
    Write-SentinelError -Root $Root -Component 'Watcher' -Operation 'Initialize monitoring' -Exception $_.Exception -Context @{
        Phase=$startupPhase;ErrorId=$_.FullyQualifiedErrorId;ScriptStackTrace=$_.ScriptStackTrace
    }
    throw
}

while ($true) {
    try {
        if($processMonitorMode -eq 'Sysmon') {Start-Sleep -Seconds ([int]$config.PollSeconds);$processEvent=$null}
        else {$processEvent=Wait-Event -SourceIdentifier "SentinelLocal.ProcessStart" -Timeout ([int]$config.PollSeconds)}
        if ($processEvent) {
            Invoke-SentinelVolatileObservation -Root $Root -Event $processEvent -Handler {
            param($processEvent)
            $processIdValue=[int]$processEvent.SourceEventArgs.NewEvent.ProcessID
            $processInfo=Get-ProcessInfo $processIdValue
            if ($processInfo) {
                $scoreResult=Get-ProcessScore $processInfo
                $excepted=Test-SentinelException -Path $processInfo.ExecutablePath -Config $config
                if ($scoreResult.Score -gt 0 -and $config.ScanReferencedScripts) {
                    foreach ($scriptTarget in @(Get-SentinelScriptTargets -ExecutablePath $processInfo.ExecutablePath -CommandLine $processInfo.CommandLine)) {
                        if (-not (Test-SentinelException -Path $scriptTarget -Config $config)) {
                            Queue-SentinelResponse -FilePath $scriptTarget -Score ([math]::Max($scoreResult.Score,[int]$config.ScorePolicy.DefenderCustomScan)) -Reasons (@($scoreResult.Reasons)+@('Referenced script static scan')) -Source 'ScriptArgument'
                        }
                    }
                    $decodedPath=Save-SentinelDecodedCommand -Root $Root -CommandLine $processInfo.CommandLine -ExecutablePath $processInfo.ExecutablePath
                    if ($decodedPath) { Queue-SentinelResponse -FilePath $decodedPath -Score ([math]::Max($scoreResult.Score,[int]$config.ScorePolicy.DefenderCustomScan)) -Reasons (@($scoreResult.Reasons)+@('Captured EncodedCommand static scan; never executed')) -Source 'DecodedScript' }
                    if ($processInfo.CommandLine -match '(?i)-(enc|encodedcommand)\b|https?://') {
                        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{Type='ScriptContentContext';Severity='MEDIUM';Process=$processInfo;DecodedPayloadPath=$decodedPath;Reason='Decodable PowerShell payloads are captured for static scanning only; invalid/unsupported encoding and remote content remain unscanned. Runtime behavior still depends on Defender AMSI.'}))
                    }
                }
                if ($scoreResult.Score -ge [int]$config.ScorePolicy.DefenderCustomScan -and $processInfo.ExecutablePath -and -not $excepted) {
                    Queue-SentinelResponse -FilePath $processInfo.ExecutablePath -ProcessIdValue $processIdValue -Score $scoreResult.Score -Reasons $scoreResult.Reasons -Source "Process" -ObservedProcess $processInfo
                } elseif ($scoreResult.Score -gt 0) {
                    [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                        Type="ProcessLowScore";Score=$scoreResult.Score;Reasons=$scoreResult.Reasons;Process=$processInfo
                    }))
                }

                if ($config.AutoKillHeuristicProcesses -and $scoreResult.Score -ge [int]$config.HeuristicKillThreshold -and -not $excepted) {
                    if (Test-ProcessIdentityMatch $processInfo) {
                        try {
                            Stop-Process -Id $processIdValue -Force -ErrorAction Stop
                        } catch {
                            Write-SentinelError -Root $Root -Component "Watcher" -Operation "Heuristic process stop" -Exception $_.Exception -Context @{ProcessId=$processIdValue;Score=$scoreResult.Score}
                        }
                    } else {
                        [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{
                            Type="ProcessStopSkipped"
                            Severity="MEDIUM"
                            ProcessId=$processIdValue
                            Path=$processInfo.ExecutablePath
                            CreationDate=$processInfo.CreationDate
                            Reason="PID/path/creation-time identity no longer matches; possible process exit or PID reuse."
                        }))
                    }
                }
            }
            if (-not $processInfo) {
                [void](Write-SentinelJsonLine -Path $alertLog -Data ([ordered]@{Type='ProcessObservationGap';Severity='MEDIUM';ProcessId=$processIdValue;ProcessName=[string]$processEvent.SourceEventArgs.NewEvent.ProcessName;Reason='Process ended before metadata capture. Enable existing Sysmon process-create telemetry for durable metadata.'}))
            }
            } # Volatile event acknowledgement runs in finally.
        }
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Process-start event loop" -Exception $_.Exception
    }

    $recordRef=[ref]$lastDefenderRecord
    Handle-DefenderEvents $recordRef
    $lastDefenderRecord=$recordRef.Value
    try {
        Set-Content -LiteralPath $lastDefenderState -Value $lastDefenderRecord -Encoding ASCII -ErrorAction Stop
    } catch {
        Write-SentinelError -Root $Root -Component "Watcher" -Operation "Save Defender record cursor" -Exception $_.Exception
    }

    Check-UnresolvedDefenderDetections
    if ($config.Sysmon.Enabled) {
        try {
            Read-SentinelSysmon -Root $Root -Config $config -ScoreProcess {param($observed) Get-ProcessScore $observed} -QueueResponse {
                param($path,$processIdValue,$score,$observed)
                Queue-SentinelResponse -FilePath $path -ProcessIdValue $processIdValue -Score $score.Score -Reasons $score.Reasons -Source 'Sysmon' -ObservedProcess $observed
            }
        } catch { Write-SentinelError -Root $Root -Component Sysmon -Operation 'Read events' -Exception $_.Exception }
    }

    if (((Get-Date)-$lastPersistence).TotalSeconds -ge [int]$config.PersistencePollSeconds) {
        try {
            $newSnapshot=Get-PersistenceSnapshot
            Update-SentinelPersistenceSnapshot -Root $Root -Current $newSnapshot -Compare { param($old,$new) Compare-Persistence $old $new }
            $lastPersistence=Get-Date
        } catch { Write-SentinelError -Root $Root -Component Watcher -Operation 'Durable persistence comparison' -Exception $_.Exception; $lastPersistence=Get-Date }
    }

    if (((Get-Date)-$lastHealth).TotalSeconds -ge [int]$config.DefenderHealthPollSeconds) {
        try {
            & (Join-Path $Root "DefenderHealth.ps1") -Root $Root -Quiet
        } catch {
            Write-SentinelError -Root $Root -Component "Watcher" -Operation "Scheduled Defender health check" -Exception $_.Exception
        }
        Check-IntegrityMonitorHeartbeat
        $lastHealth=Get-Date
    }

    if (((Get-Date)-$lastHeartbeat).TotalSeconds -ge [int]$config.HeartbeatSeconds) {
        Write-Heartbeat -LastDefenderRecordId $lastDefenderRecord -StartedAt $startedAt
        $lastHeartbeat=Get-Date
    }

    if (((Get-Date)-$lastFirewallCleanup).TotalSeconds -ge [int]$config.FirewallCleanupSeconds) {
        Remove-ExpiredSentinelFirewallRules -Root $Root
        $lastFirewallCleanup=Get-Date
    }

    if (((Get-Date)-$lastRetention).TotalHours -ge 12) {
        Invoke-SentinelRetention -Root $Root -MaxLogDays ([int]$config.MaxLogDays)
        $lastRetention=Get-Date
    }
}
