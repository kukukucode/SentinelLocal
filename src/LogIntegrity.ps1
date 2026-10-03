# Shared append/retention/verification transaction support. All paths are local
# checkpoints, not independent proof against an administrator controlling the host.
function Write-SentinelAtomicJson {
    param([string]$Path,$Data)
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $encoding=[System.Text.UTF8Encoding]::new($true)
        $bytes = $encoding.GetPreamble() + $encoding.GetBytes((ConvertTo-Json -InputObject $Data -Depth 20 -Compress))
        $stream = [System.IO.File]::Open($temp,[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if ([System.IO.File]::Exists($Path)) { [System.IO.File]::Replace($temp,$Path,[NullString]::Value) }
        else { [System.IO.File]::Move($temp,$Path) }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}

function Get-SentinelChainPath {
    param([string]$Path)
    $root = Split-Path -Parent (Split-Path -Parent $Path)
    return Join-Path $root ('state\log-chain\' + [IO.Path]::GetFileName($Path) + '.state')
}

function Enter-SentinelLogLock {
    param([string]$Path)
    $suffix = (Get-SentinelStringHash ([IO.Path]::GetFullPath($Path).ToLowerInvariant())).Substring(0,24)
    # Default kernel-object permissions depend on the creator's token. A SYSTEM
    # writer and an elevated administrator must share the same transaction lock.
    # Supply permissions at creation, without a create-then-set-ACL race.
    $security = [Security.AccessControl.MutexSecurity]::new()
    $security.SetAccessRuleProtection($true,$false)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $privileged = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $identity.User.Value -eq 'S-1-5-18'
        $allowed = @('S-1-5-18','S-1-5-32-544')
        # Non-elevated development fixtures remain usable by their creator.
        # Elevated production locks never grant the administrator's user SID:
        # that would also grant the same user's non-elevated processes access.
        if (-not $privileged) { $allowed += $identity.User.Value }
        $owner = if ($privileged) { 'S-1-5-32-544' } else { $identity.User.Value }
        $security.SetOwner([Security.Principal.SecurityIdentifier]::new($owner))
        foreach ($sid in $allowed) {
            $security.AddAccessRule([Security.AccessControl.MutexAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.MutexRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
        }
    } finally { $identity.Dispose() }
    $created = $false
    $mutex = [System.Threading.Mutex]::new($false,('Global\SentinelLocalLog_' + $suffix),[ref]$created,$security)
    try {
        # Constructor security is ignored for an already existing named object.
        # Refuse a legacy or pre-created production lock with a weaker ACL;
        # never resecure an object while another process might own a handle.
        if ($privileged) {
            $actual = $mutex.GetAccessControl()
            $rules = @($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
            if (-not $actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544' -or $rules.Count -ne 2) { throw 'Log mutex has an unexpected owner or access policy; restart components after a verified upgrade.' }
            foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
                if (@($rules | Where-Object { $_.IdentityReference.Value -eq $sid -and $_.AccessControlType -eq 'Allow' -and $_.MutexRights -eq 'FullControl' }).Count -ne 1) { throw 'Log mutex has an unexpected access policy; restart components after a verified upgrade.' }
            }
        }
        try { $locked = $mutex.WaitOne([TimeSpan]::FromSeconds(10)) }
        catch [System.Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { throw 'Timed out waiting for log lock.' }
        return $mutex
    } catch { $mutex.Dispose(); throw }
}

function Get-SentinelLogSnapshot {
    param([string]$Path)
    $count = 0L; $last = $null; $first = $null
    if (Test-Path -LiteralPath $Path) {
        foreach ($line in [System.IO.File]::ReadLines($Path)) {
            $obj = $line | ConvertFrom-Json -ErrorAction Stop
            if ($obj._ChainAlg -ne 'SHA256' -or -not $obj._ChainPrev -or -not $obj._ChainHash) { throw 'Missing hash-chain fields.' }
            if ($count -eq 0) { $first = [string]$obj._ChainPrev }
            elseif ([string]$obj._ChainPrev -ne $last) { throw ('Previous hash mismatch at line ' + ($count + 1)) }
            $payload = [ordered]@{}
            foreach ($property in $obj.PSObject.Properties) {
                if ($property.Name -notin @('_ChainAlg','_ChainPrev','_ChainHash')) { $payload[$property.Name] = $property.Value }
            }
            $hash = Get-SentinelStringHash ([string]$obj._ChainPrev + "`n" + ($payload | ConvertTo-Json -Depth 14 -Compress))
            if ($hash -ne [string]$obj._ChainHash) { throw ('Hash mismatch at line ' + ($count + 1)) }
            $last = [string]$obj._ChainHash; $count++
        }
    }
    $length = if (Test-Path -LiteralPath $Path) { (Get-Item -LiteralPath $Path).Length } else { 0L }
    return [pscustomobject]@{LineCount=$count;LastHash=$last;FirstPreviousHash=$first;ByteLength=[long]$length}
}

function Test-SentinelSnapshotMatches {
    param($Snapshot,$Checkpoint)
    return ($Snapshot.LineCount -eq [long]$Checkpoint.LineCount -and $Snapshot.ByteLength -eq [long]$Checkpoint.ByteLength -and
        ($Snapshot.LineCount -eq 0 -or ($Snapshot.LastHash -eq $Checkpoint.LastHash -and $Snapshot.FirstPreviousHash -eq $Checkpoint.FirstPreviousHash)))
}

function Repair-SentinelLogTransaction {
    param([string]$Path)
    $statePath = Get-SentinelChainPath $Path
    $pendingPath = $statePath + '.pending'
    if (-not (Test-Path -LiteralPath $pendingPath)) { return }
    $pending = Get-Content -LiteralPath $pendingPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $snapshot = Get-SentinelLogSnapshot $Path
    if (Test-SentinelSnapshotMatches $snapshot $pending.After) { Write-SentinelAtomicJson $statePath $pending.After }
    elseif (-not (Test-SentinelSnapshotMatches $snapshot $pending.Before)) { throw 'Incomplete log transaction does not match either checkpoint.' }
    if ($pending.TempPath -and (Test-Path -LiteralPath $pending.TempPath)) {
        if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($pending.TempPath)) -ne [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))) { throw 'Invalid transaction temporary path.' }
        Remove-Item -LiteralPath $pending.TempPath -Force
    }
    Remove-Item -LiteralPath $pendingPath -Force
}

function Get-SentinelLogCheckpoint {
    param([string]$Path)
    $statePath = Get-SentinelChainPath $Path
    Repair-SentinelLogTransaction $Path
    $exists = Test-Path -LiteralPath $Path
    $length = if ($exists) { (Get-Item -LiteralPath $Path).Length } else { 0L }
    $checkpoint = if (Test-Path -LiteralPath $statePath) { Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop } else { $null }
    if (-not $checkpoint) {
        if ($length -gt 0) { throw 'Log checkpoint missing; refusing to silently trust existing records.' }
        return [pscustomobject]@{Schema=2;LogPath=$Path;LastHash='GENESIS';FirstPreviousHash='GENESIS';LineCount=0L;ByteLength=0L;LastUpdated=(Get-Date).ToString('o')}
    }
    if (-not $exists -and (-not $checkpoint.PSObject.Properties['LineCount'] -or [long]$checkpoint.LineCount -gt 0)) { throw 'Checkpoint exists but log is missing.' }
    $tail = if ($length -gt 0) { Get-Content -LiteralPath $Path -Tail 1 -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop } else { $null }
    if ($tail -and [string]$tail._ChainHash -ne [string]$checkpoint.LastHash) { throw 'Log tail differs from checkpoint (truncation or incomplete write).' }
    if (-not $checkpoint.PSObject.Properties['Schema'] -or [int]$checkpoint.Schema -lt 2) {
        if (-not $tail) { throw 'Legacy checkpoint has no corresponding log tail.' }
        $snapshot = Get-SentinelLogSnapshot $Path
        $checkpoint = [pscustomobject]@{Schema=2;LogPath=$Path;LastHash=$snapshot.LastHash;FirstPreviousHash=$snapshot.FirstPreviousHash;LineCount=$snapshot.LineCount;ByteLength=$snapshot.ByteLength;LastUpdated=(Get-Date).ToString('o')}
        Write-SentinelAtomicJson $statePath $checkpoint
    }
    if ($length -ne [long]$checkpoint.ByteLength -or ($length -eq 0 -and [long]$checkpoint.LineCount -ne 0)) { throw 'Log length differs from checkpoint.' }
    return $checkpoint
}

function Add-SentinelChainedRecord {
    param([string]$Path,$Payload)
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $mutex = Enter-SentinelLogLock $Path
    try {
        $before = Get-SentinelLogCheckpoint $Path
        $canonical = $Payload | ConvertTo-Json -Depth 14 -Compress
        $hash = Get-SentinelStringHash ([string]$before.LastHash + "`n" + $canonical)
        $Payload['_ChainAlg']='SHA256'; $Payload['_ChainPrev']=[string]$before.LastHash; $Payload['_ChainHash']=$hash
        $encoding = [System.Text.UTF8Encoding]::new($true)
        $bytes = $encoding.GetBytes(($Payload | ConvertTo-Json -Depth 14 -Compress) + [Environment]::NewLine)
        $extraBom = if ([long]$before.ByteLength -eq 0) { 3 } else { 0 }
        $after = [ordered]@{Schema=2;LogPath=$Path;LastHash=$hash;FirstPreviousHash=$before.FirstPreviousHash;LineCount=([long]$before.LineCount + 1);ByteLength=([long]$before.ByteLength + $bytes.Length + $extraBom);LastUpdated=(Get-Date).ToString('o')}
        $statePath = Get-SentinelChainPath $Path
        Write-SentinelAtomicJson ($statePath + '.pending') ([ordered]@{Before=$before;After=$after;Operation='Append'})
        $stream = [System.IO.File]::Open($Path,[System.IO.FileMode]::OpenOrCreate,[System.IO.FileAccess]::Write,[System.IO.FileShare]::Read)
        try {
            [void]$stream.Seek(0,[System.IO.SeekOrigin]::End)
            if ($extraBom) { $bom=$encoding.GetPreamble(); $stream.Write($bom,0,$bom.Length) }
            $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true)
        } finally { $stream.Dispose() }
        Write-SentinelAtomicJson $statePath $after
        Remove-Item -LiteralPath ($statePath + '.pending') -Force
    } finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
}

function Get-SentinelLogVerification {
    param([string]$Path)
    $mutex = $null
    try {
        $mutex = Enter-SentinelLogLock $Path
        if (-not (Test-Path -LiteralPath (Get-SentinelChainPath $Path))) { throw 'Missing checkpoint.' }
        $checkpoint = Get-SentinelLogCheckpoint $Path
        $snapshot = Get-SentinelLogSnapshot $Path
        if (-not (Test-SentinelSnapshotMatches $snapshot $checkpoint)) { throw 'Head, tail, count, or length differs from checkpoint.' }
        return [pscustomobject]@{Log=[IO.Path]::GetFileName($Path);Valid=$true;Lines=$snapshot.LineCount;Detail='OK (local checkpoint)'}
    } catch { return [pscustomobject]@{Log=[IO.Path]::GetFileName($Path);Valid=$false;Lines=0;Detail=$_.Exception.Message} }
    finally { if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() } }
}

function Invoke-SentinelJsonRetention {
    param([string]$Path,[datetime]$Cutoff)
    $mutex = Enter-SentinelLogLock $Path
    $temp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.retention.tmp'
    try {
        $before = Get-SentinelLogCheckpoint $Path
        if (-not (Test-SentinelSnapshotMatches (Get-SentinelLogSnapshot $Path) $before)) { throw 'Cannot retain an invalid log.' }
        $writer = [System.IO.StreamWriter]::new($temp,$false,[System.Text.UTF8Encoding]::new($true))
        $prefix = $true; $removed = 0L; $kept = 0L; $first = [string]$before.LastHash
        try {
            foreach ($line in [System.IO.File]::ReadLines($Path)) {
                $obj = $line | ConvertFrom-Json -ErrorAction Stop
                $old = $false
                if ($obj.Timestamp) { $old = [datetimeoffset]::Parse([string]$obj.Timestamp).LocalDateTime -lt $Cutoff }
                if ($prefix -and $old) { $removed++; continue }
                $prefix = $false
                if ($kept -eq 0) { $first = [string]$obj._ChainPrev }
                $writer.WriteLine($line); $kept++
            }
            $writer.Flush(); $writer.BaseStream.Flush($true)
        } finally { $writer.Dispose() }
        if ($removed -eq 0) { return }
        if ($kept -eq 0) { [System.IO.File]::WriteAllBytes($temp,[byte[]]@()) }
        $after = [ordered]@{Schema=2;LogPath=$Path;LastHash=$before.LastHash;FirstPreviousHash=$first;LineCount=$kept;ByteLength=(Get-Item -LiteralPath $temp).Length;LastUpdated=(Get-Date).ToString('o')}
        $statePath = Get-SentinelChainPath $Path
        Write-SentinelAtomicJson ($statePath + '.pending') ([ordered]@{Before=$before;After=$after;Operation='Retention';TempPath=$temp})
        [System.IO.File]::Replace($temp,$Path,[NullString]::Value)
        Write-SentinelAtomicJson $statePath $after
        Remove-Item -LiteralPath ($statePath + '.pending') -Force
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
        $mutex.ReleaseMutex(); $mutex.Dispose()
    }
}

function Get-SentinelLogHealth {
    param([string]$Root)
    $logDir=Join-Path $Root 'logs'
    $names=@(Get-ChildItem -LiteralPath $logDir -File -Filter '*.jsonl' -ErrorAction SilentlyContinue | ForEach-Object Name)
    $names+=@(Get-ChildItem -LiteralPath (Join-Path $Root 'state\log-chain') -File -Filter '*.jsonl.state' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.Substring(0,$_.Name.Length-6) })
    $checks=@()
    foreach ($name in @($names | Sort-Object -Unique)) {
        $mutex=$null
        try {
            $path=Join-Path $logDir $name; $mutex=Enter-SentinelLogLock $path
            if (-not (Test-Path -LiteralPath (Get-SentinelChainPath $path))) { throw 'Missing checkpoint.' }
            [void](Get-SentinelLogCheckpoint $path)
            $checks += [pscustomobject]@{Log=$name;Healthy=$true;Detail='Tail/length checkpoint OK'}
        } catch { $checks += [pscustomobject]@{Log=$name;Healthy=$false;Detail=$_.Exception.Message} }
        finally { if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() } }
    }
    return $checks
}
