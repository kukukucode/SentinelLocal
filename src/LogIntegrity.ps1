# Shared append/retention/verification transaction support. All paths are local
# checkpoints, not independent proof against an administrator controlling the host.
function Write-SentinelAtomicJson {
    param([string]$Path,$Data)
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    # Keep the random temporary name independent of the target's basename.
    # Appending to a long checkpoint name can exceed legacy .NET MAX_PATH even
    # when the final destination is valid. The same parent preserves atomicity.
    $temp = Join-Path $parent ('.sl-' + [guid]::NewGuid().ToString('N') + '.tmp')
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
    $checkpoint=Join-Path $root ('state\log-chain\' + [IO.Path]::GetFileName($Path) + '.state')
    Assert-SentinelLogPath $checkpoint
    return $checkpoint
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
    Repair-SentinelLogRotation $Path
    Repair-SentinelSegmentRetirement $Path
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
    param([string]$Path,$Payload,[long]$MaxFileBytes=0,[long]$MaxTotalBytes=0)
    Add-SentinelChainedRecords -Path $Path -Payloads @($Payload) -MaxFileBytes $MaxFileBytes -MaxTotalBytes $MaxTotalBytes
}

function Add-SentinelChainedRecords {
    param([string]$Path,[object[]]$Payloads,[long]$MaxFileBytes=0,[long]$MaxTotalBytes=0)
    if(-not $Payloads.Count){return}
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    Assert-SentinelLogPath $Path
    $budget=Enter-SentinelLogLock (Join-Path (Split-Path -Parent $Path) '__capacity')
    $mutex=$null
    try {
        $mutex = Enter-SentinelLogLock $Path
        $before = Get-SentinelLogCheckpoint $Path
        if($before.PSObject.Properties['ArchiveOf']){throw 'Immutable log segments cannot be appended.'}
        [void](Read-SentinelSegmentIndex $Path $before)
        $encoding = [System.Text.UTF8Encoding]::new($true)
        $buffer=[IO.MemoryStream]::new();$last=[string]$before.LastHash
        try {
            foreach($payload in $Payloads){
                $canonical=$payload | ConvertTo-Json -Depth 14 -Compress
                $hash=Get-SentinelStringHash ($last+"`n"+$canonical)
                $payload['_ChainAlg']='SHA256';$payload['_ChainPrev']=$last;$payload['_ChainHash']=$hash
                $rowBytes=$encoding.GetBytes(($payload | ConvertTo-Json -Depth 14 -Compress)+[Environment]::NewLine)
                $buffer.Write($rowBytes,0,$rowBytes.Length);$last=$hash
            }
            $bytes=$buffer.ToArray()
        }finally{$buffer.Dispose()}
        $extraBom = if ([long]$before.ByteLength -eq 0) { 3 } else { 0 }
        $willRotate=$MaxFileBytes -gt 0 -and $before.ByteLength -gt 0 -and $before.ByteLength+$bytes.Length+$extraBom -gt $MaxFileBytes
        if($willRotate){$extraBom=3}
        if($MaxFileBytes -gt 0 -and $bytes.Length+3 -gt $MaxFileBytes){throw 'A single log batch exceeds the segment limit.'}
        if($MaxTotalBytes -gt 0){$total=0L;foreach($file in @(Get-ChildItem -LiteralPath (Split-Path -Parent $Path) -File -Filter '*.jsonl' -ErrorAction Stop)){$total+=$file.Length};if($total+$bytes.Length+$extraBom -gt $MaxTotalBytes){throw 'Total log capacity reached; retained evidence was not deleted.'}}
        if($willRotate){Move-SentinelLogSegment $Path $before;$before=Get-SentinelLogCheckpoint $Path}
        $after = [ordered]@{Schema=2;LogPath=$Path;LastHash=$last;FirstPreviousHash=$before.FirstPreviousHash;LineCount=([long]$before.LineCount + $Payloads.Count);ByteLength=([long]$before.ByteLength + $bytes.Length + $extraBom);LastUpdated=(Get-Date).ToString('o')}
        if($before.PSObject.Properties['SegmentSequence']){$after['SegmentSequence']=[long]$before.SegmentSequence}
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
    } finally { if($mutex){$mutex.ReleaseMutex();$mutex.Dispose()};$budget.ReleaseMutex();$budget.Dispose() }
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
        [void](Read-SentinelSegmentIndex $Path $checkpoint -Deep)
        return [pscustomobject]@{Log=[IO.Path]::GetFileName($Path);Valid=$true;Lines=$snapshot.LineCount;Detail='OK (local checkpoint)'}
    } catch { return [pscustomobject]@{Log=[IO.Path]::GetFileName($Path);Valid=$false;Lines=0;Detail=$_.Exception.Message} }
    finally { if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() } }
}

function Invoke-SentinelJsonRetention {
    param([string]$Path,[datetime]$Cutoff)
    $budget=Enter-SentinelLogLock (Join-Path (Split-Path -Parent $Path) '__capacity')
    $mutex = $null
    $temp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.retention.tmp'
    try {
        $mutex = Enter-SentinelLogLock $Path
        $before = Get-SentinelLogCheckpoint $Path
        if($before.PSObject.Properties['ArchiveOf']){throw 'Immutable segments must be retired through their active stream.'}
        if(Test-Path -LiteralPath ((Get-SentinelChainPath $Path)+'.segments.json')){Invoke-SentinelSegmentRetention $Path $Cutoff;return}
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
        if($mutex){$mutex.ReleaseMutex(); $mutex.Dispose()}
        $budget.ReleaseMutex();$budget.Dispose()
    }
}

function Get-SentinelLogStreamPaths {
    param([string]$Path)
    Assert-SentinelLogPath $Path
    $statePath=Get-SentinelChainPath $Path
    foreach($suffix in @('.pending','.rotate.pending','.retire.pending')){if(Test-Path -LiteralPath ($statePath+$suffix)){throw 'Log stream has an incomplete transaction.'}}
    if(-not (Test-Path -LiteralPath $statePath)){return @($Path)}
    $state=Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if($state.PSObject.Properties['ArchiveOf']){return @($Path)}
    $index=Read-SentinelSegmentIndex $Path $state
    if($index){foreach($entry in @($index.Segments)){Join-Path (Split-Path -Parent $Path) $entry.Name}}
    $Path
}

function Read-SentinelLogRows {
    param([string]$Path,[int]$Tail=0)
    $budget=Enter-SentinelLogLock (Join-Path (Split-Path -Parent $Path) '__capacity')
    try{
        $paths=@(Get-SentinelLogStreamPaths $Path)
        if($Tail -gt 0){
            $lines=@()
            for($i=$paths.Count-1;$i -ge 0 -and $lines.Count -lt $Tail;$i--){$lines=@(Get-Content -LiteralPath $paths[$i] -Tail ($Tail-$lines.Count) -Encoding UTF8 -ErrorAction Stop)+$lines}
            foreach($line in $lines){$line | ConvertFrom-Json -ErrorAction Stop}
        }else{foreach($file in $paths){Get-Content -LiteralPath $file -Encoding UTF8 -ErrorAction Stop | ForEach-Object {$_ | ConvertFrom-Json -ErrorAction Stop}}}
    }finally{$budget.ReleaseMutex();$budget.Dispose()}
}

function Copy-SentinelLogSnapshot {
    param([string]$Root,[string]$Stage)
    $source=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    if([IO.Path]::GetFullPath($Stage).StartsWith($source,[StringComparison]::OrdinalIgnoreCase)){throw 'Snapshot must be outside the installation.'}
    Assert-SentinelLogPath (Join-Path $Root 'logs');Assert-SentinelLogPath $Stage
    New-Item -ItemType Directory -Path (Join-Path $Stage 'logs'),(Join-Path $Stage 'state\log-chain') -Force | Out-Null
    $budget=Enter-SentinelLogLock (Join-Path $Root 'logs\__capacity')
    try{
        $names=@(Get-ChildItem -LiteralPath (Join-Path $Root 'logs') -File -Filter '*.jsonl' -ErrorAction Stop | ForEach-Object {$_.Name})
        $names+=@(Get-ChildItem -LiteralPath (Join-Path $Root 'state\log-chain') -File -Filter '*.jsonl.state' -ErrorAction Stop | ForEach-Object {$_.Name.Substring(0,$_.Name.Length-6)})
        $names=@($names | Sort-Object -Unique)
        if(-not $names.Count){throw 'No source log streams available.'}
        foreach($name in $names){
            $path=Join-Path $Root ('logs\'+$name);Assert-SentinelLogPath $path;$mutex=Enter-SentinelLogLock $path
            try{
                $statePath=Get-SentinelChainPath $path
                Assert-SentinelLogPath $statePath
                if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw ('Source log missing: '+$name)}
                foreach($suffix in @('.pending','.rotate.pending','.retire.pending')){if(Test-Path -LiteralPath ($statePath+$suffix)){throw 'A source log transaction is pending; snapshot will not repair it.'}}
                $state=Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                if($state.Schema -ne 2 -or (Get-Item -LiteralPath $path).Length -ne [long]$state.ByteLength){throw ('Source checkpoint mismatch: '+$name)}
                Copy-Item -LiteralPath $path -Destination (Join-Path $Stage ('logs\'+$name)) -ErrorAction Stop
                Write-SentinelAtomicJson (Get-SentinelChainPath (Join-Path $Stage ('logs\'+$name))) $state
            }finally{$mutex.ReleaseMutex();$mutex.Dispose()}
        }
        foreach($index in @(Get-ChildItem -LiteralPath (Join-Path $Root 'state\log-chain') -File -Filter '*.segments.json' -ErrorAction Stop)){
            Assert-SentinelLogPath $index.FullName
            $name=$index.Name.Substring(0,$index.Name.Length-'.state.segments.json'.Length)
            if($index.Name -cne ($name+'.state.segments.json') -or $name -cnotin $names){throw 'Orphan segment index refused.'}
            Copy-Item -LiteralPath $index.FullName -Destination (Join-Path $Stage ('state\log-chain\'+$index.Name)) -ErrorAction Stop
        }
    }finally{$budget.ReleaseMutex();$budget.Dispose()}
    # Parse/hash the copies after releasing production locks, not while blocking
    # collection behind a full historical-chain verification.
    $entries=@()
    foreach($name in $names){
        $path=Join-Path $Stage ('logs\'+$name);$statePath=Get-SentinelChainPath $path
        $state=Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        if(-not $state.PSObject.Properties['ArchiveOf']){if(-not (Get-SentinelLogVerification $path).Valid){throw ('Copied stream/segments failed verification: '+$name)}}
        elseif([string]$state.ArchiveOf -cnotin $names){throw 'Segment active stream missing from snapshot.'}
        $entry=[ordered]@{Name=$name;SHA256=(Get-FileHash -LiteralPath $path).Hash;Length=[long]$state.ByteLength;LineCount=[long]$state.LineCount;LastHash=[string]$state.LastHash}
        if(Test-Path -LiteralPath ($statePath+'.segments.json')){$entry['SegmentIndexSHA256']=(Get-FileHash -LiteralPath ($statePath+'.segments.json')).Hash}
        $entries+=@($entry)
    }
    return $entries
}

function Get-SentinelLogLimits {
    param($Config)
    if(-not $Config -or -not $Config.Resources){return [pscustomobject]@{FileBytes=0L;TotalBytes=0L}}
    $total=512L
    if($Config.Resources.PSObject.Properties['MaxTotalLogMB']){$total=[long]$Config.Resources.MaxTotalLogMB}
    return [pscustomobject]@{FileBytes=([long]$Config.Resources.MaxLogFileMB*1MB);TotalBytes=($total*1MB)}
}

function Assert-SentinelLogPath {
    param([string]$Path)
    $ancestor=[IO.Path]::GetFullPath($Path)
    while($ancestor){
        try{if([IO.File]::GetAttributes($ancestor) -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse log path refused.'}}
        catch [IO.FileNotFoundException]{} catch [IO.DirectoryNotFoundException]{}
        $parent=[IO.Path]::GetDirectoryName($ancestor.TrimEnd('\'));if($parent -eq $ancestor){break};$ancestor=$parent
    }
}

function Get-SentinelLogUtcNow {return [datetimeoffset]::UtcNow}

function Assert-SentinelSegmentMetadata {
    param([string]$Path,$Index)
    if($Index.Schema -ne 1 -or $Index.Stream -cne [IO.Path]::GetFileName($Path) -or $null -eq $Index.RetiredSequence -or $Index.RetiredSequence -lt 0 -or $Index.NextSequence -le $Index.RetiredSequence -or [string]$Index.RetiredHash -notmatch '^(GENESIS|[A-Fa-f0-9]{64})$'){throw 'Invalid segment metadata.'}
    $seq=[long]$Index.RetiredSequence;$previous=[string]$Index.RetiredHash
    foreach($entry in @($Index.Segments)){
        $seq++;$expected=[IO.Path]::GetFileNameWithoutExtension($Path)+'.s'+$seq.ToString('D6')+'.jsonl'
        if($seq -gt 999999 -or $entry.Sequence -ne $seq -or $entry.Name -cne $expected -or [string]$entry.SHA256 -notmatch '^[a-fA-F0-9]{64}$' -or $entry.FirstPreviousHash -cne $previous -or [string]$entry.LastHash -notmatch '^[a-fA-F0-9]{64}$' -or $entry.Length -le 0 -or $entry.LineCount -le 0 -or [string]$entry.ClosedAt -notmatch '(Z|[+-]\d{2}:\d{2})$'){throw 'Invalid segment entry.'}
        [void][datetimeoffset]::Parse([string]$entry.ClosedAt);$previous=[string]$entry.LastHash
    }
    if($Index.NextSequence -ne $seq+1){throw 'Invalid segment sequence.'}
}

function Test-SentinelSameJson($Left,$Right){return (ConvertTo-Json -InputObject $Left -Depth 20 -Compress) -ceq (ConvertTo-Json -InputObject $Right -Depth 20 -Compress)}

function Assert-SentinelIndexTransaction {
    param([string]$Path,$Before,$After)
    Assert-SentinelSegmentMetadata $Path $Before;Assert-SentinelSegmentMetadata $Path $After
    $indexPath=(Get-SentinelChainPath $Path)+'.segments.json';Assert-SentinelLogPath $indexPath
    if(Test-Path -LiteralPath $indexPath){
        $current=Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        if(-not (Test-SentinelSameJson $current $Before) -and -not (Test-SentinelSameJson $current $After)){throw 'Segment index differs from both transaction states.'}
    }elseif($Before.RetiredSequence -ne 0 -or @($Before.Segments).Count -ne 0 -or $Before.NextSequence -ne 1){throw 'Transaction index disappeared.'}
}

function Read-SentinelSegmentIndex {
    param([string]$Path,$Checkpoint,[switch]$Deep,[switch]$ValidateDigests)
    $basePath=$Path
    if($Checkpoint.PSObject.Properties['ArchiveOf']){
        if([string]$Checkpoint.ArchiveOf -notmatch '^[A-Za-z0-9_.-]+\.jsonl$' -or ([string]$Checkpoint.ArchiveOf).Contains('..')){throw 'Unsafe archive stream name.'}
        $basePath=Join-Path (Split-Path -Parent $Path) ([string]$Checkpoint.ArchiveOf)
    }
    $indexPath=(Get-SentinelChainPath $basePath)+'.segments.json'
    Assert-SentinelLogPath $indexPath
    $index=$null
    if(Test-Path -LiteralPath $indexPath){$index=Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop}
    if(-not $index){
        if($Checkpoint.PSObject.Properties['ArchiveOf'] -or ($Checkpoint.PSObject.Properties['SegmentSequence'] -and $Checkpoint.SegmentSequence -gt 0)){throw 'Segment index missing.'}
        if(@(Get-ChildItem -LiteralPath (Split-Path -Parent $basePath) -Filter ([IO.Path]::GetFileNameWithoutExtension($basePath)+'.s??????.jsonl') -File -ErrorAction Stop).Count){throw 'Unindexed log segment found.'}
        return $null
    }
    Assert-SentinelSegmentMetadata $basePath $index
    if($index.Schema -ne 1 -or $index.Stream -cne [IO.Path]::GetFileName($basePath) -or $index.RetiredSequence -lt 0 -or $index.NextSequence -le $index.RetiredSequence -or [string]$index.RetiredHash -notmatch '^(GENESIS|[A-Fa-f0-9]{64})$'){throw 'Invalid segment index.'}
    $sequence=[long]$index.RetiredSequence;$previous=[string]$index.RetiredHash;$seen=@{}
    foreach($entry in @($index.Segments)){
        $sequence++;$expected=([IO.Path]::GetFileNameWithoutExtension($basePath)+'.s'+$sequence.ToString('D6')+'.jsonl')
        if($sequence -gt 999999 -or [long]$entry.Sequence -ne $sequence -or $entry.Name -cne $expected -or $seen.ContainsKey($expected) -or [string]$entry.SHA256 -notmatch '^[a-fA-F0-9]{64}$' -or $entry.FirstPreviousHash -ne $previous -or [string]$entry.LastHash -notmatch '^[a-fA-f0-9]{64}$' -or $entry.Length -le 0 -or $entry.LineCount -le 0){throw 'Missing duplicated or invalid segment metadata.'}
        $seen[$expected]=$true;$archive=Join-Path (Split-Path -Parent $basePath) $expected;Assert-SentinelLogPath $archive
        if([string]$entry.ClosedAt -notmatch '(Z|[+-]\d{2}:\d{2})$'){throw 'Segment closure time needs an explicit timezone.'}
        [void][datetimeoffset]::Parse([string]$entry.ClosedAt)
        if(-not (Test-Path -LiteralPath $archive -PathType Leaf) -or (Get-Item -LiteralPath $archive).Length -ne [long]$entry.Length){throw ('Missing/truncated segment: '+$expected)}
        $state=Get-Content -LiteralPath (Get-SentinelChainPath $archive) -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if($state.ArchiveOf -cne $index.Stream -or $state.LastHash -ne $entry.LastHash -or $state.FirstPreviousHash -ne $entry.FirstPreviousHash -or $state.ByteLength -ne $entry.Length -or $state.LineCount -ne $entry.LineCount){throw 'Segment checkpoint differs from index.'}
        if(($Deep -or $ValidateDigests) -and (Get-FileHash -LiteralPath $archive).Hash -ne $entry.SHA256){throw ('Invalid segment digest: '+$expected)}
        if($Deep -and -not (Test-SentinelSnapshotMatches (Get-SentinelLogSnapshot $archive) $state)){throw ('Invalid segment chain: '+$expected)}
        $previous=[string]$entry.LastHash
    }
    if($index.NextSequence -ne $sequence+1){throw 'Segment sequence gap.'}
    $actual=@(Get-ChildItem -LiteralPath (Split-Path -Parent $basePath) -Filter ([IO.Path]::GetFileNameWithoutExtension($basePath)+'.s??????.jsonl') -File -ErrorAction Stop)
    if($actual.Count -ne $seen.Count -or @($actual | Where-Object {-not $seen.ContainsKey($_.Name)}).Count){throw 'Extra/unindexed segment detected.'}
    if(-not $Checkpoint.PSObject.Properties['ArchiveOf'] -and ([long]$Checkpoint.SegmentSequence -ne $sequence -or $Checkpoint.FirstPreviousHash -ne $previous)){throw 'Active stream is not linked to its segment index.'}
    return $index
}

function Move-SentinelLogSegment {
    param([string]$Path,$Before)
    $index=Read-SentinelSegmentIndex $Path $Before
    if(-not $index){$index=[pscustomobject]@{Schema=1;Stream=[IO.Path]::GetFileName($Path);RetiredSequence=0L;RetiredHash=[string]$Before.FirstPreviousHash;NextSequence=1L;Segments=@()}}
    $sequence=[long]$index.NextSequence
    if($sequence -gt 999999){throw 'Segment sequence exhausted.'}
    $name=[IO.Path]::GetFileNameWithoutExtension($Path)+'.s'+$sequence.ToString('D6')+'.jsonl'
    $next=$index | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $next.Segments=@($index.Segments)+@([pscustomobject]@{Sequence=$sequence;Name=$name;SHA256=(Get-FileHash -LiteralPath $Path).Hash;Length=[long]$Before.ByteLength;LineCount=[long]$Before.LineCount;FirstPreviousHash=[string]$Before.FirstPreviousHash;LastHash=[string]$Before.LastHash;ClosedAt=(Get-SentinelLogUtcNow).ToString('o')})
    $next.NextSequence=$sequence+1
    $after=[ordered]@{Schema=2;LogPath=$Path;LineCount=0L;ByteLength=0L;FirstPreviousHash=[string]$Before.LastHash;LastHash=[string]$Before.LastHash;LastUpdated=[datetimeoffset]::Now.ToString('o');SegmentSequence=$sequence}
    $plan=[ordered]@{Schema=1;Stream=[IO.Path]::GetFileName($Path);Segment=$name;Before=$Before;After=$after;IndexBefore=$index;IndexAfter=$next}
    Write-SentinelAtomicJson ((Get-SentinelChainPath $Path)+'.rotate.pending') $plan
    Repair-SentinelLogRotation $Path
}

function Repair-SentinelLogRotation {
    param([string]$Path)
    $statePath=Get-SentinelChainPath $Path;$pending=$statePath+'.rotate.pending'
    if(-not (Test-Path -LiteralPath $pending)){return}
    $plan=Get-Content -LiteralPath $pending -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $sequence=[long]$plan.After.SegmentSequence
    $expected=[IO.Path]::GetFileNameWithoutExtension($Path)+'.s'+$sequence.ToString('D6')+'.jsonl'
    if($plan.Schema -ne 1 -or $plan.Stream -cne [IO.Path]::GetFileName($Path) -or $sequence -le 0 -or $sequence -gt 999999 -or $plan.Segment -cne $expected -or $plan.After.ByteLength -ne 0 -or $plan.After.LineCount -ne 0 -or $plan.After.LastHash -ne $plan.Before.LastHash -or $plan.After.FirstPreviousHash -ne $plan.Before.LastHash){throw 'Invalid rotation transaction.'}
    $archive=Join-Path (Split-Path -Parent $Path) $expected;Assert-SentinelLogPath $archive;Assert-SentinelLogPath $Path
    $entry=@($plan.IndexAfter.Segments | Where-Object Name -eq $expected)
    if($entry.Count -ne 1 -or $entry[0].SHA256 -notmatch '^[A-Fa-f0-9]{64}$'){throw 'Rotation segment not bound to index.'}
    Assert-SentinelIndexTransaction $Path $plan.IndexBefore $plan.IndexAfter
    $expectedIndex=$plan.IndexBefore | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $expectedIndex.Segments=@($expectedIndex.Segments)+@($entry[0]);$expectedIndex.NextSequence=$sequence+1
    if(-not (Test-SentinelSameJson $expectedIndex $plan.IndexAfter) -or $plan.IndexBefore.NextSequence -ne $sequence -or $plan.Before.Schema -ne 2 -or $plan.After.Schema -ne 2 -or $plan.Before.ByteLength -ne $entry[0].Length -or $plan.Before.LineCount -ne $entry[0].LineCount -or $plan.Before.FirstPreviousHash -ne $entry[0].FirstPreviousHash -or $plan.Before.LastHash -ne $entry[0].LastHash){throw 'Rotation changed unrelated metadata.'}
    if(-not (Test-Path -LiteralPath $archive)){
        if(-not (Test-Path -LiteralPath $Path) -or (Get-FileHash -LiteralPath $Path).Hash -ne $entry[0].SHA256){throw 'Rotation source disappeared or changed.'}
        [IO.File]::Move($Path,$archive)
    }
    if((Get-FileHash -LiteralPath $archive).Hash -ne $entry[0].SHA256 -or (Get-Item -LiteralPath $archive).Length -ne $plan.Before.ByteLength){throw 'Rotation archive changed.'}
    if(Test-Path -LiteralPath $Path){if((Get-Item -LiteralPath $Path).Length -ne 0){throw 'Rotation destination contains unexpected bytes.'}}else{[IO.File]::WriteAllBytes($Path,[byte[]]@())}
    $archiveState=ConvertTo-SentinelOrderedMap $plan.Before;$archiveState['LogPath']=$archive;$archiveState['ArchiveOf']=$plan.Stream
    Write-SentinelAtomicJson (Get-SentinelChainPath $archive) $archiveState
    Write-SentinelAtomicJson $statePath $plan.After
    Write-SentinelAtomicJson ($statePath+'.segments.json') $plan.IndexAfter
    [void](Read-SentinelSegmentIndex $Path $plan.After)
    Remove-Item -LiteralPath $pending -Force -ErrorAction Stop
}

function Repair-SentinelSegmentRetirement {
    param([string]$Path)
    $statePath=Get-SentinelChainPath $Path;$pending=$statePath+'.retire.pending'
    if(-not (Test-Path -LiteralPath $pending)){return}
    $plan=Get-Content -LiteralPath $pending -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if($plan.Schema -ne 1 -or $plan.Stream -cne [IO.Path]::GetFileName($Path)){throw 'Invalid retirement transaction.'}
    Assert-SentinelIndexTransaction $Path $plan.IndexBefore $plan.IndexAfter
    $removed=@($plan.Removed);$original=@($plan.IndexBefore.Segments)
    if(-not $removed.Count -or $removed.Count -gt $original.Count){throw 'Retirement must remove an existing prefix.'}
    for($i=0;$i -lt $removed.Count;$i++){if(-not (Test-SentinelSameJson $removed[$i] $original[$i])){throw 'Retirement entries differ from indexed prefix.'}}
    $expectedIndex=$plan.IndexBefore | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    $expectedIndex.Segments=@($original | Select-Object -Skip $removed.Count);$expectedIndex.RetiredSequence=$removed[-1].Sequence;$expectedIndex.RetiredHash=$removed[-1].LastHash
    if(-not (Test-SentinelSameJson $expectedIndex $plan.IndexAfter)){throw 'Retirement changed unrelated metadata.'}
    foreach($entry in @($plan.Removed)){
        $expected=[IO.Path]::GetFileNameWithoutExtension($Path)+'.s'+([long]$entry.Sequence).ToString('D6')+'.jsonl'
        if($entry.Name -cne $expected -or $entry.SHA256 -notmatch '^[a-fA-F0-9]{64}$' -or $entry.Sequence -gt $plan.IndexAfter.RetiredSequence){throw 'Unsafe retirement entry.'}
        $archive=Join-Path (Split-Path -Parent $Path) $expected;Assert-SentinelLogPath $archive
        if(Test-Path -LiteralPath $archive){if((Get-FileHash -LiteralPath $archive).Hash -ne $entry.SHA256){throw 'Refusing to retire modified evidence.'}}
    }
    # Commit the retained prefix anchor before deleting its immutable files.
    Write-SentinelAtomicJson ($statePath+'.segments.json') $plan.IndexAfter
    foreach($entry in @($plan.Removed)){
        $archive=Join-Path (Split-Path -Parent $Path) $entry.Name
        if(Test-Path -LiteralPath $archive){Remove-Item -LiteralPath $archive -Force -ErrorAction Stop}
        $archiveState=Get-SentinelChainPath $archive
        if(Test-Path -LiteralPath $archiveState){Remove-Item -LiteralPath $archiveState -Force -ErrorAction Stop}
    }
    Remove-Item -LiteralPath $pending -Force -ErrorAction Stop
}

function Invoke-SentinelSegmentRetention {
    param([string]$Path,[datetime]$Cutoff)
    $budget=Enter-SentinelLogLock (Join-Path (Split-Path -Parent $Path) '__capacity');$mutex=$null
    try{
        $mutex=Enter-SentinelLogLock $Path;$before=Get-SentinelLogCheckpoint $Path;$index=Read-SentinelSegmentIndex $Path $before
        if(-not $index){return}
        $removed=@();$kept=@();$prefix=$true
        foreach($entry in @($index.Segments)){
            if($prefix -and ([datetimeoffset]$entry.ClosedAt).LocalDateTime -lt $Cutoff){$removed+=@($entry)}else{$prefix=$false;$kept+=@($entry)}
        }
        if(-not $removed.Count){return}
        $after=$index | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $after.Segments=$kept;$after.RetiredSequence=[long]$removed[-1].Sequence;$after.RetiredHash=[string]$removed[-1].LastHash
        Write-SentinelAtomicJson ((Get-SentinelChainPath $Path)+'.retire.pending') ([ordered]@{Schema=1;Stream=$index.Stream;IndexBefore=$index;IndexAfter=$after;Removed=$removed})
        Repair-SentinelSegmentRetirement $Path
        [void](Read-SentinelSegmentIndex $Path $before)
    }finally{if($mutex){$mutex.ReleaseMutex();$mutex.Dispose()};$budget.ReleaseMutex();$budget.Dispose()}
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
            $checkpoint=Get-SentinelLogCheckpoint $path
            if(-not $checkpoint.PSObject.Properties['ArchiveOf']){[void](Read-SentinelSegmentIndex $path $checkpoint -ValidateDigests)}
            $checks += [pscustomobject]@{Log=$name;Healthy=$true;Detail='Tail/length checkpoint OK'}
        } catch { $checks += [pscustomobject]@{Log=$name;Healthy=$false;Detail=$_.Exception.Message} }
        finally { if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() } }
    }
    return $checks
}
