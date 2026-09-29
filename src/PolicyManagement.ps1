function Merge-SentinelPolicy {
    param($Current,$Patch,[string]$Prefix='')
    $map=[ordered]@{}
    foreach($property in $Current.PSObject.Properties) { $map[$property.Name]=$property.Value }
    foreach($property in $Patch.PSObject.Properties) {
        $name=$property.Name;$full=$Prefix+$name
        if(-not $map.Contains($name) -or $full -eq 'Version') { throw ('Unsupported policy field: '+$full) }
        if($Current.$name -is [pscustomobject]) {
            if($property.Value -isnot [pscustomobject]) { throw ('Policy object expected: '+$full) }
            $map[$name]=Merge-SentinelPolicy $Current.$name $property.Value ($full+'.')
        } else { $map[$name]=$property.Value }
    }
    return [pscustomobject]$map
}

function Assert-SentinelBaseline {
    param([string]$Root)
    $baseline=Read-SentinelBaseline $Root
    foreach($name in Get-SentinelCriticalFileNames) {
        $entries=@($baseline.Files | Where-Object { $_.Name -eq $name })
        if($entries.Count -ne 1 -or $entries[0].SHA256 -ine (Get-FileHash -LiteralPath (Join-Path $Root $name) -Algorithm SHA256 -ErrorAction Stop).Hash) { throw ('Integrity baseline mismatch: '+$name+'. Review the change before updating policy.') }
    }
    return $baseline
}

function Set-SentinelConfigTransaction {
    param([string]$Root,$Candidate,[string]$Reason)
    if(-not $Reason.Trim()) { throw 'Policy change reason required.' }
    Assert-SentinelConfig $Candidate
    $baseline=Assert-SentinelBaseline $Root
    $configPath=Join-Path $Root 'Config.json';$baselinePath=Join-Path $Root 'state\integrity-baseline.json'
    $oldConfig=[IO.File]::ReadAllBytes($configPath);$oldBaseline=[IO.File]::ReadAllBytes($baselinePath)
    $beforeHash=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    $backupPath=Join-Path $Root ('backups\policy-'+(Get-Date -Format 'yyyyMMddHHmmssfff')+'-'+[guid]::NewGuid().ToString('N')+'.json')
    Write-SentinelAtomicJson $backupPath ([ordered]@{Schema=1;Reason=$Reason;ConfigBase64=[Convert]::ToBase64String($oldConfig);BaselineBase64=[Convert]::ToBase64String($oldBaseline);CreatedAt=(Get-Date).ToString('o')})
    try {
        Write-SentinelAtomicJson $configPath $Candidate
        $entry=@($baseline.Files | Where-Object { $_.Name -eq 'Config.json' })[0]
        $entry.SHA256=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
        $item=Get-Item -LiteralPath $configPath
        $entry.Length=$item.Length;$entry.LastWriteTimeUtc=$item.LastWriteTimeUtc.ToString('o')
        Write-SentinelAtomicJson $baselinePath $baseline
        $audit=[ordered]@{Type='PolicyChanged';Severity='MEDIUM';Reason=$Reason;Operator=[Security.Principal.WindowsIdentity]::GetCurrent().Name;BeforeSHA256=$beforeHash;AfterSHA256=$entry.SHA256;Backup=$backupPath}
        if(-not (Write-SentinelJsonLine (Join-Path $Root 'logs\administration.jsonl') $audit)) { throw 'Policy audit could not be persisted.' }
        return [pscustomobject]@{Changed=$true;Backup=$backupPath;RestartRequired=$true}
    } catch {
        [IO.File]::WriteAllBytes($configPath,$oldConfig);[IO.File]::WriteAllBytes($baselinePath,$oldBaseline)
        throw
    }
}

function Get-SentinelHardeningPlan {
    param($Snapshot,[ValidateSet('AuditFirst','RecommendedBlock')][string]$Profile)
    $pref=$Snapshot.Preference
    $audit=$Profile -eq 'AuditFirst'
    $plan=@()
    $desired=[ordered]@{MAPSReporting='Advanced';SubmitSamplesConsent='SendSafeSamples';DisableBlockAtFirstSeen=$false;PUAProtection='Enabled';EnableNetworkProtection=$(if($audit){'AuditMode'}else{'Enabled'});CheckForSignaturesBeforeRunningScan=$true;CloudBlockLevel='High';DisableBehaviorMonitoring=$false;DisableIOAVProtection=$false;DisableRealtimeMonitoring=$false;EnableControlledFolderAccess=$(if($audit){'AuditMode'}else{'Enabled'})}
    foreach($name in $desired.Keys) {
        $value=$desired[$name]
        if($name -eq 'EnableNetworkProtection' -and $Snapshot.NetworkProtectionSupported -ne $true) {
            $plan += [pscustomobject]@{Kind='Unavailable';Setting=$name;Current=$pref.$name;Desired=$null}
            continue
        }
        # Preserve existing Block/Warn profiles and higher cloud levels.
        if($name -in @('PUAProtection','EnableNetworkProtection','EnableControlledFolderAccess') -and [string]$pref.$name -in @('Enabled','1')) { $value=$pref.$name }
        if($audit -and $name -eq 'EnableControlledFolderAccess' -and [string]$pref.$name -in @('BlockDiskModificationOnly','3')) { $value=$pref.$name }
        if($name -eq 'CloudBlockLevel' -and [string]$pref.$name -in @('HighPlus','ZeroTolerance','4','6')) { $value=$pref.$name }
        if($name -eq 'SubmitSamplesConsent' -and [string]$pref.$name -in @('SendAllSamples','3')) { $value=$pref.$name }
        $plan += [pscustomobject]@{Kind='Preference';Setting=$name;Current=$pref.$name;Desired=$value}
    }
    $current=@{}
    foreach($rule in @($pref.AttackSurfaceReductionRules)) { $current[[string]$rule.Id.ToLowerInvariant()]=[int]$rule.Action }
    foreach($id in (Get-SentinelManagedAsrRules).Keys) {
        $action=if($audit){2}else{1}
        if($current.ContainsKey($id) -and ($current[$id] -eq 1 -or ($audit -and $current[$id] -eq 6))) { $action=$current[$id] }
        $plan += [pscustomobject]@{Kind='ASR';Setting=$id;Current=$current[$id];Desired=$action}
    }
    return $plan
}

function ConvertTo-SentinelPreferenceValue {
    param([string]$Name,$Value)
    $maps=@{
        MAPSReporting=@{'0'='Disabled';'1'='Basic';'2'='Advanced'}
        SubmitSamplesConsent=@{'0'='AlwaysPrompt';'1'='SendSafeSamples';'2'='NeverSend';'3'='SendAllSamples'}
        PUAProtection=@{'0'='Disabled';'1'='Enabled';'2'='AuditMode'}
        EnableNetworkProtection=@{'0'='Disabled';'1'='Enabled';'2'='AuditMode'}
        EnableControlledFolderAccess=@{'0'='Disabled';'1'='Enabled';'2'='AuditMode';'3'='BlockDiskModificationOnly';'4'='AuditDiskModificationOnly'}
        CloudBlockLevel=@{'0'='Default';'1'='Moderate';'2'='High';'4'='HighPlus';'6'='ZeroTolerance'}
    }
    if($maps.ContainsKey($Name) -and $maps[$Name].ContainsKey([string]$Value)) { return $maps[$Name][[string]$Value] }
    return [string]$Value
}
