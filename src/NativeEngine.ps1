# This small C# shim is only the ABI bridge; parsing/state algorithms live in Rust.
$script:SentinelNativeCodeDirectory=$PSScriptRoot
function Initialize-SentinelNative {
    if($script:SentinelNativeLoaded){return}
    if(-not [Environment]::Is64BitProcess){throw 'The native engine requires 64-bit Windows PowerShell.'}
    $directory=$script:SentinelNativeCodeDirectory
    if(-not (Test-Path -LiteralPath (Join-Path $directory 'sentinel_engine.dll'))){$directory=Join-Path (Split-Path -Parent $directory) 'native\bin'}
    $binary=Join-Path $directory 'sentinel_engine.dll';$metadata=Join-Path $directory 'sentinel-engine.json'
    Assert-SentinelLogPath $binary;Assert-SentinelLogPath $metadata
    $metaLock=[IO.File]::Open($metadata,'Open','Read','Read');$dllLock=$null
    try{
        $reader=[IO.StreamReader]::new($metaLock,[Text.Encoding]::UTF8,$true,4096,$true)
        try{$info=$reader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop}finally{$reader.Dispose()}
        if($info.Schema -ne 1 -or $info.ABI -ne 1 -or $info.Architecture -ne 'x64' -or $info.DLL -cne 'sentinel_engine.dll' -or $info.SHA256 -notmatch '^[A-F0-9]{64}$'){throw 'Invalid native engine metadata.'}
        $dllLock=[IO.File]::Open($binary,'Open','Read','Read');$hash=[Security.Cryptography.SHA256]::Create()
        try{$actual=([BitConverter]::ToString($hash.ComputeHash($dllLock))).Replace('-','')}finally{$hash.Dispose()}
        if($actual -cne $info.SHA256){throw 'Native engine differs from its pinned build metadata.'}
        $baselinePath=Join-Path $directory 'state\integrity-baseline.json'
        if(Test-Path -LiteralPath $baselinePath){
            $baseline=Read-SentinelBaseline $directory
            $entry=@($baseline.Files | Where-Object Name -eq 'sentinel_engine.dll')
            if($entry.Count -ne 1 -or $entry[0].SHA256 -cne $actual){throw 'Native engine differs from its protected integrity baseline.'}
        }
        if(-not ('SentinelNativeHost' -as [type])){
            Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class SentinelNativeHost {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadLibraryEx(string path, IntPtr reserved, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr GetProcAddress(IntPtr module, string name);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate IntPtr Call(IntPtr input, UIntPtr count, out UIntPtr length);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void Free(IntPtr result, UIntPtr length);
    static Call call; static Free free; static string loadedHash;
    public static void Load(string path, string hash) {
        if(call != null) { if(loadedHash != hash) throw new InvalidOperationException("Native code changed; restart this PowerShell process."); return; }
        IntPtr module=LoadLibraryEx(path,IntPtr.Zero,0x100|0x800);
        if(module==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr a=GetProcAddress(module,"sentinel_call"), b=GetProcAddress(module,"sentinel_free");
        if(a==IntPtr.Zero || b==IntPtr.Zero) throw new InvalidOperationException("Native ABI missing.");
        call=(Call)Marshal.GetDelegateForFunctionPointer(a,typeof(Call));free=(Free)Marshal.GetDelegateForFunctionPointer(b,typeof(Free));loadedHash=hash;
    }
    public static string Invoke(string json) {
        byte[] bytes=new UTF8Encoding(false,true).GetBytes(json);
        if(bytes.Length>16*1024*1024) throw new InvalidOperationException("Native request too large.");
        IntPtr input=Marshal.AllocHGlobal(bytes.Length), output=IntPtr.Zero; UIntPtr length=UIntPtr.Zero;
        try { Marshal.Copy(bytes,0,input,bytes.Length);output=call(input,(UIntPtr)bytes.Length,out length);
            if(output==IntPtr.Zero || length.ToUInt64()>16*1024*1024) throw new InvalidOperationException("Invalid native reply size.");
            byte[] result=new byte[(int)length.ToUInt64()];Marshal.Copy(output,result,0,result.Length);return new UTF8Encoding(false,true).GetString(result);
        } finally { if(output!=IntPtr.Zero) free(output,length);Marshal.FreeHGlobal(input); }
    }
}
'@
        }
        [SentinelNativeHost]::Load([IO.Path]::GetFullPath($binary),$actual)
        $script:SentinelNativeLoaded=$true
    }finally{if($dllLock){$dllLock.Dispose()};$metaLock.Dispose()}
}
function Invoke-SentinelNative {
    param([hashtable]$Request)
    Initialize-SentinelNative
    $response=[SentinelNativeHost]::Invoke(($Request | ConvertTo-Json -Depth 32 -Compress)) | ConvertFrom-Json -ErrorAction Stop
    if(-not $response.Ok){throw ('Native engine: '+$response.Error)}
    return $response.Data
}

function Get-SentinelNativeLogScan {
    param([string]$Path)
    $request=@{op='scan';path=[IO.Path]::GetFullPath($Path)}
    if($script:SentinelBenchmarkCapture){$request.capture=$script:SentinelBenchmarkCapture}
    $scope=if($script:SentinelBenchmarkCapture){Get-SentinelStringHash ($script:SentinelBenchmarkCapture | ConvertTo-Json -Depth 6 -Compress)}else{'VerificationOnly'}
    if($script:SentinelNativeScanCache -and $script:SentinelNativeScanCache.ContainsKey($request.path)){
        $cached=$script:SentinelNativeScanCache[$request.path]
        if($cached.CaptureKey -ceq $scope){
            $actual=Invoke-SentinelNative @{op='hash';path=$request.path}
            if($actual.SHA256 -ceq $cached.SHA256 -and $actual.ByteLength -eq $cached.ByteLength){return $cached}
        }
    }
    $result=Invoke-SentinelNative $request
    # Unsupported numeric/depth representations are checked with the original
    # PS 5.1 canonicalizer, in this bounded batch, never accepted by guessing.
    foreach($entry in @($result.CompatibilityRows)){
        $obj=$entry.Line | ConvertFrom-Json -ErrorAction Stop
        $payload=[ordered]@{};foreach($property in $obj.PSObject.Properties){if($property.Name -notin @('_ChainAlg','_ChainPrev','_ChainHash')){$payload[$property.Name]=$property.Value}}
        $expected=Get-SentinelStringHash ([string]$obj._ChainPrev+"`n"+($payload | ConvertTo-Json -Depth 14 -Compress))
        if($expected -ine [string]$obj._ChainHash){throw ('Hash mismatch at compatibility line '+$entry.LineNumber)}
    }
    $result | Add-Member NoteProperty CaptureKey $scope
    $result | Add-Member NoteProperty PowerShellCompatibilityCount @($result.CompatibilityRows).Count
    $result.CompatibilityRows=@();$result.CanonicalValidationComplete=$true
    if(-not $script:SentinelNativeScanCache){$script:SentinelNativeScanCache=@{}}
    if($script:SentinelNativeScanCache.Count -ge 256){$script:SentinelNativeScanCache.Clear()}
    $script:SentinelNativeScanCache[[IO.Path]::GetFullPath($Path)]=$result
    return $result
}

function Get-SentinelVerifiedLogDigest {
    param([string]$Path)
    $full=[IO.Path]::GetFullPath($Path)
    $actual=Invoke-SentinelNative @{op='hash';path=$full}
    if($script:SentinelNativeScanCache -and $script:SentinelNativeScanCache.ContainsKey($full) -and $actual.SHA256 -cne $script:SentinelNativeScanCache[$full].SHA256){throw 'Verified copy changed before its manifest was written.'}
    return $actual.SHA256
}

function Read-SentinelBenchmarkRows {
    param([string]$Path)
    if(-not $script:SentinelBenchmarkCapture){return Read-SentinelLogRows $Path}
    foreach($file in @(Get-SentinelLogStreamPaths $Path)){
        $scan=Get-SentinelNativeLogScan $file
        foreach($row in @($scan.Rows)){$row}
    }
}
