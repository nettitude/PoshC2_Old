<#
.Synopsis
    Starts a new process locally with alternative credentials
.DESCRIPTION
	Allows a 'RunAs' locally with alternative credentials, WMI allows a this on remote systems, but does not allow locally
.EXAMPLE
    PS C:\> Invoke-RunAs -Cmd 'winrm.cmd' -Args 'quickconfig -quiet -force' -Domain testdomain -Username 'administrator' -Password '$Pa55w0rd$'
    Start a new process locally with alternate creds

.EXAMPLE
    PS C:\> Invoke-RunAs -cmd 'powershell.exe' -args 'start-service -name WinRM' -Domain testdomain -Username 'administrator' -Password '$Pa55w0rd$'
    Start a new process locally with alternate creds
#>
Function Invoke-RunAs
{

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$True)]
   [string]$Cmd,
	
   [Parameter(Mandatory=$False)]
   [string]$Args,
      [Parameter(Mandatory=$True)]
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
$procstartinfo.FileName = $Cmd
$procstartinfo.UserName = $creds.UserName
$procstartinfo.Password = $creds.Password
$procstartinfo.Domain = $Domain
$procstartinfo.Arguments = $Args
$procstartinfo.UseShellExecute = $false
$procstartinfo.RedirectStandardInput = $False
$procstartinfo.RedirectStandardOutput = $False
$procstartinfo.RedirectStandardError = $True
$procstartinfo.Verb = 'runAs'
$procstartinfo.CreateNoWindow = $true
$procstartinfo.WindowStyle = 'hidden'
$procstartinfo.LoadUserProfile = $false
$procstartinfo.WorkingDirectory = 'c:\'

$output = "Starting"
Try
{
$process = [System.Diagnostics.Process]::Start($procstartinfo)
$process.WaitForExit()
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




