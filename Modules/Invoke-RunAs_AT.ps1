function Invoke-Runas {
<#
.SYNOPSIS
    Overview:
    
    if running as Standard user - Args MAX Length is 1024 characters
    using Advapi32::CreateProcessWithLogonW

    if running as SYSTEM user - Args MAX Length is 32k characters
    Advapi32::LogonUser, Advapi32::DuplicateTokenEx, CreateProcessAsUser 
        
    Parameters:

     -User              Specifiy username.
  
     -Password          Specify password.
     
     -Domain            Specify domain. Defaults to localhost if not specified.
     
     -Command           Full path of the module to be executed.

     -Args              Args to be executed, must start with a space, e.g. " /c calc.exe" Size can vary depending on the user

.EXAMPLE
    Invoke-Runas -User Ted -Password Password1 -Domain MYDOMAIN -Command C:\Temp\Runme.exe                   

.EXAMPLE
    Invoke-Runas -User Ted -Password Password1 -Domain MYDOMAIN -Command C:\Windows\system32\WindowsPowershell\v1.0\powershell.exe -Args " -exec bypass -e Tjsksdsadsa"    

.DESCRIPTION
    Author: Ben Turner (@benpturner)
    License: BSD 3-Clause
#>

    param (
        [Parameter(Mandatory = $True)]
        [string]$User,
        [Parameter(Mandatory = $True)]
        [string]$Password,
        [Parameter(Mandatory = $False)]
        [string]$Domain=".",
        [Parameter(Mandatory = $True)]
        [string]$Command,
        [Parameter(Mandatory = $False)]
        [string]$Args
    )  

    Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Security.Principal;

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public Int32 Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }
        
    public enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public class AdjPriv
    {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }
  
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
        {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = new IntPtr(processHandle);
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            if(disable)
            {
                tp.Attr = SE_PRIVILEGE_DISABLED;
            }
            else
            {
                tp.Attr = SE_PRIVILEGE_ENABLED;
            }
            retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
    }

    public static class Advapi32
    {

        [DllImport("advapi32.dll", CharSet=CharSet.Auto)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            int ImpersonationLevel,
            int TokenType,
            ref IntPtr phNewToken);
            
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LogonUser(
            string pszUsername, 
            string pszDomain, 
            string pszPassword,
            int dwLogonType, 
            int dwLogonProvider, 
            ref IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken, 
            string lpApplicationName,
            string lpCommandLine, 
            ref SECURITY_ATTRIBUTES lpProcessAttributes, 
            ref SECURITY_ATTRIBUTES lpThreadAttributes, 
            bool bInheritHandle, 
            Int32 dwCreationFlags, 
            IntPtr lpEnvrionment,
            string lpCurrentDirectory, 
            ref STARTUPINFO lpStartupInfo,
            ref PROCESS_INFORMATION lpProcessInformation);


        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool CreateProcessWithLogonW(
            String userName,
            String domain,
            String password,
            int logonFlags,
            String applicationName,
            String commandLine,
            int creationFlags,
            int environment,
            String currentDirectory,
            ref  STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);
    }
    
    public static class Kernel32
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();
    }
"@


    if (($env:username -eq "$($env:computername)$")) {
        echo "`n[>] User is `"NT Authority\SYSTEM`" so running LogonUser -> DuplicateTokenEx -> CreateProcessAsUser"
        # EnablePrivs from http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        $processHandle = (Get-Process -id $pid).Handle
        [AdjPriv]::EnablePrivilege($processHandle, "SeAssignPrimaryTokenPrivilege", $Disable) 
    
        $LogonTokenHandle = [IntPtr]::Zero

        echo "`n[>] Calling Advapi32::LogonUser"
        $CallResult1 = [Advapi32]::LogonUser($User, $Domain, $Password, 2, 0, [ref] $LogonTokenHandle)

        if (!$CallResult1) {
            echo "`n[!] Mmm, something went wrong! GetLastError returned:"
            echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)`n"
        } else {
            echo "`n[+] Success, LogonTokenHandle: "
            echo $LogonTokenHandle
        }

        $SecImpersonation = New-Object SECURITY_IMPERSONATION_LEVEL
        $SECURITY_ATTRIBUTES = New-Object SECURITY_ATTRIBUTES
        $PrivLogonTokenHandle = [IntPtr]::Zero

        echo "`n[>] Calling Advapi32::DuplicateTokenEx"
        $CallResult2 = [Advapi32]::DuplicateTokenEx($LogonTokenHandle, 0x2000000, [ref] $SECURITY_ATTRIBUTES, 2, 1, [ref] $PrivLogonTokenHandle)


        if (!$CallResult2) {
            echo "`n[!] Mmm, something went wrong! GetLastError returned:"
            echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)`n"
        } else {
            echo "`n[+] Success, PrivLogonTokenHandle:"
            echo $PrivLogonTokenHandle
        }

        # StartupInfo Struct
        $StartupInfo = New-Object STARTUPINFO
        $StartupInfo.dwFlags = 0x00000001
        $StartupInfo.wShowWindow = 0x0001
        $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)
    
        # ProcessInfo Struct
        $ProcessInfo = New-Object PROCESS_INFORMATION
    
        $SecAttributes1 = New-Object SECURITY_ATTRIBUTES
        $SecAttributes2 = New-Object SECURITY_ATTRIBUTES
        $lpEnvrionment = [IntPtr]::Zero
        $CurrentDirectory = $Env:SystemRoot

        echo "`n[>] Calling Advapi32::CreateProcessAsUser"
        $CallResult3 = [Advapi32]::CreateProcessAsUser($PrivLogonTokenHandle, $command, $args,
            [ref] $SecAttributes1, [ref] $SecAttributes2, $false, 0, $lpEnvrionment, $CurrentDirectory, [ref]$StartupInfo, [ref]$ProcessInfo)
    
        if (!$CallResult3) {
            echo "`n[!] Mmm, something went wrong! GetLastError returned:"
            echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)`n"
        } else {
            echo "`n[+] Success, process details:"
            Get-Process -Id $ProcessInfo.dwProcessId
            echo "`n[+] Please note, this process will have a primary token assigned but the user displayed will be SYSTEM"
            echo "`n[+] Run Invoke-TokenManipulation to see the Token loaded"
        }
    } else {
        cd $Env:SystemRoot
        echo "`n[>] User is `"$env:username`" so running CreateProcessWithLogonW"
        # Inspired from: https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-Runas.ps1
    	# StartupInfo Struct
	    $StartupInfo = New-Object STARTUPINFO
	    $StartupInfo.dwFlags = 0x00000001
	    $StartupInfo.wShowWindow = 0x0001
	    $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)
	
	    # ProcessInfo Struct
	    $ProcessInfo = New-Object PROCESS_INFORMATION
	
	    # CreateProcessWithLogonW --> lpCurrentDirectory
	    $GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
	
	    echo "`n[>] Calling Advapi32::CreateProcessWithLogonW"
	    $CallResult = [Advapi32]::CreateProcessWithLogonW(
		    $User, $Domain, $Password, 0x1, $Command,
		    $Args, 0x04000000, $null, $GetCurrentPath,
		    [ref]$StartupInfo, [ref]$ProcessInfo)
	
	    if (!$CallResult) {
		    echo "`n[!] Mmm, something went wrong! GetLastError returned:"
		    echo "==> $((New-Object System.ComponentModel.Win32Exception([int][Kernel32]::GetLastError())).Message)`n"
	    } else {
		    echo "`n[+] Success, process details:"
		    Get-Process -Id $ProcessInfo.dwProcessId
	    }
    } 
}