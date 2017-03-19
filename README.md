# PoshC2
PoshC2 is a proxy aware C2 framework written completely in PowerShell to aid penetration testers with red teaming, post-exploitation and lateral movement. The tools and modules were developed off the back of our successful PowerShell sessions and payload types for the Metasploit Framework. PowerShell was chosen as the base language as it provides all of the functionality and rich features required without needing to introduce multiple languages to the framework. 

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

Wiki:
================
For more info see the GitHub Wiki
# Welcome to the PoshC2 wiki page
