#handle PS2
    if(-not $PSScriptRoot)
    {
        $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
    }

#Pick and import assemblies:
    if([IntPtr]::size -eq 8) #64
    {
        $SQLiteAssembly = Join-path $PSScriptRoot "x64\System.Data.SQLite.dll"
    }
    elseif([IntPtr]::size -eq 4) #32
    {
        $SQLiteAssembly = Join-path $PSScriptRoot "x86\System.Data.SQLite.dll"
    }
    else
    {
        Throw "Something is odd with bitness..."
    }

    if( -not ($Library = Add-Type -path $SQLiteAssembly -PassThru -ErrorAction stop) )
    {
        Throw "This module requires the ADO.NET driver for SQLite:`n`thttp://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki"
    }

#Get public and private function definition files.
    $Public  = Get-ChildItem $PSScriptRoot\*.ps1 -ErrorAction SilentlyContinue
    #$Private = Get-ChildItem $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue 

#Dot source the files
    Foreach($import in @($Public))
    {
        Try
        {
            #PS2 compatibility
            if($import.fullname)
            {
                . $import.fullname
            }
        }
        Catch
        {
            Write-Error "Failed to import function $($import.fullname): $_"
        }
    }
    
#Create some aliases, export public functions
    Export-ModuleMember -Function $($Public | Select -ExpandProperty BaseName)