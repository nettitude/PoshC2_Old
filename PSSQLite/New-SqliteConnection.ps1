function New-SQLiteConnection
{
    <#
    .SYNOPSIS
        Creates a SQLiteConnection to a SQLite data source
    
    .DESCRIPTION
        Creates a SQLiteConnection to a SQLite data source
    
    .PARAMETER DataSource
       SQLite Data Source to connect to.
    
    .PARAMETER Password
        Specifies A Secure String password to use in the SQLite connection string.
                
        SECURITY NOTE: If you use the -Debug switch, the connectionstring including plain text password will be sent to the debug stream.
    
    .PARAMETER ReadOnly
        If specified, open SQLite data source as read only

    .PARAMETER Open
        We open the connection by default.  You can use this parameter to create a connection without opening it.

    .OUTPUTS
        System.Data.SQLite.SQLiteConnection

    .EXAMPLE
        $Connection = New-SQLiteConnection -DataSource C:\NAMES.SQLite
        Invoke-SQLiteQuery -SQLiteConnection $Connection -query $Query

        # Connect to C:\NAMES.SQLite, invoke a query against it

    .EXAMPLE
        $Connection = New-SQLiteConnection -DataSource :MEMORY: 
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "CREATE TABLE OrdersToNames (OrderID INT PRIMARY KEY, fullname TEXT);"
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "INSERT INTO OrdersToNames (OrderID, fullname) VALUES (1,'Cookie Monster');"
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "PRAGMA STATS"

        # Create a connection to a SQLite data source in memory
        # Create a table in the memory based datasource, verify it exists with PRAGMA STATS

        $Connection.Close()
        $Connection.Open()
        Invoke-SqliteQuery -SQLiteConnection $Connection -Query "PRAGMA STATS"

        #Close the connection, open it back up, verify that the ephemeral data no longer exists

    .LINK
        https://github.com/RamblingCookieMonster/Invoke-SQLiteQuery

    .LINK
        Invoke-SQLiteQuery

    .FUNCTIONALITY
        SQL

    #>
    [cmdletbinding()]
    [OutputType([System.Data.SQLite.SQLiteConnection])]
    param(
        [Parameter( Position=0,
                    Mandatory=$true,
                    ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true,
                    ValueFromRemainingArguments=$false,
                    HelpMessage='SQL Server Instance required...' )]
        [Alias( 'Instance', 'Instances', 'ServerInstance', 'Server', 'Servers','cn','Path','File','FullName','Database' )]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $DataSource,
                
        [Parameter( Position=2,
                    Mandatory=$false,
                    ValueFromPipelineByPropertyName=$true,
                    ValueFromRemainingArguments=$false )]
        [System.Security.SecureString]
        $Password,

        [Parameter( Position=3,
                    Mandatory=$false,
                    ValueFromPipelineByPropertyName=$true,
                    ValueFromRemainingArguments=$false )]
        [Switch]
        $ReadOnly,

        [Parameter( Position=4,
                    Mandatory=$false,
                    ValueFromPipelineByPropertyName=$true,
                    ValueFromRemainingArguments=$false )]
        [bool]
        $Open = $True
    )
    Process
    {
        foreach($DataSRC in $DataSource)
        {
            Write-Verbose "Querying Data Source '$DataSRC'"
            [string]$ConnectionString = "Data Source=$DataSRC;"
            if ($Password) 
            {
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
                $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                $ConnectionString += "Password=$PlainPassword;"
            }
            if($ReadOnly)
            {
                $ConnectionString += "Read Only=True;"
            }
        
            $conn = New-Object System.Data.SQLite.SQLiteConnection -ArgumentList $ConnectionString
            $conn.ParseViaFramework = $true #Allow UNC paths, thanks to Ray Alex!
            Write-Debug "ConnectionString $ConnectionString"

            if($Open)
            {
                Try
                {
                    $conn.Open() 
                }
                Catch
                {
                    Write-Error $_
                    continue
                }
            }

            write-Verbose "Created SQLiteConnection:`n$($Conn | Out-String)"

            $Conn
        }
    }
}