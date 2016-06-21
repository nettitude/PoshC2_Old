function Invoke-SQLiteBulkCopy {
<#
.SYNOPSIS
    Use a SQLite transaction to quickly insert data

.DESCRIPTION
    Use a SQLite transaction to quickly insert data.  If we run into any errors, we roll back the transaction.
    
    The data source is not limited to SQL Server; any data source can be used, as long as the data can be loaded to a DataTable instance or read with a IDataReader instance.

.PARAMETER DataSource
    Path to one ore more SQLite data sources to query 

.PARAMETER Force
    If specified, skip the confirm prompt

.PARAMETER  NotifyAfter
	The number of rows to fire the notification event after transferring.  0 means don't notify.  Notifications hit the verbose stream (use -verbose to see them)

.PARAMETER QueryTimeout
    Specifies the number of seconds before the queries time out.

.PARAMETER SQLiteConnection
    An existing SQLiteConnection to use.  We do not close this connection upon completed query.

.PARAMETER ConflictClause
    The conflict clause to use in case a conflict occurs during insert. Valid values: Rollback, Abort, Fail, Ignore, Replace

    See https://www.sqlite.org/lang_conflict.html for more details

.EXAMPLE
    #
    #Create a table
        Invoke-SqliteQuery -DataSource "C:\Names.SQLite" -Query "CREATE TABLE NAMES (
            fullname VARCHAR(20) PRIMARY KEY,
            surname TEXT,
            givenname TEXT,
            BirthDate DATETIME)" 

    #Build up some fake data to bulk insert, convert it to a datatable
        $DataTable = 1..10000 | %{
            [pscustomobject]@{
                fullname = "Name $_"
                surname = "Name"
                givenname = "$_"
                BirthDate = (Get-Date).Adddays(-$_)
            }
        } | Out-DataTable

    #Copy the data in within a single transaction (SQLite is faster this way)
        Invoke-SQLiteBulkCopy -DataTable $DataTable -DataSource $Database -Table Names -NotifyAfter 1000 -ConflictClause Ignore -Verbose 
        
.INPUTS
    System.Data.DataTable

.OUTPUTS
    None
        Produces no output

.NOTES
    This function borrows from:
        Chad Miller's Write-Datatable
        jbs534's Invoke-SQLBulkCopy
        Mike Shepard's Invoke-BulkCopy from SQLPSX

.LINK
    https://github.com/RamblingCookieMonster/Invoke-SQLiteQuery

.LINK
    New-SQLiteConnection

.LINK
    Invoke-SQLiteBulkCopy

.LINK
    Out-DataTable

.FUNCTIONALITY
    SQL
#>
    [cmdletBinding( DefaultParameterSetName = 'Datasource',
                    SupportsShouldProcess = $true,
                    ConfirmImpact = 'High' )]
    param(
        [parameter( Position = 0,
                    Mandatory = $true,
                    ValueFromPipeline = $false,
                    ValueFromPipelineByPropertyName= $false)]
        [System.Data.DataTable]
        $DataTable,

        [Parameter( ParameterSetName='Datasource',
                    Position=1,
                    Mandatory=$true,
                    ValueFromRemainingArguments=$false,
                    HelpMessage='SQLite Data Source required...' )]
        [Alias('Path','File','FullName','Database')]
        [validatescript({
            #This should match memory, or the parent path should exist
            if ( $_ -match ":MEMORY:" -or (Test-Path $_) ) {
                $True
            }
            else {
                Throw "Invalid datasource '$_'.`nThis must match :MEMORY:, or must exist"
            }
        })]
        [string]
        $DataSource,

        [Parameter( ParameterSetName = 'Connection',
                    Position=1,
                    Mandatory=$true,
                    ValueFromPipeline=$false,
                    ValueFromPipelineByPropertyName=$true,
                    ValueFromRemainingArguments=$false )]
        [Alias( 'Connection', 'Conn' )]
        [System.Data.SQLite.SQLiteConnection]
        $SQLiteConnection,

        [parameter( Position=2,
                    Mandatory = $true)]
        [string]
        $Table,

        [Parameter( Position=3,
                     Mandatory=$false,
                     ValueFromPipeline=$false,
                     ValueFromPipelineByPropertyName=$false,
                     ValueFromRemainingArguments=$false)]
        [ValidateSet("Rollback","Abort","Fail","Ignore","Replace")]
        [string]
        $ConflictClause,

        [int]
        $NotifyAfter = 0,

        [switch]
        $Force,

        [Int32]
        $QueryTimeout = 600

    )

    Write-Verbose "Running Invoke-SQLiteBulkCopy with ParameterSet '$($PSCmdlet.ParameterSetName)'."

    Function CleanUp
    {
        [cmdletbinding()]
        param($conn, $com, $BoundParams)
        #Only dispose of the connection if we created it
        if($BoundParams.Keys -notcontains 'SQLiteConnection')
        {
            $conn.Close()
            $conn.Dispose()
            Write-Verbose "Closed connection"
        }
        $com.Dispose()
    }

    function Get-ParameterName
    {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
            [string[]]$InputObject,

            [Parameter(ValueFromPipelineByPropertyName = $true)]
            [string]$Regex = '(\W+)',

            [Parameter(ValueFromPipelineByPropertyName = $true)]
            [string]$Separator = '_'
        )

        Process{
            $InputObject | ForEach-Object {
                if($_ -match $Regex){
                    $Groups = @($_ -split $Regex | Where-Object {$_})
                    for($i = 0; $i -lt $Groups.Count; $i++){
                        if($Groups[$i] -match $Regex){
                            $Groups[$i] = ($Groups[$i].ToCharArray() | ForEach-Object {[string][int]$_}) -join $Separator
                        }
                    }
                    $Groups -join $Separator
                } else {
                    $_
                }
            }
        }
    }

    function New-SqliteBulkQuery {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
            [string]$Table,

            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
            [string[]]$Columns,

            [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
            [string[]]$Parameters,

            [Parameter(ValueFromPipelineByPropertyName = $true)]
            [string]$ConflictClause = ''
        )

        Begin{
            $EscapeSingleQuote = "'","''"
            $Delimeter = ", "
            $QueryTemplate = "INSERT{0} INTO {1} ({2}) VALUES ({3})"
        }

        Process{
            $fmtConflictClause = if($ConflictClause){" OR $ConflictClause"}
            $fmtTable = "'{0}'" -f ($Table -replace $EscapeSingleQuote)
            $fmtColumns = ($Columns | ForEach-Object { "'{0}'" -f ($_ -replace $EscapeSingleQuote) }) -join $Delimeter
            $fmtParameters = ($Parameters | ForEach-Object { "@$_"}) -join $Delimeter

            $QueryTemplate -f $fmtConflictClause, $fmtTable, $fmtColumns, $fmtParameters
        }
    }

    #Connections
        if($PSBoundParameters.Keys -notcontains "SQLiteConnection")
        {
            $ConnectionString = "Data Source={0}" -f $DataSource
            $SQLiteConnection = New-Object System.Data.SQLite.SQLiteConnection -ArgumentList $ConnectionString
            $SQLiteConnection.ParseViaFramework = $true #Allow UNC paths, thanks to Ray Alex!
        }

        Write-Debug "ConnectionString $($SQLiteConnection.ConnectionString)"
        Try
        {
            if($SQLiteConnection.State -notlike "Open")
            {
                $SQLiteConnection.Open()
            }
            $Command = $SQLiteConnection.CreateCommand()
            $CommandTimeout = $QueryTimeout
            $Transaction = $SQLiteConnection.BeginTransaction()
        }
        Catch
        {
            Throw $_
        }
    
    write-verbose "DATATABLE IS $($DataTable.gettype().fullname) with value $($Datatable | out-string)"
    $RowCount = $Datatable.Rows.Count
    Write-Verbose "Processing datatable with $RowCount rows"

    if ($Force -or $PSCmdlet.ShouldProcess("$($DataTable.Rows.Count) rows, with BoundParameters $($PSBoundParameters | Out-String)", "SQL Bulk Copy"))
    {
        #Get column info...
            $Columns = $DataTable.Columns | Select -ExpandProperty ColumnName
            $ColumnTypeHash = @{}
            $ColumnToParamHash = @{}
            $Index = 0
            foreach($Col in $DataTable.Columns)
            {
                $Type = Switch -regex ($Col.DataType.FullName)
                {
                    # I figure we create a hashtable, can act upon expected data when doing insert
                    # Might be a better way to handle this...
                    '^(|\ASystem\.)Boolean$' {"BOOLEAN"} #I know they're fake...
                    '^(|\ASystem\.)Byte\[\]' {"BLOB"}
                    '^(|\ASystem\.)Byte$'  {"BLOB"}
                    '^(|\ASystem\.)Datetime$'  {"DATETIME"}
                    '^(|\ASystem\.)Decimal$' {"REAL"}
                    '^(|\ASystem\.)Double$' {"REAL"}
                    '^(|\ASystem\.)Guid$' {"TEXT"}
                    '^(|\ASystem\.)Int16$'  {"INTEGER"}
                    '^(|\ASystem\.)Int32$'  {"INTEGER"}
                    '^(|\ASystem\.)Int64$' {"INTEGER"}
                    '^(|\ASystem\.)UInt16$'  {"INTEGER"}
                    '^(|\ASystem\.)UInt32$'  {"INTEGER"}
                    '^(|\ASystem\.)UInt64$' {"INTEGER"}
                    '^(|\ASystem\.)Single$' {"REAL"}
                    '^(|\ASystem\.)String$' {"TEXT"}
                    Default {"BLOB"} #Let SQLite handle the rest...
                }

                #We ref columns by their index, so add that...
                $ColumnTypeHash.Add($Index,$Type)

                # Parameter names can only be alphanumeric: https://www.sqlite.org/c3ref/bind_blob.html
                # So we have to replace all non-alphanumeric chars in column name to use it as parameter later.
                # This builds hashtable to correlate column name with parameter name.
                $ColumnToParamHash.Add($Col.ColumnName, (Get-ParameterName $Col.ColumnName))

                $Index++
            }

        #Build up the query
            if ($PSBoundParameters.ContainsKey('ConflictClause'))
            {
                $Command.CommandText = New-SqliteBulkQuery -Table $Table -Columns $ColumnToParamHash.Keys -Parameters $ColumnToParamHash.Values -ConflictClause $ConflictClause
            }
            else
            {
                $Command.CommandText = New-SqliteBulkQuery -Table $Table -Columns $ColumnToParamHash.Keys -Parameters $ColumnToParamHash.Values
            }

            foreach ($Column in $Columns)
            {
                $param = New-Object System.Data.SQLite.SqLiteParameter $ColumnToParamHash[$Column]
                [void]$Command.Parameters.Add($param)
            }
            
            for ($RowNumber = 0; $RowNumber -lt $RowCount; $RowNumber++)
            {
                $row = $Datatable.Rows[$RowNumber]
                for($col = 0; $col -lt $Columns.count; $col++)
                {
                    # Depending on the type of thid column, quote it
                    # For dates, convert it to a string SQLite will recognize
                    switch ($ColumnTypeHash[$col])
                    {
                        "BOOLEAN" {
                            $Command.Parameters[$ColumnToParamHash[$Columns[$col]]].Value = [int][boolean]$row[$col]
                        }
                        "DATETIME" {
                            Try
                            {
                                $Command.Parameters[$ColumnToParamHash[$Columns[$col]]].Value = $row[$col].ToString("yyyy-MM-dd HH:mm:ss")
                            }
                            Catch
                            {
                                $Command.Parameters[$ColumnToParamHash[$Columns[$col]]].Value = $row[$col]
                            }
                        }
                        Default {
                            $Command.Parameters[$ColumnToParamHash[$Columns[$col]]].Value = $row[$col]
                        }
                    }
                }

                #We have the query, execute!
                    Try
                    {
                        [void]$Command.ExecuteNonQuery()
                    }
                    Catch
                    {
                        #Minimal testing for this rollback...
                            Write-Verbose "Rolling back due to error:`n$_"
                            $Transaction.Rollback()
                        
                        #Clean up and throw an error
                            CleanUp -conn $SQLiteConnection -com $Command -BoundParams $PSBoundParameters
                            Throw "Rolled back due to error:`n$_"
                    }

                if($NotifyAfter -gt 0 -and $($RowNumber % $NotifyAfter) -eq 0)
                {
                    Write-Verbose "Processed $($RowNumber + 1) records"
                }
            }  
    }
    
    #Commit the transaction and clean up the connection
        $Transaction.Commit()
        CleanUp -conn $SQLiteConnection -com $Command -BoundParams $PSBoundParameters
    
}