<#
        .Synopsis
        C2-Viewer cmdlet for the PowershellC2 to view the db when using the team server
        .EXAMPLE
        C2-Viewer -FolderPath C:\Temp\PoshC2-031120161055
#>
function C2-Viewer
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
        # do you want a read-only c2 server window
    }
    if (!$PoshPath) {
        $PoshPath = Read-Host -Prompt `n'Enter the PoshC2 path'
        # do you want a read-only c2 server window
    }
    $slash = $FolderPath -match '.+[^\\]\\$'
    if ($slash) {
        $FolderPath = $FolderPath.TrimEnd('\')
    }

    $defaultrows = 10
    $prompt = Read-Host -Prompt "How many previous rows do you want to show, Number or ALL? [$($defaultrows)]"
    
    $defaultrows = ($defaultrows,$prompt)[[bool]$prompt]
    if ($defaultrows -eq "ALL"){[INT]$defaultrowstotal=99999} else {[INT]$defaultrowstotal=[INT]$defaultrows}

    Clear-Host
    Write-Host -Object ""
    Write-Host -Object "__________            .__.     _________  ________  "  -ForegroundColor Green
    Write-Host -Object "\_______  \____  _____|  |__   \_   ___ \ \_____  \ "  -ForegroundColor Green
    Write-Host -Object " |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/ "  -ForegroundColor Green
    Write-Host -Object " |    |  (  <_> )___ \|   Y  \ \     \____/       \ "  -ForegroundColor Green
    Write-Host -Object " |____|   \____/____  >___|  /  \______  /\_______ \"  -ForegroundColor Green
    Write-Host -Object "                    \/     \/          \/         \/"  -ForegroundColor Green
    Write-Host "=============== v2.2 www.PoshC2.co.uk ==============" -ForegroundColor Green
    Write-Host "====================================================" `n -ForegroundColor Green

    # initiate defaults
    $Database = "$FolderPath\PowershellC2.SQLite"
    $p = $env:PsModulePath
    $p += ";$PoshPath"

    [Environment]::SetEnvironmentVariable("PSModulePath",$p)
    Import-Module -Name PSSQLite


    $count = Invoke-SqliteQuery -DataSource $Database -Query "SELECT COUNT() FROM CompletedTasks" -as SingleValue

    $resultsdb = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM CompletedTasks ORDER BY CompletedTaskID DESC LIMIT $defaultrowstotal" -as PSObject

    foreach ($test in $resultsdb)
    {
    $ranuri = $test.RandomURI
    $im_result = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM Implants WHERE RandomURI='$ranuri'" -as PSObject
    $implanthost = $im_result.User
    $im = Invoke-SqliteQuery -DataSource $Database -Query "SELECT User FROM Implants WHERE RandomURI='$ranuri'" -as SingleValue

    $taskcompledtime = $test.TaskID
    Write-Host $test.Command -ForegroundColor Yellow
    Write-Host "Command returned against host:" $im_result.Hostname $im_result.Domain "($taskcompledtime)" -ForegroundColor Green
    Write-Host -Object $test.Output -ForegroundColor Green
    $taskiddb ++
    }

    $count ++
    while ($true) {
        $resultsdb = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM CompletedTasks WHERE CompletedTaskID=$count" -as PSObject

        if ($resultsdb)
        {
        $ranuri = $resultsdb.RandomURI
        $im_result = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM Implants WHERE RandomURI='$ranuri'" -as PSObject
        $implanthost = $im_result.User
        $im = Invoke-SqliteQuery -DataSource $Database -Query "SELECT User FROM Implants WHERE RandomURI='$ranuri'" -as SingleValue

        $taskcompledtime = $resultsdb.TaskID
        Write-Host $resultsdb.Command -ForegroundColor Yellow
        Write-Host "Command returned against host:" $im_result.Hostname $im_result.Domain "($taskcompledtime)" -ForegroundColor Green
        Write-Host -Object $resultsdb.Output -ForegroundColor Green
        $taskiddb ++
        $count ++
        }
    }
}
