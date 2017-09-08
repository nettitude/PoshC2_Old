Function Get-RecentFiles {
    # dump list of recently accessed files 
    $obj = New-Object -ComObject WScript.Shell
    $Path = [System.Environment]::GetFolderPath('Recent')
    $files = Get-ChildItem -Path $Path | Sort-Object LastAccessTime | Select-Object -Last 50

    try {
    foreach ($file in $files)
    {
      $lnk = $file.versioninfo.filename
      $target = $obj.CreateShortcut($lnk).TargetPath
      $target
    }
    }

    catch {
    Write-Output 'Not a link, skipping'
    }
}