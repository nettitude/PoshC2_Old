<#
.Synopsis
    ArpScanner

    PortScan / EgressBuster 2017
    Ben Turner @benpturner 
    Rob Maslen @rbmaslen 

.DESCRIPTION
	Powershell ArpScanner using C# AssemblyLoad. This uses [DllImport("iphlpapi.dll", ExactSpelling=true)] to Export 'SendARP'

    By default it will loop through all interfaces and perform an arpscan of the local network based on the IP Address and Subnet mask provided by the network adaptor. 

    The C# Code has been included but for OpSec purposes it uses AssemblyLoad and not AddType

.EXAMPLE
    PS C:\> Invoke-Arpscan
.EXAMPLE
    PS C:\> ArpScan
.EXAMPLE
    PS C:\> Invoke-Arpscan -IPCidr 10.0.0.1/24

#>
$arploaded = $null
function Invoke-Arpscan {

param (
    [Parameter(Mandatory = $False)]
    [string]$IPCidr,
    [Parameter(Mandatory=$False)]
    [switch]$AddType
)  

if ($AddType.IsPresent) {

echo "[+] Loading Assembly using AddType"
echo ""

Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;

public class ArpScanner
{
    public class MacState
    {
        public Int32 Counter = 0;
        public AutoResetEvent DoneEvent = new AutoResetEvent(false);
        public Dictionary<String, String> Results
        {
            get { return _results; }
            set { _results = value; }
        }
        Dictionary<String, String> _results;
    }
    public class IPQueryState
    {
        public IPQueryState(MacState state)
        {
            CurrentState = state;
        }
        public MacState CurrentState { get { return _currentState; } private set { _currentState = value; } }
        MacState _currentState;

        public string Query { get { return _query; } set { _query = value; } }
        String _query;
    }

    public Dictionary<String, String> DoScan(String ipString)
    {
        return DoScan(ipString, 100);
    }


    public Dictionary<String, String> DoScan(String ipString, ushort maxThreads)
    {
        ThreadPool.SetMaxThreads(maxThreads, maxThreads);
        Dictionary<String, String> Results = new Dictionary<String, String>();
        if ((!ipString.StartsWith("127.0.0.1")) && !ipString.StartsWith("169"))
        {
            MacState state = new MacState();
            state.Results = Results;
            if (ArpScanner.IPv4Tools.IsIPRangeFormat(ipString))
            {
                ArpScanner.IPv4Tools.IPRange iprange = IPv4Tools.IPEnumerator[ipString];

                foreach (string n in iprange)
                {
                    state.Counter++;
                }

                foreach (string ip in iprange)
                {
                    IPQueryState ipq = new IPQueryState(state);
                    ipq.Query = ip;
                    ThreadPool.QueueUserWorkItem(GetMAC, ipq);
                }
                state.DoneEvent.WaitOne();
            }
            else
            {
                IPQueryState ipq = new IPQueryState(state);
                ipq.Query = ipString;
                GetMAC(ipq);
            }


        }
        return Results;
    }

    static void GetMAC(object state)
    {
        IPQueryState queryState = state as IPQueryState;
        try
        {
            IPAddress dst = null;
            if (!IPAddress.TryParse(queryState.Query, out dst))
            {
                Console.WriteLine(String.Format("IP Address {0} is invalid ", queryState.Query));
                return;
            }

            uint uintAddress = BitConverter.ToUInt32(dst.GetAddressBytes(), 0);
            byte[] macAddr = new byte[6];
            int macAddrLen = macAddr.Length;
            int retValue = Kernel32Imports.SendARP(uintAddress, 0, macAddr, ref macAddrLen);
            if (retValue != 0)
            {
                return;
            }
            string[] str = new string[(int)macAddrLen];
            for (int i = 0; i < macAddrLen; i++)
                str[i] = macAddr[i].ToString("x2");
            string mac = string.Join(":", str);

            if (queryState.Query != null && mac != null)
                queryState.CurrentState.Results.Add(queryState.Query, mac);

        }
        finally
        {
            int temp = 0;
            if ((temp = Interlocked.Decrement(ref queryState.CurrentState.Counter)) == 0)
                queryState.CurrentState.DoneEvent.Set();
        }
    }

    static class Kernel32Imports
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
    }

    class IPv4Tools
    {
        private static readonly Regex _ipCidrRegex = new Regex(@"^(?<ip>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(\/(?<cidr>(\d|[1-2]\d|3[0-2])))$");
        private static readonly Regex _ipRegex = new Regex(@"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");
        private static readonly Regex _ipRangeRegex = new Regex(@"^(?<ip>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?<from>([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))(\-(?<to>([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))$");

        public static IPv4Tools IPEnumerator
        {
            get
            {
                return new IPv4Tools();
            }
        }

        public IPRange this[string value]
        {
            get
            {
                return new IPRange(value);
            }
        }

        public static bool IsIPRangeFormat(string IpRange)
        {
            return (_ipCidrRegex.Match(IpRange).Success || _ipRangeRegex.Match(IpRange).Success);
        }

        public static bool IsIPCidr(string ip_cidr)
        {
            return _ipCidrRegex.Match(ip_cidr).Success;
        }

        public static bool IsIPRange(string IpRange)
        {
            return _ipRangeRegex.Match(IpRange).Success;
        }

        public static bool IsIP(string ip)
        {
            return _ipRegex.Match(ip).Success;
        }

        public static Match IpCidrMatch(string ip_cidr)
        {
            return _ipCidrRegex.Match(ip_cidr);
        }

        public static Match IpRangeMatch(string IpRange)
        {
            return _ipRangeRegex.Match(IpRange);
        }

        public class IPRange : IEnumerable<string>
        {
            string _ip_cidr;
            public IPRange(string ip_cidr)
            {
                _ip_cidr = ip_cidr;
            }

            public IEnumerator<string> GetEnumerator()
            {
                return new IPRangeEnumerator(_ip_cidr);
            }

            private IEnumerator GetEnumerator1()
            {
                return this.GetEnumerator();
            }
            IEnumerator IEnumerable.GetEnumerator()
            {
                return GetEnumerator1();
            }
        }

        class IPRangeEnumerator : IEnumerator<string>
        {
            string _ipcidr = null;
            UInt32 _loAddr;
            UInt32 _hiAddr;
            UInt32? _current = null;

            public IPRangeEnumerator(string ip_cidr)
            {
                _ipcidr = ip_cidr;
                Match cidrmch = IPv4Tools.IpCidrMatch(ip_cidr);
                Match rangeMch = IPv4Tools.IpRangeMatch(ip_cidr);
                if (cidrmch.Success)
                    ProcessCidrRange(cidrmch);
                else if (rangeMch.Success)
                    ProcessIPRange(rangeMch);

                if (!cidrmch.Success && !rangeMch.Success)
                    throw new Exception("IP Range must either be in IP/CIDR or IP to-from format");
            }
            public void ProcessIPRange(Match rangeMch)
            {
                System.Net.IPAddress startIp = IPAddress.Parse(rangeMch.Groups["ip"].Value);
                ushort fromRange = ushort.Parse(rangeMch.Groups["from"].Value);
                ushort toRange = ushort.Parse(rangeMch.Groups["to"].Value);

                if (fromRange > toRange)
                    throw new Exception("IP Range the from must be less than the to");
                else if (toRange > 254)
                    throw new Exception("IP Range the to must be less than 254");
                else
                {
                    byte[] arrIpBytes = startIp.GetAddressBytes();
                    Array.Reverse(arrIpBytes);
                    uint ipuint = System.BitConverter.ToUInt32(arrIpBytes, 0);
                    _loAddr = ipuint;
                    _hiAddr = ipuint + ((uint)(toRange - fromRange)) + 1;
                }
            }

            public void ProcessCidrRange(Match cidrmch)
            {
                System.Net.IPAddress ip = IPAddress.Parse(cidrmch.Groups["ip"].Value);
                Int32 cidr = Int32.Parse(cidrmch.Groups["cidr"].Value);

                if (cidr <= 0)
                    throw new Exception("CIDR can't be negative");
                else if (cidr > 32)
                    throw new Exception("CIDR can't be more 32");
                else if (cidr == 32)
                {
                    byte[] arrIpBytes = ip.GetAddressBytes();
                    Array.Reverse(arrIpBytes);
                    UInt32 ipuint = System.BitConverter.ToUInt32(arrIpBytes, 0);
                    _loAddr = ipuint;
                    _hiAddr = ipuint;
                }
                else
                {
                    byte[] arrIpBytes = ip.GetAddressBytes();
                    Array.Reverse(arrIpBytes);
                    UInt32 ipuint = System.BitConverter.ToUInt32(arrIpBytes, 0);
                    uint umsk = uint.MaxValue >> cidr;
                    uint lmsk = (umsk ^ uint.MaxValue);
                    _loAddr = ipuint & lmsk;
                    _hiAddr = ipuint | umsk;
                }
            }

            UInt32 HostToNetwork(UInt32 host)
            {
                byte[] hostBytes = System.BitConverter.GetBytes(host);
                Array.Reverse(hostBytes);
                return System.BitConverter.ToUInt32(hostBytes, 0);
            }

            public string Current
            {
                get
                {
                    if (String.IsNullOrEmpty(_ipcidr) || !_current.HasValue)
                        throw new InvalidOperationException();

                    return IPv4Tools.UIntToIpString(HostToNetwork(_current.Value));
                }
            }

            public bool MoveNext()
            {
                if (!_current.HasValue)
                {
                    _current = _loAddr;
                    if (_current == _hiAddr) //handles if /32 used
                        return true;
                }
                else
                    _current++;

                if ((0xFF & _current) == 0 || (0xFF & _current) == 255)
                    _current++;

                if (_current < _hiAddr)
                    return true;
                else
                    return false;
            }

            public void Reset()
            {
                _current = _loAddr;
                if ((0xFF & _current) == 0 || (0xFF & _current) == 255)
                    _current++;
            }

            object Current1
            {
                get { return this.Current; }
            }

            object IEnumerator.Current
            {
                get { return Current1; }
            }

            public void Dispose()
            { }
        }
        static string UIntToIpString(UInt32 address)
        {
            int num1 = 15;
            char[] chPtr = new char[15];
            int num2 = (int)(address >> 24 & (long)byte.MaxValue);
            do
            {
                chPtr[--num1] = (char)(48 + num2 % 10);
                num2 /= 10;
            }
            while (num2 > 0);
            int num3;
            chPtr[num3 = num1 - 1] = '.';
            int num4 = (int)(address >> 16 & (long)byte.MaxValue);
            do
            {
                chPtr[--num3] = (char)(48 + num4 % 10);
                num4 /= 10;
            }
            while (num4 > 0);
            int num5;
            chPtr[num5 = num3 - 1] = '.';
            int num6 = (int)(address >> 8 & (long)byte.MaxValue);
            do
            {
                chPtr[--num5] = (char)(48 + num6 % 10);
                num6 /= 10;
            }
            while (num6 > 0);

            int startIndex;
            chPtr[startIndex = num5 - 1] = '.';
            int num7 = (int)(address & (long)byte.MaxValue);
            do
            {
                chPtr[--startIndex] = (char)(48 + num7 % 10);
                num7 /= 10;
            }
            while (num7 > 0);

            return new string(chPtr, startIndex, 15 - startIndex);
        }
    }
}
"@
} else {
    if ($arploaded -ne "TRUE") {
        $script:arploaded = "TRUE"
        echo "[+] Loading Assembly using System.Reflection"
        echo ""
        $ps = "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UFF1ZXJ5U3RhdGUAc3RhdGUAQ29tcGlsZXJHZW5lcmF0ZWRBdHRyaWJ1dGUAR3VpZEF0dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBBc3NlbWJseUZpbGVWZXJzaW9uQXR0cmlidXRlAEFzc2VtYmx5Q29uZmlndXJhdGlvbkF0dHJpYnV0ZQBBc3NlbWJseURlc2NyaXB0aW9uQXR0cmlidXRlAERlZmF1bHRNZW1iZXJBdHRyaWJ1dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAEJ5dGUAZ2V0X1ZhbHVlAGdldF9IYXNWYWx1ZQB2YWx1ZQBTeXN0ZW0uVGhyZWFkaW5nAFRvU3RyaW5nAFVJbnRUb0lwU3RyaW5nAGlwU3RyaW5nAHJhbmdlTWNoAGNpZHJtY2gASXBSYW5nZU1hdGNoAElwQ2lkck1hdGNoAFN0YXJ0c1dpdGgAV2FpdENhbGxiYWNrAEhvc3RUb05ldHdvcmsAQXJwU2Nhbm5lckRMTC5kbGwAaXBobHBhcGkuZGxsAFRocmVhZFBvb2wAZ2V0X0l0ZW0AUXVldWVVc2VyV29ya0l0ZW0AU3lzdGVtAERvU2NhbgBQaHlBZGRyTGVuAEpvaW4AU3lzdGVtLlJlZmxlY3Rpb24AR3JvdXBDb2xsZWN0aW9uAEludmFsaWRPcGVyYXRpb25FeGNlcHRpb24AaXAAR3JvdXAAQ2hhcgBwTWFjQWRkcgBfaGlBZGRyAF9sb0FkZHIASXNJUENpZHIAX2lwX2NpZHIAX2lwY2lkcgBBcnBTY2FubmVyAENvdW50ZXIAQml0Q29udmVydGVyAElFbnVtZXJhdG9yAGdldF9JUEVudW1lcmF0b3IASVBSYW5nZUVudW1lcmF0b3IAU3lzdGVtLkNvbGxlY3Rpb25zLklFbnVtZXJhYmxlLkdldEVudW1lcmF0b3IALmN0b3IALmNjdG9yAFN5c3RlbS5EaWFnbm9zdGljcwBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBEZWJ1Z2dpbmdNb2RlcwBHZXRBZGRyZXNzQnl0ZXMAR2V0Qnl0ZXMASVB2NFRvb2xzAFN5c3RlbS5UZXh0LlJlZ3VsYXJFeHByZXNzaW9ucwBTeXN0ZW0uQ29sbGVjdGlvbnMAZ2V0X0dyb3VwcwBnZXRfU3VjY2VzcwBJUEFkZHJlc3MAYWRkcmVzcwBnZXRfUmVzdWx0cwBzZXRfUmVzdWx0cwBLZXJuZWwzMkltcG9ydHMASXNJUFJhbmdlRm9ybWF0AE9iamVjdABTeXN0ZW0uTmV0AFNldABSZXNldABHZXRWYWx1ZU9yRGVmYXVsdABEZWNyZW1lbnQAU3lzdGVtLkNvbGxlY3Rpb25zLklFbnVtZXJhdG9yLkN1cnJlbnQAU3lzdGVtLkNvbGxlY3Rpb25zLklFbnVtZXJhdG9yLmdldF9DdXJyZW50AF9jdXJyZW50AERvbmVFdmVudABBdXRvUmVzZXRFdmVudABob3N0AE1vdmVOZXh0AF9pcFJhbmdlUmVnZXgAX2lwUmVnZXgAX2lwQ2lkclJlZ2V4AEFycmF5AGdldF9RdWVyeQBzZXRfUXVlcnkASXNOdWxsT3JFbXB0eQAAAAATMQAyADcALgAwAC4AMAAuADEAAAcxADYAOQAANUkAUAAgAEEAZABkAHIAZQBzAHMAIAB7ADAAfQAgAGkAcwAgAGkAbgB2AGEAbABpAGQAIAAABXgAMgAAAzoAAIEhXgAoAD8APABpAHAAPgAoACgAWwAwAC0AOQBdAHwAWwAxAC0AOQBdAFsAMAAtADkAXQB8ADEAWwAwAC0AOQBdAHsAMgB9AHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAMgA1AFsAMAAtADUAXQApAFwALgApAHsAMwB9ACgAWwAwAC0AOQBdAHwAWwAxAC0AOQBdAFsAMAAtADkAXQB8ADEAWwAwAC0AOQBdAHsAMgB9AHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAMgA1AFsAMAAtADUAXQApACkAKABcAC8AKAA/ADwAYwBpAGQAcgA+ACgAXABkAHwAWwAxAC0AMgBdAFwAZAB8ADMAWwAwAC0AMgBdACkAKQApACQAAYDTXgAoACgAWwAwAC0AOQBdAHwAWwAxAC0AOQBdAFsAMAAtADkAXQB8ADEAWwAwAC0AOQBdAHsAMgB9AHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAMgA1AFsAMAAtADUAXQApAFwALgApAHsAMwB9ACgAWwAwAC0AOQBdAHwAWwAxAC0AOQBdAFsAMAAtADkAXQB8ADEAWwAwAC0AOQBdAHsAMgB9AHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAMgA1AFsAMAAtADUAXQApACQAAYFpXgAoAD8APABpAHAAPgAoACgAWwAwAC0AOQBdAHwAWwAxAC0AOQBdAFsAMAAtADkAXQB8ADEAWwAwAC0AOQBdAHsAMgB9AHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAMgA1AFsAMAAtADUAXQApAFwALgApAHsAMwB9ACgAPwA8AGYAcgBvAG0APgAoAFsAMAAtADkAXQB8AFsAMQAtADkAXQBbADAALQA5AF0AfAAxAFsAMAAtADkAXQB7ADIAfQB8ADIAWwAwAC0ANABdAFsAMAAtADkAXQB8ADIANQBbADAALQA1AF0AKQApACkAKABcAC0AKAA/ADwAdABvAD4AKABbADAALQA5AF0AfABbADEALQA5AF0AWwAwAC0AOQBdAHwAMQBbADAALQA5AF0AewAyAH0AfAAyAFsAMAAtADQAXQBbADAALQA5AF0AfAAyADUAWwAwAC0ANQBdACkAKQApACQAAW9JAFAAIABSAGEAbgBnAGUAIABtAHUAcwB0ACAAZQBpAHQAaABlAHIAIABiAGUAIABpAG4AIABJAFAALwBDAEkARABSACAAbwByACAASQBQACAAdABvAC0AZgByAG8AbQAgAGYAbwByAG0AYQB0AAEFaQBwAAAJZgByAG8AbQAABXQAbwAAVUkAUAAgAFIAYQBuAGcAZQAgAHQAaABlACAAZgByAG8AbQAgAG0AdQBzAHQAIABiAGUAIABsAGUAcwBzACAAdABoAGEAbgAgAHQAaABlACAAdABvAABLSQBQACAAUgBhAG4AZwBlACAAdABoAGUAIAB0AG8AIABtAHUAcwB0ACAAYgBlACAAbABl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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        $dllbytes  = [System.Convert]::FromBase64String($ps)
        $assembly = [System.Reflection.Assembly]::Load($dllbytes)
    }
}

if ($IPCidr) {

    try {
        echo "[+] Arpscan against: $IPCidr"
        $ArpScanner = New-Object ArpScanner
        $ArpScanner.DoScan($ipcidr)
    } catch {
        echo "[-] Error against network $IPCidr"
    }

} else {

    $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -EA Stop | ? {$_.IPEnabled}

    foreach ($Network in $Networks) {

    $ip  = $Network.IpAddress[0]
    $mask  = $Network.IPSubnet[0]
    $DefaultGateway = $Network.DefaultIPGateway
    $DNSServers  = $Network.DNSServerSearchOrder

    $val = 0; $mask -split "\." | % {$val = $val * 256 + [Convert]::ToInt64($_)}
    $ipcidr = $ip + "/" + [Convert]::ToString($val,2).IndexOf('0')

    try {
        echo "[+] Arpscan against: $ipcidr"
        $ArpScanner = New-Object ArpScanner
        $ArpScanner.DoScan($ipcidr)
    } catch {
        echo "[-] Error against network $ipcidr"
    }

    }

}

}
New-Alias ArpScan Invoke-Arpscan