#!/usr/local/bin/pwsh
<#
        MIT License

        Copyright (c) 2018 ytmknd

        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to deal
        in the Software without restriction, including without limitation the rights
        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
        copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all
        copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        SOFTWARE.
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$TRUE,Position=1)]
    [string]$clientIPAddressesWithBitmask,

    [Parameter(Mandatory=$FALSE,Position=2)]
    [string]$subnetMask,

    [Parameter(Mandatory=$FALSE,Position=3)]
    [string]$defaultGatewayAddress,

    [Parameter(Mandatory=$FALSE,Position=4)]
    [string]$dnsServerAddress,

    [Parameter(Mandatory=$FALSE,Position=5)]
    [string]$clientMacAddresses,

    [switch]$noreplymode
)

$DebugPreference = "Continue"

$TransactionID = "00000000"
$ClientIPAddress = "127.0.0.1"
$ClientHardwareAddress = "112233445566"
$ServerIdentifier = "192.168.10.5"
$SubnetMask = "255.255.255.0"
$Router = "192.168.10.1"
$DomainNameServer = "192.168.10.1"
$DomainName = "tempdomain"
$NetBIOSOverTCPIPNameServer = "192.168.10.1"
#
$global:requestedIPAddress = "127.0.0.1"
#
$clientIPAddressStartAddress = @(0,0,0,0)   
$clientIPAddressEndAddress = @(0,0,0,0)   

# Recv
## UDP packet buffer
$udpPacketRecv = @("00") * 300
# Send
## UDP packet buffer
$udpPacketSend = @("00") * 300
## DHCP option(for send and recieve)
$global:dhcpOptions = @("00") * 64
$global:headpos = 4 # skip magic 

$port=67
$endpoint = new-object System.Net.IPEndPoint ([IPAddress]::Any,$port)
$udpclient = new-Object System.Net.Sockets.UdpClient $port
$udpclient.EnableBroadcast = true;

# Recv
set-variable -name CMD_PARSER_NOT_IMPLEMENTED -value "CMDParseOption_NotImplemented" -option constant
set-variable -name CMD_PARSE_OPTION_ASCII -value "CMDParseOption_Ascii" -option constant
set-variable -name CMD_PARSE_OPTION_DUMP -value "CMDParseOption_Dump" -option constant
set-variable -name CMD_PARSE_OPTION_DUMP_IP -value "CMDParseOption_DumpIPAddress" -option constant
# Send
set-variable -name CMD_GET_NOT_IMPLEMENTED -value "getCMD_NotImplemented" -option constant
set-variable -name CMD_GET_OPTIONSEQ_IPV4 -value "getCMDAndIPv4Address4DHCPOption" -option constant
set-variable -name CMD_GET_OPTIONSEQ_ASCII -value "getCMDAndAscii4DHCPOption" -option constant
$DHCPOptionTable=@(
<#  0#> @("Pad.","CMDParseOption_Pad",$CMD_PARSER_NOT_IMPLEMENTED),
<#  1#> @("Subnet Mask.",$CMD_PARSE_OPTION_DUMP,"getSubnetMask4DHCPOption"),
<#  2#> @("Time Offset (deprecated).",$CMD_PARSER_NOT_IMPLEMENTED),
<#  3#> @("Router.",$CMD_PARSE_OPTION_DUMP_IP,$CMD_GET_OPTIONSEQ_IPV4),
<#  4#> @("Time Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<#  5#> @("Name Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<#  6#> @("Domain Name Server.",$CMD_PARSE_OPTION_DUMP_IP,$CMD_GET_OPTIONSEQ_IPV4),
<#  7#> @("Log Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<#  8#> @("Quote Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<#  9#> @("LPR Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 10#> @("Impress Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 11#> @("Resource Location Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 12#> @("Host Name.","CMDParseOption_Ascii",$CMD_PARSER_NOT_IMPLEMENTED),
<# 13#> @("Boot File Size.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 14#> @("Merit Dump File.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 15#> @("Domain Name.",$CMD_PARSE_OPTION_ASCII,$CMD_GET_OPTIONSEQ_ASCII),
<# 16#> @("Swap Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 17#> @("Root Path.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 18#> @("Extensions Path.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 19#> @("IP Forwarding enable/disable.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 20#> @("Non-local Source Routing enable/disable.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 21#> @("Policy Filter.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 22#> @("Maximum Datagram Reassembly Size.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 23#> @("Default IP Time-to-live.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 24#> @("Path MTU Aging Timeout.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 25#> @("Path MTU Plateau Table.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 26#> @("Interface MTU.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 27#> @("All Subnets are Local.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 28#> @("Broadcast Address.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 29#> @("Perform Mask Discovery.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 30#> @("Mask supplier.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 31#> @("Perform router discovery.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 32#> @("Router solicitation address.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 33#> @("Static routing table.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 34#> @("Trailer encapsulation.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 35#> @("ARP cache timeout.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 36#> @("Ethernet encapsulation.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 37#> @("Default TCP TTL.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 38#> @("TCP keepalive interval.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 39#> @("TCP keepalive garbage.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 40#> @("Network Information Service Domain.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 41#> @("Network Information Servers.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 42#> @("NTP servers.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 43#> @("Vendor specific information.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 44#> @("NetBIOS over TCP/IP name server.",$CMD_PARSE_OPTION_DUMP_IP,$CMD_GET_OPTIONSEQ_IPV4),
<# 45#> @("NetBIOS over TCP/IP Datagram Distribution Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 46#> @("NetBIOS over TCP/IP Node Type.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 47#> @("NetBIOS over TCP/IP Scope.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 48#> @("X Window System Font Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 49#> @("X Window System Display Manager.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 50#> @("Requested IP Address.",$CMD_PARSE_OPTION_DUMP_IP),
<# 51#> @("IP address lease time.",$CMD_PARSE_OPTION_DUMP,"getIPAddressLeaseTime4DHCPOption"),
<# 52#> @("Option overload.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 53#> @("DHCP message type.","CMDParseOption_DHCPMessageType","getDHCPMessageType4DHCPOption"),
<# 54#> @("Server identifier.",$CMD_PARSE_OPTION_DUMP_IP,"getServerIdentifier4DHCPOption"),
<# 55#> @("Parameter request list.",$CMD_PARSE_OPTION_DUMP),
<# 56#> @("Message.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 57#> @("Maximum DHCP message size.",$CMD_PARSE_OPTION_DUMP),
<# 58#> @("Renew time value.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 59#> @("Rebinding time value.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 60#> @("Class-identifier.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 61#> @("Client-identifier.",$CMD_PARSE_OPTION_DUMP),
<# 62#> @("NetWare/IP Domain Name.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 63#> @("NetWare/IP information.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 64#> @("Network Information Service+ Domain.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 65#> @("Network Information Service+ Servers.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 66#> @("TFTP server name.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 67#> @("Bootfile name.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 68#> @("Mobile IP Home Agent.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 69#> @("Simple Mail Transport Protocol Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 70#> @("Post Office Protocol Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 71#> @("Network News Transport Protocol Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 72#> @("Default World Wide Web Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 73#> @("Default Finger Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 74#> @("Default Internet Relay Chat Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 75#> @("StreetTalk Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 76#> @("StreetTalk Directory Assistance Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 77#> @("User Class Information.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 78#> @("SLP Directory Agent.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 79#> @("SLP Service Scope.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 80#> @("Rapid Commit.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 81#> @("FQDN, Fully Qualified Domain Name.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 82#> @("Relay Agent Information.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 83#> @("Internet Storage Name Service.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 84#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<# 85#> @("NDS servers.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 86#> @("NDS tree name.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 87#> @("NDS context.",$CMD_PARSER_NOT_IMPLEMENTED),	
<# 88#> @("BCMCS Controller Domain Name list.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 89#> @("BCMCS Controller IPv4 address list.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 90#> @("Authentication.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 91#> @("client-last-transaction-time.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 92#> @("associated-ip.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 93#> @("Client System Architecture Type.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 94#> @("Client Network Interface Identifier.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 95#> @("LDAP, Lightweight Directory Access Protocol.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 96#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<# 97#> @("Client Machine Identifier.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 98#> @("Open Groups User Authentication.",$CMD_PARSER_NOT_IMPLEMENTED),
<# 99#> @("GEOCONF_CIVIC.",$CMD_PARSER_NOT_IMPLEMENTED),
<#100#> @("IEEE 1003.1 TZ String.",$CMD_PARSER_NOT_IMPLEMENTED),
<#101#> @("Reference to the TZ Database.",$CMD_PARSER_NOT_IMPLEMENTED),
<#102#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#103#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#104#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#105#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#106#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#107#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#108#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#109#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#110#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#111#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#112#> @("NetInfo Parent Server Address.",$CMD_PARSER_NOT_IMPLEMENTED),
<#113#> @("NetInfo Parent Server Tag.",$CMD_PARSER_NOT_IMPLEMENTED),
<#114#> @("URL.",$CMD_PARSER_NOT_IMPLEMENTED),
<#115#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#116#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#117#> @("Name Service Search.",$CMD_PARSER_NOT_IMPLEMENTED),
<#118#> @("Subnet Selection.",$CMD_PARSER_NOT_IMPLEMENTED),
<#119#> @("DNS domain search list.",$CMD_PARSER_NOT_IMPLEMENTED),
<#120#> @("SIP Servers DHCP Option.",$CMD_PARSER_NOT_IMPLEMENTED),
<#121#> @("Classless Static Route Option.",$CMD_PARSER_NOT_IMPLEMENTED),
<#122#> @("CCC, CableLabs Client Configuration.",$CMD_PARSER_NOT_IMPLEMENTED),
<#123#> @("GeoConf.",$CMD_PARSER_NOT_IMPLEMENTED),
<#124#> @("Vendor-Identifying Vendor Class.",$CMD_PARSER_NOT_IMPLEMENTED),
<#125#> @("Vendor-Identifying Vendor-Specific.",$CMD_PARSER_NOT_IMPLEMENTED),
<#126#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#127#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#128#> @("TFTP Server IP address.",$CMD_PARSER_NOT_IMPLEMENTED),
<#129#> @("Call Server IP address.",$CMD_PARSER_NOT_IMPLEMENTED),
<#130#> @("Discrimination string.",$CMD_PARSER_NOT_IMPLEMENTED),
<#131#> @("Remote statistics server IP address.",$CMD_PARSER_NOT_IMPLEMENTED),
<#132#> @("802.1P VLAN ID.",$CMD_PARSER_NOT_IMPLEMENTED),
<#133#> @("802.1Q L2 Priority.",$CMD_PARSER_NOT_IMPLEMENTED),
<#134#> @("Diffserv Code Point.",$CMD_PARSER_NOT_IMPLEMENTED),
<#135#> @("HTTP Proxy for phone-specific applications.",$CMD_PARSER_NOT_IMPLEMENTED),
<#136#> @("PANA Authentication Agent.",$CMD_PARSER_NOT_IMPLEMENTED),
<#137#> @("LoST Server.",$CMD_PARSER_NOT_IMPLEMENTED),
<#138#> @("CAPWAP Access Controller addresses.",$CMD_PARSER_NOT_IMPLEMENTED),
<#139#> @("OPTION-IPv4_Address-MoS.",$CMD_PARSER_NOT_IMPLEMENTED),
<#140#> @("OPTION-IPv4_FQDN-MoS.",$CMD_PARSER_NOT_IMPLEMENTED),
<#141#> @("SIP UA Configuration Service Domains.",$CMD_PARSER_NOT_IMPLEMENTED),
<#142#> @("OPTION-IPv4_Address-ANDSF.",$CMD_PARSER_NOT_IMPLEMENTED),
<#143#> @("OPTION-IPv6_Address-ANDSF.",$CMD_PARSER_NOT_IMPLEMENTED),
<#144#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#145#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#146#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#147#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#148#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#149#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#150#> @("TFTP server address/Etherboot.",$CMD_PARSER_NOT_IMPLEMENTED),
<#151#> @("status-code.",$CMD_PARSER_NOT_IMPLEMENTED),
<#152#> @("base-time.",$CMD_PARSER_NOT_IMPLEMENTED),
<#153#> @("start-time-of-state.",$CMD_PARSER_NOT_IMPLEMENTED),
<#154#> @("query-start-time.",$CMD_PARSER_NOT_IMPLEMENTED),
<#155#> @("query-end-time.",$CMD_PARSER_NOT_IMPLEMENTED),
<#156#> @("dhcp-state.",$CMD_PARSER_NOT_IMPLEMENTED),
<#157#> @("data-source.",$CMD_PARSER_NOT_IMPLEMENTED),
<#158#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#160#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#161#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#162#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#163#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#164#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#165#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#166#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#167#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#168#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#169#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#170#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#171#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#172#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#173#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#174#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#175#> @("Etherboot.",$CMD_PARSER_NOT_IMPLEMENTED),
<#176#> @("IP Telephone.",$CMD_PARSER_NOT_IMPLEMENTED),
<#177#> @("Etherboot./PacketCable and CableHome.",$CMD_PARSER_NOT_IMPLEMENTED),
<#178#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#179#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#180#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#181#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#182#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#183#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#184#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#185#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#186#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#187#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#188#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#189#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#190#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#191#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#192#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#193#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#194#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#195#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#196#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#197#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#198#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#199#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#200#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#201#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#202#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#203#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#204#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#205#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#206#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#207#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#208#> @("pxelinux.magic (string) = F1:00:74:7E (241.0.116.126).",$CMD_PARSER_NOT_IMPLEMENTED),
<#209#> @("pxelinux.configfile (text).",$CMD_PARSER_NOT_IMPLEMENTED),
<#210#> @("pxelinux.pathprefix (text).",$CMD_PARSER_NOT_IMPLEMENTED),
<#211#> @("pxelinux.reboottime (unsigned integer 32 bits).",$CMD_PARSER_NOT_IMPLEMENTED),
<#212#> @("OPTION_6RD.",$CMD_PARSER_NOT_IMPLEMENTED),
<#213#> @("OPTION_V4_ACCESS_DOMAIN.",$CMD_PARSER_NOT_IMPLEMENTED),
<#214#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#215#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#216#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#217#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#218#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#219#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#220#> @("Subnet Allocation.",$CMD_PARSER_NOT_IMPLEMENTED),
<#221#> @("Virtual Subnet Selection.",$CMD_PARSER_NOT_IMPLEMENTED),
<#222#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#223#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#224#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#225#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#226#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#227#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#228#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#229#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#230#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#231#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#232#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#233#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#234#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#235#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#236#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#237#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#238#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#239#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#240#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#241#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#242#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#243#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#244#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#245#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#246#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#247#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#248#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#249#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#250#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#251#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#252#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#253#> @("  ",$CMD_PARSER_NOT_IMPLEMENTED),
<#254#> @("Private use.",$CMD_PARSER_NOT_IMPLEMENTED),
<#255#> @("End.",$CMD_PARSER_NOT_IMPLEMENTED)
)

# for building DHCP header
set-variable -name DHCP_OPCODE_REQUEST -value "01" -option constant
set-variable -name DHCP_OPCODE_ACK -value "02" -option constant
function setOpcode2UDPPacket($type) { #Opcode
    if (($type -ne $DHCP_OPCODE_REQUEST) -And ($type -ne $DHCP_OPCODE_ACK)) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    $udpPacketSend[0] = $type
}
set-variable -name DHCP_HARDWARE_TYPE_ETHERNET -value "01" -option constant
function setHardwareType2UDPPacket($type) { #Hardware type
    if ($type -ne $DHCP_HARDWARE_TYPE_ETHERNET) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    $udpPacketSend[1] = $type
}
function setHardwareAddressLength2UDPPacket($length) { #Hardware address length
    if ($length -ne 6) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    $udpPacketSend[2] = $length.toString("X2")
}
function setHopCount2UDPPacket() { #Hop count
    $udpPacketSend[3] = "00" # always 00
}
function setTransactionID2UDPPacket($id) { #Transaction ID
    if (($id.length) -ne 8) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    $udpPacketSend[4] = $id.SubString(0,2) 
    $udpPacketSend[5] = $id.SubString(2,2)
    $udpPacketSend[6] = $id.SubString(4,2)
    $udpPacketSend[7] = $id.SubString(6,2)
}
function setNumberOfSeconds2UDPPacket() { #Number of seconds
    $udpPacketSend[8] = "00" # always 00
    $udpPacketSend[9] = "00" # always 00
}
function setFlagsOfSeconds2UDPPacket() { #Flags
    $udpPacketSend[10] = "00" # always 00
    $udpPacketSend[11] = "00" # always 00
}
function setClientIPAddress2UDPPacket($ip) { #Client IP address
    $aIp = $ip.split(".")
    if (($aIp.length) -ne 4) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    foreach($o in $aIp) {
        if ((($o.ToInt32($Null)) -lt 0) -Or (($o.ToInt32($Null)) -gt 255)) {
            throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
        } 
    }
    $udpPacketSend[12] = $aIp[0].ToInt32($Null).ToString("X2")
    $udpPacketSend[13] = $aIp[1].ToInt32($Null).ToString("X2")
    $udpPacketSend[14] = $aIp[2].ToInt32($Null).ToString("X2")
    $udpPacketSend[15] = $aIp[3].ToInt32($Null).ToString("X2")
}
function setYourIPAddress2UDPPacket($ip) { #Your IP address
    $aIp = $ip.split(".")
    if (($aIp.length) -ne 4) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    foreach($o in $aIp) {
        if (($o -lt 0) -Or ($o -gt 255)) {
            throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
        } 
    }
    $udpPacketSend[16] = $aIp[0].ToInt32($Null).ToString("X2")
    $udpPacketSend[17] = $aIp[1].ToInt32($Null).ToString("X2")
    $udpPacketSend[18] = $aIp[2].ToInt32($Null).ToString("X2")
    $udpPacketSend[19] = $aIp[3].ToInt32($Null).ToString("X2")
}
function setServerIPAddress2UDPPacket($ip) { #Server IP address
    $aIp = $ip.split(".")
    if (($aIp.length) -ne 4) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    foreach($o in $aIp) {
        if (($o -lt 0) -Or ($o -gt 255)) {
            throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
        } 
    }
    $udpPacketSend[20] = $aIp[0].ToInt32($Null).ToString("X2")
    $udpPacketSend[21] = $aIp[1].ToInt32($Null).ToString("X2")
    $udpPacketSend[22] = $aIp[2].ToInt32($Null).ToString("X2")
    $udpPacketSend[23] = $aIp[3].ToInt32($Null).ToString("X2")
}
function setGatewayIPAddress2UDPPacket($ip) { #Gateway IP address
    $aIp = $ip.split(".")
    if (($aIp.length) -ne 4) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    foreach($o in $aIp) {
        if (($o -lt 0) -Or ($o -gt 255)) {
            throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
        } 
    }
    $udpPacketSend[20] = $aIp[0].ToInt32($Null).ToString("X2")
    $udpPacketSend[21] = $aIp[1].ToInt32($Null).ToString("X2")
    $udpPacketSend[22] = $aIp[2].ToInt32($Null).ToString("X2")
    $udpPacketSend[23] = $aIp[3].ToInt32($Null).ToString("X2")
}
function setClientHardwareAddress2UDPPacket($mac) { #Boot filename
    if (($mac.length) -ne 12) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    #mac addr(6 bytes)
    $udpPacketSend[28] = $mac.SubString(0,2) 
    $udpPacketSend[29] = $mac.SubString(2,2)
    $udpPacketSend[30] = $mac.SubString(4,2)
    $udpPacketSend[31] = $mac.SubString(6,2)
    $udpPacketSend[32] = $mac.SubString(8,2)
    $udpPacketSend[33] = $mac.SubString(10,2)
    #padding 
    for($i=34;$i -le 43;$i++) {
        $udpPacketSend[$i] = "00" # always 00
    }
}
function setServerHostName2UDPPacket() { #Server host name
    for($i=44;$i -le 107;$i++) {
        $udpPacketSend[$i] = "00" # always 00
    }
}
function setBootFilename2UDPPacket() { #Boot filename
    for($i=108;$i -le 235;$i++) {
        $udpPacketSend[$i] = "00" # always 00
    }
}
function setDHCPOption2UDPPacket($opt) { #DHCP Option
    for($i=0;$i -lt 64;$i++) {
        $udpPacketSend[236 + $i] = $opt[$i] 
    }
}

function lcl_checkIfAllZero($serverhostname) {
    $allzerof = $TRUE
    foreach($d in $serverhostname) {
        if ($d -ne "00") {
            $allzerof = $FALSE
            break
        }
    }
    return $allzerof
}

# for building DHCP option
function setMagic2DHCPOption() { 
    # 0x63 0x82 0x53 0x63
    $dhcpOptions[0] = "63"
    $dhcpOptions[1] = "82"
    $dhcpOptions[2] = "53"
    $dhcpOptions[3] = "63"
}
function setCodeAndOption2DHCPOption($data) { 
    for($i=0;$i -lt $data.length;$i++) {
        $dhcpOptions[($headpos + $i)] = $data[$i]
    }
    #echo("$([string]::Join(" ",$data)):$($i)//")
}
function setEndMark2DHCPOption() { 
    $dhcpOptions[$headpos] = "FF" 
}
function lcl_getVEXTLength() {
    #Write-Debug "$($dhcpOptions[$headpos + 1])"
    return [Convert]::ToInt32(($dhcpOptions[$headpos + 1]), 16)
}
function ForwardHeadPos() {
    $i = lcl_getVEXTLength
    #Write-Debug "$($headpos+2+$i)"
    return $headpos+2+$i
}
function getOptionSeq4DHCPOption([array]$opt) {
    for($i=0;$i -lt $DHCPOptionTable.length;$i++) {
        if ($DHCPOptionTable[$i][0] -eq $opt[0]) {
            return Invoke-Expression "$($DHCPOptionTable[$i][2]) $i $($opt[1..-1])"
        }
    }
    throw "Exception : function not found(" + $opt[0] + ")"
}
#<#0	0#>	@("Pad.",...
function getSubnetMask4DHCPOption([int]$num, [array]$opt) {     
    return @( $num.ToString("X2"), "00" )
}
#<#1	4#>	@("Subnet Mask.",...
function getSubnetMask4DHCPOption([int]$num, [array]$opt) {     
    #Write-Debug "$($num) $($opt[0])"
    $ret = @( $num.ToString("X2"), "04" )
    $aIp = ($opt[0]).split(".")
    if (($aIp.length) -ne 4) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    foreach($o in $aIp) {
        if ((($o.ToInt32($Null)) -lt 0) -Or (($o.ToInt32($Null)) -gt 255)) {
            throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
        } 
    }
    $ret += $aIp[0].ToInt32($Null).ToString("X2")
    $ret += $aIp[1].ToInt32($Null).ToString("X2")
    $ret += $aIp[2].ToInt32($Null).ToString("X2")
    $ret += $aIp[3].ToInt32($Null).ToString("X2")
    return $ret
}
#<#53 1#> @("DHCP message type.",...
set-variable -name MSG_DHCPDISCOVER -value "DHCPDISCOVER" -option constant
set-variable -name MSG_DHCPOFFER -value "DHCPOFFER" -option constant
set-variable -name MSG_DHCPREQUEST -value "DHCPREQUEST" -option constant
set-variable -name MSG_DHCPDECLINE -value "DHCPDECLINE" -option constant
set-variable -name MSG_DHCPPACK -value "DHCPPACK" -option constant
set-variable -name MSG_DHCPPNCK -value "DHCPPNCK" -option constant
function getDHCPMessageType4DHCPOption([int]$num, [array]$opt) {     
    #Write-Debug "$($num) $($opt[0])"
    $ret = @( $num.ToString("X2"), "01" )
    switch ($opt[0]) {
        $MSG_DHCPDISCOVER { $ret+="01" }
        $MSG_DHCPOFFER { $ret+="02" }
        $MSG_DHCPREQUEST { $ret+="03" }
        $MSG_DHCPDECLINE { $ret+="04" }
        $MSG_DHCPPACK { $ret+="05" }
        $MSG_DHCPPNCK { $ret+="06" }
        default{         
            throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")" 
        }
    }
    return $ret
}
#<#54 4#> @("Server identifier.",...
function getServerIdentifier4DHCPOption([int]$num, [array]$opt) {     
    #Write-Debug "$($num) $($opt[0])"
    $ret = @( $num.ToString("X2"), "04" )
    $aIp = ($opt[0]).split(".")
    if (($aIp.length) -ne 4) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    foreach($o in $aIp) {
        if ((($o.ToInt32($Null)) -lt 0) -Or (($o.ToInt32($Null)) -gt 255)) {
            throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
        } 
    }
    $ret += $aIp[0].ToInt32($Null).ToString("X2")
    $ret += $aIp[1].ToInt32($Null).ToString("X2")
    $ret += $aIp[2].ToInt32($Null).ToString("X2")
    $ret += $aIp[3].ToInt32($Null).ToString("X2")
    return $ret
}
#<#3	4+#> @("Router.",...
function getCMDAndIPv4Address4DHCPOption([int]$num, [array]$opt) {     
    #Write-Debug "$($num) $($opt[0])"
    $ret = @( $num.ToString("X2"), "04" )
    $aIp = ($opt[0]).split(".")
    if (($aIp.length) -ne 4) {
        throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
    }
    foreach($o in $aIp) {
        if ((($o.ToInt32($Null)) -lt 0) -Or (($o.ToInt32($Null)) -gt 255)) {
            throw "Exception : Illegal parameter(" + $MyInvocation.MyCommand + ")"
        } 
    }
    $ret += $aIp[0].ToInt32($Null).ToString("X2")
    $ret += $aIp[1].ToInt32($Null).ToString("X2")
    $ret += $aIp[2].ToInt32($Null).ToString("X2")
    $ret += $aIp[3].ToInt32($Null).ToString("X2")
    return $ret
}
#<#51 4#> @("IP address lease time.",...
function getIPAddressLeaseTime4DHCPOption([int]$num, [array]$opt) {     
    #Write-Debug "$($num) $($opt[0])"
    $ret = @( $num.ToString("X2"), "04" )
    $ret += "00" # 1day
    $ret += "01"
    $ret += "51"
    $ret += "80"
    return $ret
}
#<#15 1+#> @("Domain Name.",...
function getCMDAndAscii4DHCPOption([int]$num, [array]$opt) {     
    #Write-Debug "$($num) $($opt[0])"
    $ret = @( $num.ToString("X2") )
    $ret += ($opt[0]).length.ToString("X2")
    $aString = $opt.ToCharArray()
    foreach($c in $aString) {
        $ret += ([byte][char]($c)).toString("X2")
    }
    return $ret
}

function clearDHCPOptionsBuf() {
    Set-Variable -Name "dhcpOptions" -Scope global -Value (@("00") * 64) 
}

function lcl_buildDHCPOFFERPacket() {
    ##Header
    setOpcode2UDPPacket $DHCP_OPCODE_ACK
    setHardwareType2UDPPacket $DHCP_HARDWARE_TYPE_ETHERNET
    setHardwareAddressLength2UDPPacket 6
    setHopCount2UDPPacket
    setTransactionID2UDPPacket $TransactionID
    setNumberOfSeconds2UDPPacket
    setFlagsOfSeconds2UDPPacket
    setClientIPAddress2UDPPacket $ClientIPAddress
    setYourIPAddress2UDPPacket "0.0.0.0"
    setServerIPAddress2UDPPacket "0.0.0.0"
    setGatewayIPAddress2UDPPacket "0.0.0.0"
    setClientHardwareAddress2UDPPacket $ClientHardwareAddress
    setServerHostName2UDPPacket
    setBootFilename2UDPPacket
    ##Option
    clearDHCPOptionsBuf
    setMagic2DHCPOption
    Set-Variable -Name "headpos" -Scope global -Value 4 
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "DHCP message type.",$MSG_DHCPOFFER) # Option: (53) DHCP Message Type (OFFER)
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Server identifier.",$ServerIdentifier) # Option: (54) DHCP Server Identifier
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "IP address lease time.","1day") # Option: (51) IP Address Lease Time
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Subnet Mask.",$SubnetMask) # Option: (1) Subnet Mask
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Router.",$Router) # Option: (3) Router
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Domain Name Server.","192.168.10.1") # Option: (6) Domain Name Server
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Domain Name.",$DomainNameServer) # Option: (15) Domain Name
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "NetBIOS over TCP/IP name server.",$NetBIOSOverTCPIPNameServer) # Option: (44) NetBIOS over TCP/IP Name Server
    $headpos=ForwardHeadPos
    setEndMark2DHCPOption
    setDHCPOption2UDPPacket $dhcpOptions
}
function replyDHCPOFFER() {
    lcl_buildDHCPOFFERPacket

    #Set-Variable -Name "dhcpOptions" -Scope global -Value $dhcpOptions 
    $count=0
    foreach($e in $dhcpOptions) {
        [System.Console]::Write($d + " ")
        $count += 1 
        if ($count % 16 -eq 0) { [System.Console]::WriteLine("") } 
    }
    if($count % 16 -ne 0) { [System.Console]::WriteLine("") } 

    Write-Debug("DEBUG DHCPOFFER")
    echoDHCPPcakcetSend

    #send
    $b=@()
    foreach($d in $udpPacketSend) {
        $b += [Byte]::Parse(([Convert]::ToInt32($d,16)), [System.Globalization.NumberStyles]::Integer) 
    }
    $endpoint = new-object System.Net.IPEndPoint (([system.net.IPAddress]::Parse($ClientIPAddress)),68)
    $bytesSent=$udpclient.Send($b,($b.length),$endpoint)
}
function lcl_buildDHCPPACKPacket() {
    ##Header
    setOpcode2UDPPacket $DHCP_OPCODE_ACK
    setHardwareType2UDPPacket $DHCP_HARDWARE_TYPE_ETHERNET
    setHardwareAddressLength2UDPPacket 6
    setHopCount2UDPPacket
    setTransactionID2UDPPacket $TransactionID
    setNumberOfSeconds2UDPPacket
    setFlagsOfSeconds2UDPPacket
    setClientIPAddress2UDPPacket $requestedIPAddress
    setYourIPAddress2UDPPacket "0.0.0.0"
    setServerIPAddress2UDPPacket "0.0.0.0"
    setGatewayIPAddress2UDPPacket "0.0.0.0"
    setClientHardwareAddress2UDPPacket $ClientHardwareAddress
    setServerHostName2UDPPacket
    setBootFilename2UDPPacket
    ##Option
    clearDHCPOptionsBuf
    setMagic2DHCPOption
    Set-Variable -Name "headpos" -Scope global -Value 4 
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "DHCP message type.",$MSG_DHCPPACK) # Option: (53) DHCP Message Type (ACK)
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Server identifier.",$ServerIdentifier) # Option: (54) DHCP Server Identifier
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "IP address lease time.","1day") # Option: (51) IP Address Lease Time
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Subnet Mask.",$SubnetMask) # Option: (1) Subnet Mask
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Router.",$Router) # Option: (3) Router
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Domain Name Server.",$DomainNameServer) # Option: (6) Domain Name Server
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Domain Name.",$DomainName) # Option: (15) Domain Name
    $headpos=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "NetBIOS over TCP/IP name server.",$NetBIOSOverTCPIPNameServer) # Option: (44) NetBIOS over TCP/IP Name Server
    $headpos=ForwardHeadPos
    setEndMark2DHCPOption
    setDHCPOption2UDPPacket $dhcpOptions
}
function replyDHCPPACK() {
    lcl_buildDHCPPACKPacket

    #Set-Variable -Name "dhcpOptions" -Scope global -Value $dhcpOptions 
    $count=0
    foreach($e in $dhcpOptions) {
        [System.Console]::Write($e + " ")
        $count += 1 
        if ($count % 16 -eq 0) { [System.Console]::WriteLine("") } 
    }
    if($count % 16 -ne 0) { [System.Console]::WriteLine("") } 

    echo("DEBUG DHCPPACK")
    echoDHCPPcakcetSend

    #send
    $b=@()
    foreach($d in $udpPacketSend) {
        $b += [Byte]::Parse(([Convert]::ToInt32($d,16)), [System.Globalization.NumberStyles]::Integer) 
    }
    $endpoint = new-object System.Net.IPEndPoint (([system.net.IPAddress]::Parse($ClientIPAddress)),68)
    $bytesSent=$udpclient.Send($b,($b.length),$endpoint)
}
# Dump UDP packet
function CMDParseOption_NotImplemented() {
    echo("Not implemented.")
}
function CMDParseOption_Pad() {
    echo("NOP(Pad).")
}
function CMDParseOption_Ascii() {
    $ret = ""
    $encoding = [system.Text.Encoding]::GetEncoding("ASCII")
    $i = getVEXTLength
    foreach($d in $dhcpOptions[($headpos+2)..($headpos+2+$i-1)]) {
        $ret = $ret + $encoding.getchars([Convert]::ToInt32($d,16))
    }
    return $ret
}
function CMDParseOption_Dump() {
    $i = getVEXTLength
    $count = 0
    foreach($d in $dhcpOptions[($headpos+2)..($headpos+2+$i-1)]) {
        [System.Console]::Write($d + " ")
        $count += 1 
        if ($count % 16 -eq 0) { [System.Console]::WriteLine("") }    
    }
    if($count % 16 -ne 0) { [System.Console]::WriteLine("") } 
}

function lcl_getDHCPOptionMessage() {
    $rawdata = $dhcpOptions[$headpos+2]
    $ret="UNKNOWN"
    switch ($rawdata) {
        "01"{ $ret=$MSG_DHCPDISCOVER }
        "02"{ $ret=$MSG_DHCPOFFER }
        "03"{ $ret=$MSG_DHCPREQUEST }
        "04"{ $ret=$MSG_DHCPDECLINE }
        "05"{ $ret=$MSG_DHCPPACK }
        "06"{ $ret=$MSG_DHCPPNCK }
        default{ $ret="UNKNOWNMESSAGE" }
    }
    return $ret
}
function CMDParseOption_DHCPMessageType() { #53 DHCP message type.
    return lcl_getDHCPOptionMessage
}
function CMDParseOption_DumpIPAddress() { #50 Requested IP Address..
    $ret =""
    $i = getVEXTLength
    foreach($d in $dhcpOptions[($headpos+2)..($headpos+2+$i-1)]) {
        $ret = $ret + [Convert]::ToInt32($d,16).ToString("d") + "."
    }
    $ret = $ret.SubString(0,$ret.length-1)
    Set-Variable -Name "requestedIPAddress" -Scope global -Value $ret # record  
    return $ret
}
function lcl_outputCodeHeader() {
    [System.Console]::Write("option $([Convert]::ToInt32($dhcpOptions[$headpos],16)) ")
}
function lcl_outputLengthHeader() {
    [System.Console]::Write("+" + (($headpos+1).ToString("00")) + $d + " Len  :")
}
function lcl_outputParamHeader() {
    [System.Console]::Write("       ")
}
function getVEXTDescription() {
    return $DHCPOptionTable[[Convert]::ToInt32($dhcpOptions[$headpos],16)][0]
}
function getVEXTLength() {
    return [Convert]::ToInt32($dhcpOptions[$headpos + 1],16)
}
function getVEXTParam() {
    return Invoke-Expression "$($DHCPOptionTable[[Convert]::ToInt32($dhcpOptions[$headpos],16)][1])"
}
function optionParseForwardHeadPos() {
    $i = getVEXTLength
    return $headpos+2+$i
}
function parseOptionBody() {
    $headpos = 4 
    while ($dhcpOptions[$headpos] -ne "FF") {
        lcl_outputCodeHeader
        echo(getVEXTDescription)
        lcl_outputParamHeader 
        echo(getVEXTParam)
        $headpos=optionParseForwardHeadPos
    }

    [System.Console]::WriteLine("--Terminated.--")
}

function echoDHCPPcakcetRecv() {
    echo ("Opcode                 " + ":" + [string]::Join(" ", $udpPacketRecv[0..0]))
    echo ("Hardware type          " + ":" + [string]::Join(" ", $udpPacketRecv[1..1]))
    echo ("Hardware address length" + ":" + [string]::Join(" ", $udpPacketRecv[2..2]))
    echo ("Hop count              " + ":" + [string]::Join(" ", $udpPacketRecv[3..3]))
    echo ("Transaction ID         " + ":" + [string]::Join(" ", $udpPacketRecv[4..7]))
    echo ("Number of seconds      " + ":" + [string]::Join(" ", $udpPacketRecv[8..9]))
    echo ("Flags                  " + ":" + [string]::Join(" ", $udpPacketRecv[10..11]))
    echo ("Client IP address      " + ":" + [string]::Join(" ", $udpPacketRecv[12..15]))
    echo ("Your IP address        " + ":" + [string]::Join(" ", $udpPacketRecv[16..19]))
    echo ("Server IP address      " + ":" + [string]::Join(" ", $udpPacketRecv[20..23]))
    echo ("Gateway IP address     " + ":" + [string]::Join(" ", $udpPacketRecv[24..27]))
    echo ("Client hardware address" + ":" + [string]::Join(" ", $udpPacketRecv[28..43])) 
    if ((lcl_checkIfAllZero $udpPacketRecv[44..107]) -eq $TRUE) {
        echo ("Server host name       " + ":" + "00 * $($udpPacketRecv[44..107].length)")
    } else {
        echo ("Server host name       " + ":" + [string]::Join(" ", $udpPacketRecv[44..107]))
    }
    if ((lcl_checkIfAllZero $udpPacketRecv[108..235]) -eq $TRUE) {
        echo ("Boot filename          " + ":" + "00 * $($udpPacketRecv[108..235].length)")
    } else {
        echo ("Boot filename          " + ":" + [string]::Join(" ", $udpPacketRecv[108..235]))
    }

    Set-Variable -Name "headpos" -Scope global -Value 4 
    parseOptionBody
}

function echoDHCPPcakcetSend() {
    echo ("Opcode                 " + ":" + [string]::Join(" ", $udpPacketSend[0..0]))
    echo ("Hardware type          " + ":" + [string]::Join(" ", $udpPacketSend[1..1]))
    echo ("Hardware address length" + ":" + [string]::Join(" ", $udpPacketSend[2..2]))
    echo ("Hop count              " + ":" + [string]::Join(" ", $udpPacketSend[3..3]))
    echo ("Transaction ID         " + ":" + [string]::Join(" ", $udpPacketSend[4..7]))
    echo ("Number of seconds      " + ":" + [string]::Join(" ", $udpPacketSend[8..9]))
    echo ("Flags                  " + ":" + [string]::Join(" ", $udpPacketSend[10..11]))
    echo ("Client IP address      " + ":" + [string]::Join(" ", $udpPacketSend[12..15]))
    echo ("Your IP address        " + ":" + [string]::Join(" ", $udpPacketSend[16..19]))
    echo ("Server IP address      " + ":" + [string]::Join(" ", $udpPacketSend[20..23]))
    echo ("Gateway IP address     " + ":" + [string]::Join(" ", $udpPacketSend[24..27]))
    echo ("Client hardware address" + ":" + [string]::Join(" ", $udpPacketSend[28..43])) 
    if ((lcl_checkIfAllZero $udpPacketSend[44..107]) -eq $TRUE) {
        echo ("Server host name       " + ":" + "00 * $($udpPacketSend[44..107].length)")
    } else {
        echo ("Server host name       " + ":" + [string]::Join(" ", $udpPacketSend[44..107]))
    }
    if ((lcl_checkIfAllZero $udpPacketRecv[108..235]) -eq $TRUE) {
        echo ("Boot filename          " + ":" + "00 * $($udpPacketRecv[108..235].length)")
    } else {
        echo ("Boot filename          " + ":" + [string]::Join(" ", $udpPacketSend[108..235]))
    }

    Set-Variable -Name "headpos" -Scope global -Value 4 
    parseOptionBody
}

function lcl_convertIPAddress($str) { #50 Requested IP Address..
    $seq = $str.split(".")
    $ret =""
    foreach($d in $seq) {
        $ret = $ret + [Convert]::ToInt32($d,16).ToString("d") + "."
    }
    $ret = $ret.SubString(0,$ret.length-1)
    return $ret
}

function IsLeasedIPAdress ($fthoct) {
    return $True; #FIXME    
}
function lcl_getIPAdressString ($fthoct) {
    $ret=""
    $ret+=($clientIPAddressStartAddress[0]).ToString($null) + "."
    $ret+=($clientIPAddressStartAddress[1]).ToString($null) + "."
    $ret+=($clientIPAddressStartAddress[2]).ToString($null) + "."
    $ret+=$i.ToString($null)
    return $ret;  
}
function lcl_findLeasableIPAddress() {
    if ($clientIPAddressStartAddress -eq $clientIPAddressEndAddress) {
        return (lcl_getIPAdressString $clientIPAddressStartAddress[3]);
    } else {
        for($i=$clientIPAddressStartAddress[3]+1;$i -le $clientIPAddressEndAddress[3];$i++) {
            if (IsLeasedIPAdress($i)) {
                return (lcl_getIPAdressString $i)
            }
        }
    }
    return "0.0.0.0" # no resource
}

function getClientIPStartAndEndAddress() {
    Write-Debug $clientIPAddressesWithBitmask
    #IPv4 only
    if ($clientIPAddressesWithBitmask.Contains("/")) {     # xxx.xxx.xxx.xxx/mm (24 <= mm <= 32)
        $a = $clientIPAddressesWithBitmask.Split("/")
        $ba = ($a[0]).split(".")
        $mask = $a[1]
        if (([Convert]::ToInt32($mask) -lt 24) -Or (([Convert]::ToInt32($mask) -gt 32))) { 
            throw "Exception : Illegal parameter(clientIPAddressesWithBitmask)" 
        }
        if ($ba.length -ne 4) { throw "Exception : Illegal parameter(clientIPAddressesWithBitmask)" }
        for($i=0;$i -lt 4;$i++) {
            if (([Convert]::ToInt32($ba[$i]) -gt 255) -Or (([Convert]::ToInt32($ba[$i]) -lt 0))) { 
                throw "Exception : Illegal parameter(clientIPAddressesWithBitmask)" 
            }
            $clientIPAddressStartAddress[$i] = $ba[$i]
        }
        $clientIPAddressStartAddress[3] = $clientIPAddressStartAddress[3] -band ((255 -shl (32 - $mask)) -band 255)

        $clientIPAddressEndAddress[0] = $clientIPAddressStartAddress[0] 
        $clientIPAddressEndAddress[1] = $clientIPAddressStartAddress[1] 
        $clientIPAddressEndAddress[2] = $clientIPAddressStartAddress[2] 
        $clientIPAddressEndAddress[3] = $clientIPAddressStartAddress[3] -bor (( 65535 -bxor (255 -shl (32 - $mask))) -band 255)

        #echo ($clientIPAddressStartAddress)
        #echo ($clientIPAddressEndAddress)
    } else {    # xxx.xxx.xxx.xxx
        $ba = ($clientIPAddressesWithBitmask).split(".")
        if ($ba.length -ne 4) { throw "Exception : Illegal parameter(clientIPAddressesWithBitmask)" }
        for($i=0;$i -lt 4;$i++) {
            if (([Convert]::ToInt32($ba[$i]) -gt 255) -Or (([Convert]::ToInt32($ba[$i]) -lt 0))) { 
                throw "Exception : Illegal parameter(clientIPAddressesWithBitmask)" 
            }
            $clientIPAddressStartAddress[$i] = $ba[$i]
        }
        $clientIPAddressEndAddress[0] = $clientIPAddressStartAddress[0] 
        $clientIPAddressEndAddress[1] = $clientIPAddressStartAddress[1] 
        $clientIPAddressEndAddress[2] = $clientIPAddressStartAddress[2] 
        $clientIPAddressEndAddress[3] = $clientIPAddressStartAddress[3]

        #echo ($clientIPAddressStartAddress)
        #echo ($clientIPAddressEndAddress)           
    }
}

function mainloop() {
    while(1) {
        $content = $udpclient.Receive([ref]$endpoint)
        $udpPacketRecv = [bitconverter]::ToString($content).split("-")
        #$dhcpOptions = $udpPacketRecv[236..299]
        for($i=0;$i -lt 64;$i++) {
            $dhcpOptions[$i] = ($udpPacketRecv[236+$i])
        }

        echo ("I recieved a BOOTP/DHCP packet-->")
        echoDHCPPcakcetRecv

        switch(CMDParseOption_DHCPMessageType) {
            $MSG_DHCPDISCOVER { 
                echo("Recieved DHCPDISCOVER message.")
                $TransactionID = ([string]::Join("", $udpPacketRecv[4..7]))
                $ClientIPAddress = lcl_findLeasableIPAddress
                $ClientHardwareAddress = ([string]::Join("", $udpPacketRecv[28..33]))
                if ($noreplymode -ne $TRUE) { replyDHCPOFFER } 
                }
            $MSG_DHCPOFFER {
                echo("Recieved DHCPOFFER message.")
                echo("Do nothing.")
            }
            $MSG_DHCPREQUEST { 
                echo("Recieved DHCPREQUEST message.")
                $TransactionID = ([string]::Join("", $udpPacketRecv[4..7]))
                $ClientIPAddress = lcl_convertIPAddress ([string]::Join(".", $udpPacketRecv[12..15]))
                Write-Debug($requestedIPAddress)
                $ClientHardwareAddress = ([string]::Join("", $udpPacketRecv[28..33]))
                if ($noreplymode -ne $TRUE) { replyDHCPPACK }
                }
            $MSG_DHCPDECLINE {
                echo("Recieved DHCPDECLINE message.")
                echo("Do nothing.")
            }
            $MSG_DHCPPACK {
                echo("Recieved DHCPPACK message.")
                echo("Do nothing.")
            }
            $MSG_DHCPPNCK{
                echo("Recieved DHCPPNCK message.")
                echo("Do nothing.")
            }
            default { echo("Do nothing.") }
        }
    }
}

getClientIPStartAndEndAddress

mainloop
