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
$clientIPAddressStartAddress = @(0,0,0,0)   
$clientIPAddressEndAddress = @(0,0,0,0)   

# Recv
## UDP packet buffer
$udpPacketRecv = @(0) * 300
## DHCP option
$dhcpOptionsRecv = @(0) * 64
$headposRecv = 4 # skip magic 

# Send
## UDP packet buffer
$udpPacketSend = @(0) * 300
## DHCP option
$dhcpOptionsSend = @(0) * 64
$headposSend = 4 # skip magic

$port=67
$endpoint = new-object System.Net.IPEndPoint ([IPAddress]::Any,$port)
$udpclient = new-Object System.Net.Sockets.UdpClient $port
$udpclient.EnableBroadcast = true;

# Recv
set-variable -name CMD_PARSE_NOT_IMPLEMENTED -value "CMDParseOption_NotImplemented" -option constant
set-variable -name CMD_PARSE_OPTION_DUMP -value "CMDParseOption_Dump" -option constant
# Send
set-variable -name CMD_GET_NOT_IMPLEMENTED -value "getCMD_NotImplemented" -option constant
set-variable -name CMD_GET_OPTIONSEQ_IPV4 -value "getCMDAndIPv4Address4DHCPOption" -option constant
set-variable -name CMD_GET_OPTIONSEQ_ASCII -value "getCMDAndAscii4DHCPOption" -option constant
$DHCPOptionTable=@(
<#0 0#> @("Pad.","CMDParseOption_Pad",$CMD_PARSE_NOT_IMPLEMENTED),
<#1 4#> @("Subnet Mask.",$CMD_PARSE_OPTION_DUMP,"getSubnetMask4DHCPOption"),
<#2 4#> @("Time Offset (deprecated).",$CMD_PARSE_NOT_IMPLEMENTED),
<#3 4+#> @("Router.",$CMD_PARSE_NOT_IMPLEMENTED,$CMD_GET_OPTIONSEQ_IPV4),
<#4 4+#> @("Time Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#5 4+#> @("Name Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#6 4+#> @("Domain Name Server.",$CMD_PARSE_NOT_IMPLEMENTED,$CMD_GET_OPTIONSEQ_IPV4),
<#7 4+#> @("Log Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#8 4+#> @("Quote Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#9 4+#> @("LPR Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#10 4+#> @("Impress Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#11 4+#> @("Resource Location Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#12 1+#> @("Host Name.","CMDParseOption_Ascii",$CMD_PARSE_NOT_IMPLEMENTED),
<#13 2#> @("Boot File Size.",$CMD_PARSE_NOT_IMPLEMENTED),
<#14 1+#> @("Merit Dump File.",$CMD_PARSE_NOT_IMPLEMENTED),
<#15 1+#> @("Domain Name.",$CMD_PARSE_NOT_IMPLEMENTED,$CMD_GET_OPTIONSEQ_ASCII),
<#16 4#> @("Swap Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#17 1+#> @("Root Path.",$CMD_PARSE_NOT_IMPLEMENTED),
<#18 1+#> @("Extensions Path.",$CMD_PARSE_NOT_IMPLEMENTED),
<#19 1#> @("IP Forwarding enable/disable.",$CMD_PARSE_NOT_IMPLEMENTED),
<#20 1#> @("Non-local Source Routing enable/disable.",$CMD_PARSE_NOT_IMPLEMENTED),
<#21 8+#> @("Policy Filter.",$CMD_PARSE_NOT_IMPLEMENTED),
<#22 2#> @("Maximum Datagram Reassembly Size.",$CMD_PARSE_NOT_IMPLEMENTED),
<#23 1#> @("Default IP Time-to-live.",$CMD_PARSE_NOT_IMPLEMENTED),
<#24 4#> @("Path MTU Aging Timeout.",$CMD_PARSE_NOT_IMPLEMENTED),
<#25 2+#> @("Path MTU Plateau Table.",$CMD_PARSE_NOT_IMPLEMENTED),
<#26 2#> @("Interface MTU.",$CMD_PARSE_NOT_IMPLEMENTED),
<#27 1#> @("All Subnets are Local.",$CMD_PARSE_NOT_IMPLEMENTED),
<#28 4#> @("Broadcast Address.",$CMD_PARSE_NOT_IMPLEMENTED),
<#29 1#> @("Perform Mask Discovery.",$CMD_PARSE_NOT_IMPLEMENTED),
<#30 1#> @("Mask supplier.",$CMD_PARSE_NOT_IMPLEMENTED),
<#31 1#> @("Perform router discovery.",$CMD_PARSE_NOT_IMPLEMENTED),
<#32 4#> @("Router solicitation address.",$CMD_PARSE_NOT_IMPLEMENTED),
<#33 8+#> @("Static routing table.",$CMD_PARSE_NOT_IMPLEMENTED),
<#34 1#> @("Trailer encapsulation.",$CMD_PARSE_NOT_IMPLEMENTED),
<#35 4#> @("ARP cache timeout.",$CMD_PARSE_NOT_IMPLEMENTED),
<#36 1#> @("Ethernet encapsulation.",$CMD_PARSE_NOT_IMPLEMENTED),
<#37 1#> @("Default TCP TTL.",$CMD_PARSE_NOT_IMPLEMENTED),
<#38 4#> @("TCP keepalive interval.",$CMD_PARSE_NOT_IMPLEMENTED),
<#39 1#> @("TCP keepalive garbage.",$CMD_PARSE_NOT_IMPLEMENTED),
<#40 1+#> @("Network Information Service Domain.",$CMD_PARSE_NOT_IMPLEMENTED),
<#41 4+#> @("Network Information Servers.",$CMD_PARSE_NOT_IMPLEMENTED),
<#42 4+#> @("NTP servers.",$CMD_PARSE_NOT_IMPLEMENTED),
<#43 1+#> @("Vendor specific information.",$CMD_PARSE_NOT_IMPLEMENTED),
<#44 4+#> @("NetBIOS over TCP/IP name server.",$CMD_PARSE_NOT_IMPLEMENTED,$CMD_GET_OPTIONSEQ_IPV4),
<#45 4+#> @("NetBIOS over TCP/IP Datagram Distribution Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#46 1#> @("NetBIOS over TCP/IP Node Type.",$CMD_PARSE_NOT_IMPLEMENTED),
<#47 1+#> @("NetBIOS over TCP/IP Scope.",$CMD_PARSE_NOT_IMPLEMENTED),
<#48 4+#> @("X Window System Font Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#49 4+#> @("X Window System Display Manager.",$CMD_PARSE_NOT_IMPLEMENTED),
<#50 4#> @("Requested IP Address.","CMDParseOption_RequestedIPAddress"),
<#51 4#> @("IP address lease time.",$CMD_PARSE_OPTION_DUMP,"getIPAddressLeaseTime4DHCPOption"),
<#52 1#> @("Option overload.",$CMD_PARSE_NOT_IMPLEMENTED),
<#53 1#> @("DHCP message type.","CMDParseOption_DHCPMessageType","getDHCPMessageType4DHCPOption"),
<#54 4#> @("Server identifier.",$CMD_PARSE_NOT_IMPLEMENTED,"getServerIdentifier4DHCPOption"),
<#55 1+#> @("Parameter request list.",$CMD_PARSE_OPTION_DUMP),
<#56 1+#> @("Message.",$CMD_PARSE_NOT_IMPLEMENTED),
<#57 2#> @("Maximum DHCP message size.",$CMD_PARSE_OPTION_DUMP),
<#58 4#> @("Renew time value.",$CMD_PARSE_NOT_IMPLEMENTED),
<#59 4#> @("Rebinding time value.",$CMD_PARSE_NOT_IMPLEMENTED),
<#60 1+#> @("Class-identifier.",$CMD_PARSE_NOT_IMPLEMENTED),
<#61 2+#> @("Client-identifier.",$CMD_PARSE_OPTION_DUMP),
<#62 1 to 255#> @("NetWare/IP Domain Name.",$CMD_PARSE_NOT_IMPLEMENTED),
<#63 #> @("NetWare/IP information.",$CMD_PARSE_NOT_IMPLEMENTED),
<#64 1+#> @("Network Information Service+ Domain.",$CMD_PARSE_NOT_IMPLEMENTED),
<#65 4+#> @("Network Information Service+ Servers.",$CMD_PARSE_NOT_IMPLEMENTED),
<#66 1+#> @("TFTP server name.",$CMD_PARSE_NOT_IMPLEMENTED),
<#67 1+#> @("Bootfile name.",$CMD_PARSE_NOT_IMPLEMENTED),
<#68 0+#> @("Mobile IP Home Agent.",$CMD_PARSE_NOT_IMPLEMENTED),
<#69 4+#> @("Simple Mail Transport Protocol Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#70 4+#> @("Post Office Protocol Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#71 4+#> @("Network News Transport Protocol Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#72 4+#> @("Default World Wide Web Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#73 4+#> @("Default Finger Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#74 4+#> @("Default Internet Relay Chat Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#75 4+#> @("StreetTalk Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#76 4+#> @("StreetTalk Directory Assistance Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#77 Variable.#> @("User Class Information.",$CMD_PARSE_NOT_IMPLEMENTED),
<#78 Variable.#> @("SLP Directory Agent.",$CMD_PARSE_NOT_IMPLEMENTED),
<#79 Variable.#> @("SLP Service Scope.",$CMD_PARSE_NOT_IMPLEMENTED),
<#80 0#> @("Rapid Commit.",$CMD_PARSE_NOT_IMPLEMENTED),
<#81 4+#> @("FQDN, Fully Qualified Domain Name.",$CMD_PARSE_NOT_IMPLEMENTED),
<#82 Variable.#> @("Relay Agent Information.",$CMD_PARSE_NOT_IMPLEMENTED),
<#83 14+#> @("Internet Storage Name Service.",$CMD_PARSE_NOT_IMPLEMENTED),
<#84 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#85 Variable.#> @("NDS servers.",$CMD_PARSE_NOT_IMPLEMENTED),
<#86 Variable.#> @("NDS tree name.",$CMD_PARSE_NOT_IMPLEMENTED),
<#87 Variable.#> @("NDS context.",$CMD_PARSE_NOT_IMPLEMENTED),	
<#88 Variable.#> @("BCMCS Controller Domain Name list.",$CMD_PARSE_NOT_IMPLEMENTED),
<#89 4+#> @("BCMCS Controller IPv4 address list.",$CMD_PARSE_NOT_IMPLEMENTED),
<#90 Variable.#> @("Authentication.",$CMD_PARSE_NOT_IMPLEMENTED),
<#91 4#> @("client-last-transaction-time.",$CMD_PARSE_NOT_IMPLEMENTED),
<#92 4n#> @("associated-ip.",$CMD_PARSE_NOT_IMPLEMENTED),
<#93 Variable.#> @("Client System Architecture Type.",$CMD_PARSE_NOT_IMPLEMENTED),
<#94 Variable.#> @("Client Network Interface Identifier.",$CMD_PARSE_NOT_IMPLEMENTED),
<#95 Variable.#> @("LDAP, Lightweight Directory Access Protocol.",$CMD_PARSE_NOT_IMPLEMENTED),
<#96 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#97 Variable.#> @("Client Machine Identifier.",$CMD_PARSE_NOT_IMPLEMENTED),
<#98 #> @("Open Groups User Authentication.",$CMD_PARSE_NOT_IMPLEMENTED),
<#99 #> @("GEOCONF_CIVIC.",$CMD_PARSE_NOT_IMPLEMENTED),
<#100 #> @("IEEE 1003.1 TZ String.",$CMD_PARSE_NOT_IMPLEMENTED),
<#101 #> @("Reference to the TZ Database.",$CMD_PARSE_NOT_IMPLEMENTED),
<#102 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#103 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#104 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#105 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#106 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#107 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#108 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#109 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#110 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#111 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#112 Variable.#> @("NetInfo Parent Server Address.",$CMD_PARSE_NOT_IMPLEMENTED),
<#113 Variable.#> @("NetInfo Parent Server Tag.",$CMD_PARSE_NOT_IMPLEMENTED),
<#114 Variable.#> @("URL.",$CMD_PARSE_NOT_IMPLEMENTED),
<#115 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#116 1#> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#117 2+#> @("Name Service Search.",$CMD_PARSE_NOT_IMPLEMENTED),
<#118 4#> @("Subnet Selection.",$CMD_PARSE_NOT_IMPLEMENTED),
<#119 Variable#> @("DNS domain search list.",$CMD_PARSE_NOT_IMPLEMENTED),
<#120 Variable#> @("SIP Servers DHCP Option.",$CMD_PARSE_NOT_IMPLEMENTED),
<#121 5+#> @("Classless Static Route Option.",$CMD_PARSE_NOT_IMPLEMENTED),
<#122 Variable#> @("CCC, CableLabs Client Configuration.",$CMD_PARSE_NOT_IMPLEMENTED),
<#123 16#> @("GeoConf.",$CMD_PARSE_NOT_IMPLEMENTED),
<#124 #> @("Vendor-Identifying Vendor Class.",$CMD_PARSE_NOT_IMPLEMENTED),
<#125 #> @("Vendor-Identifying Vendor-Specific.",$CMD_PARSE_NOT_IMPLEMENTED),
<#126 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#127 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#128 #> @("TFTP Server IP address.",$CMD_PARSE_NOT_IMPLEMENTED),
<#129 #> @("Call Server IP address.",$CMD_PARSE_NOT_IMPLEMENTED),
<#130 #> @("Discrimination string.",$CMD_PARSE_NOT_IMPLEMENTED),
<#131 #> @("Remote statistics server IP address.",$CMD_PARSE_NOT_IMPLEMENTED),
<#132 #> @("802.1P VLAN ID.",$CMD_PARSE_NOT_IMPLEMENTED),
<#133 #> @("802.1Q L2 Priority.",$CMD_PARSE_NOT_IMPLEMENTED),
<#134 #> @("Diffserv Code Point.",$CMD_PARSE_NOT_IMPLEMENTED),
<#135 #> @("HTTP Proxy for phone-specific applications.",$CMD_PARSE_NOT_IMPLEMENTED),
<#136 4+#> @("PANA Authentication Agent.",$CMD_PARSE_NOT_IMPLEMENTED),
<#137 variable#> @("LoST Server.",$CMD_PARSE_NOT_IMPLEMENTED),
<#138 #> @("CAPWAP Access Controller addresses.",$CMD_PARSE_NOT_IMPLEMENTED),
<#139 #> @("OPTION-IPv4_Address-MoS.",$CMD_PARSE_NOT_IMPLEMENTED),
<#140 #> @("OPTION-IPv4_FQDN-MoS.",$CMD_PARSE_NOT_IMPLEMENTED),
<#141 2+#> @("SIP UA Configuration Service Domains.",$CMD_PARSE_NOT_IMPLEMENTED),
<#142 #> @("OPTION-IPv4_Address-ANDSF.",$CMD_PARSE_NOT_IMPLEMENTED),
<#143 #> @("OPTION-IPv6_Address-ANDSF.",$CMD_PARSE_NOT_IMPLEMENTED),
<#144 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#145 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#146 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#147 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#148 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#149 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#150 #> @("TFTP server address/Etherboot.",$CMD_PARSE_NOT_IMPLEMENTED),
<#151 #> @("status-code.",$CMD_PARSE_NOT_IMPLEMENTED),
<#152 #> @("base-time.",$CMD_PARSE_NOT_IMPLEMENTED),
<#153 #> @("start-time-of-state.",$CMD_PARSE_NOT_IMPLEMENTED),
<#154 #> @("query-start-time.",$CMD_PARSE_NOT_IMPLEMENTED),
<#155 #> @("query-end-time.",$CMD_PARSE_NOT_IMPLEMENTED),
<#156 #> @("dhcp-state.",$CMD_PARSE_NOT_IMPLEMENTED),
<#157 #> @("data-source.",$CMD_PARSE_NOT_IMPLEMENTED),
<#158 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#160 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#161 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#162 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#163 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#164 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#165 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#166 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#167 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#168 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#169 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#170 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#171 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#172 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#173 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#174 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#175 #> @("Etherboot.",$CMD_PARSE_NOT_IMPLEMENTED),
<#176 #> @("IP Telephone.",$CMD_PARSE_NOT_IMPLEMENTED),
<#177 #> @("Etherboot./PacketCable and CableHome.",$CMD_PARSE_NOT_IMPLEMENTED),
<#178 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#179 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#180 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#181 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#182 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#183 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#184 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#185 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#186 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#187 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#188 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#189 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#190 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#191 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#192 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#193 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#194 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#195 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#196 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#197 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#198 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#199 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#200 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#201 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#202 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#203 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#204 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#205 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#206 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#207 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#208 #> @("pxelinux.magic (string) = F1:00:74:7E (241.0.116.126).",$CMD_PARSE_NOT_IMPLEMENTED),
<#209 #> @("pxelinux.configfile (text).",$CMD_PARSE_NOT_IMPLEMENTED),
<#210 #> @("pxelinux.pathprefix (text).",$CMD_PARSE_NOT_IMPLEMENTED),
<#211 #> @("pxelinux.reboottime (unsigned integer 32 bits).",$CMD_PARSE_NOT_IMPLEMENTED),
<#212 18+#> @("OPTION_6RD.",$CMD_PARSE_NOT_IMPLEMENTED),
<#213 #> @("OPTION_V4_ACCESS_DOMAIN.",$CMD_PARSE_NOT_IMPLEMENTED),
<#214 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#215 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#216 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#217 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#218 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#219 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#220 #> @("Subnet Allocation.",$CMD_PARSE_NOT_IMPLEMENTED),
<#221 1+#> @("Virtual Subnet Selection.",$CMD_PARSE_NOT_IMPLEMENTED),
<#222 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#223 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#224 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#225 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#226 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#227 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#228 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#229 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#230 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#231 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#232 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#233 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#234 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#235 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#236 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#237 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#238 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#239 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#240 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#241 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#242 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#243 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#244 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#245 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#246 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#247 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#248 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#249 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#250 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#251 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#252 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#253 #> @("  ",$CMD_PARSE_NOT_IMPLEMENTED),
<#254 #> @("Private use.",$CMD_PARSE_NOT_IMPLEMENTED),
<#255 0#> @("End.",$CMD_PARSE_NOT_IMPLEMENTED)
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
    $dhcpOptionsSend[0] = "63"
    $dhcpOptionsSend[1] = "82"
    $dhcpOptionsSend[2] = "53"
    $dhcpOptionsSend[3] = "63"
}
function setCodeAndOption2DHCPOption($data) { 
    for($i=0;$i -lt $data.length;$i++) {
        $dhcpOptionsSend[($headposSend + $i)] = $data[$i]
    }
}
function setEndMark2DHCPOption() { 
    $dhcpOptionsSend[$headposSend] = "FF" 
}
function lcl_getVEXTLength() {
    #Write-Debug "$($dhcpOptionsSend[$headposSend + 1])"
    return [Convert]::ToInt32(($dhcpOptionsSend[$headposSend + 1]), 16)
}
function ForwardHeadPos() {
    $i = lcl_getVEXTLength
    return $headposSend+2+$i
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
    setMagic2DHCPOption
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "DHCP message type.",$MSG_DHCPOFFER) # Option: (53) DHCP Message Type (OFFER)
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Server identifier.",$ServerIdentifier) # Option: (54) DHCP Server Identifier
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "IP address lease time.","1day") # Option: (51) IP Address Lease Time
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Subnet Mask.",$SubnetMask) # Option: (1) Subnet Mask
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Router.",$Router) # Option: (3) Router
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Domain Name Server.","192.168.10.1") # Option: (6) Domain Name Server
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Domain Name.",$DomainNameServer) # Option: (15) Domain Name
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "NetBIOS over TCP/IP name server.",$NetBIOSOverTCPIPNameServer) # Option: (44) NetBIOS over TCP/IP Name Server
    $headposSend=ForwardHeadPos
    setEndMark2DHCPOption
    setDHCPOption2UDPPacket $dhcpOptionsSend

    Write-Debug("DEBUG DHCPOFFER")
    echoDHCPPcakcet($udpPacketSend)

    #send
    $aStr = ""
    $encoding = [system.Text.Encoding]::GetEncoding("ASCII")
    foreach($d in $udpPacketSend) {
        $aStr = $aStr + $encoding.getchars([Convert]::ToInt32($d,16))
    }
    $b=[Text.Encoding]::ASCII.GetBytes($aStr)
    #Write-Debug("DEBUG $($ClientIPAddress)")
    $endpoint = new-object System.Net.IPEndPoint (([system.net.IPAddress]::Parse($ClientIPAddress)),68)
    $bytesSent=$udpclient.Send($b,($b.length),$endpoint)
}
function replyDHCPOFFER() {
    lcl_buildDHCPOFFERPacket
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
    setClientIPAddress2UDPPacket $ClientIPAddress
    setYourIPAddress2UDPPacket "0.0.0.0"
    setServerIPAddress2UDPPacket "0.0.0.0"
    setGatewayIPAddress2UDPPacket "0.0.0.0"
    setClientHardwareAddress2UDPPacket $ClientHardwareAddress
    setServerHostName2UDPPacket
    setBootFilename2UDPPacket
    ##Option
    setMagic2DHCPOption
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "DHCP message type.",$MSG_DHCPPACK) # Option: (53) DHCP Message Type (ACK)
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Server identifier.",$ServerIdentifier) # Option: (54) DHCP Server Identifier
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "IP address lease time.","1day") # Option: (51) IP Address Lease Time
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Subnet Mask.",$SubnetMask) # Option: (1) Subnet Mask
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Router.",$Router) # Option: (3) Router
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Domain Name Server.",$DomainNameServer) # Option: (6) Domain Name Server
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Domain Name.",$DomainName) # Option: (15) Domain Name
    $headposSend=ForwardHeadPos
    setCodeAndOption2DHCPOption (getOptionSeq4DHCPOption "Domain Name Server.",$NetBIOSOverTCPIPNameServer) # Option: (44) NetBIOS over TCP/IP Name Server
    $headposSend=ForwardHeadPos
    setEndMark2DHCPOption
    setDHCPOption2UDPPacket $dhcpOptionsSend

    echo("DEBUG DHCPPACK")
    echoDHCPPcakcet($udpPacketSend)

    #send
    $aStr = ""
    $encoding = [system.Text.Encoding]::GetEncoding("ASCII")
    foreach($d in $udpPacketSend) {
        $aStr = $aStr + $encoding.getchars([Convert]::ToInt32($d,16))
    }
    $b=[Text.Encoding]::ASCII.GetBytes($aStr)
    #Write-Debug("DEBUG $($ClientIPAddress)")
    $endpoint = new-object System.Net.IPEndPoint (([system.net.IPAddress]::Parse($ClientIPAddress)),68)
    $bytesSent=$udpclient.Send($b,($b.length),$endpoint)
}
function replyDHCPPACK() {
    lcl_buildDHCPPACKPacket
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
    foreach($d in $dhcpOptionsRecv[($headposRecv+2)..($headposRecv+2+$i-1)]) {
        $ret = $ret + $encoding.getchars([Convert]::ToInt32($d,16))
    }
    return $ret
}
function CMDParseOption_Dump() {
    $i = getVEXTLength
    $count = 0
    foreach($d in $dhcpOptionsRecv[($headposRecv+2)..($headposRecv+2+$i-1)]) {
        [System.Console]::Write($d + " ")
        $count += 1 
        if ($count % 16 -eq 0) { [System.Console]::WriteLine("") }    
    }
    if($count % 16 -ne 0) { [System.Console]::WriteLine("") } 
}

function lcl_getDHCPOptionMessage() {
    $rawdata = $dhcpOptionsRecv[$headposRecv+2]
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
function CMDParseOption_RequestedIPAddress() { #50 Requested IP Address..
    $ret =""
    $i = getVEXTLength
    foreach($d in $dhcpOptionsRecv[($headposRecv+2)..($headposRecv+2+$i-1)]) {
        $ret = $ret + [Convert]::ToInt32($d,16).ToString("d3") + "."
    }
    return $ret
}
function lcl_outputCodeHeader() {
    [System.Console]::Write("option $([Convert]::ToInt32($dhcpOptionsRecv[$headposRecv],16)) ")
}
function lcl_outputLengthHeader() {
    [System.Console]::Write("+" + (($headposRecv+1).ToString("00")) + $d + " Len  :")
}
function lcl_outputParamHeader() {
    [System.Console]::Write("       ")
}
function getVEXTDescription() {
    return $DHCPOptionTable[[Convert]::ToInt32($dhcpOptionsRecv[$headposRecv],16)][0]
}
function getVEXTLength() {
    return [Convert]::ToInt32($dhcpOptionsRecv[$headposRecv + 1])
}
function getVEXTParam() {
    return Invoke-Expression "$($DHCPOptionTable[[Convert]::ToInt32($dhcpOptionsRecv[$headposRecv],16)][1])"
}
function optionParseForwardHeadPos() {
    $i = getVEXTLength
    return $headposRecv+2+$i
}
function parseOptionBodyRecv() {
    $headposRecv=4
    while ($dhcpOptionsRecv[$headposRecv] -ne "FF") {
        lcl_outputCodeHeader
        echo(getVEXTDescription)
        lcl_outputParamHeader 
        echo(getVEXTParam)
        $headposRecv=optionParseForwardHeadPos
    }

    [System.Console]::WriteLine("--Terminated.--")
}

function echoDHCPPcakcet() {
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

    parseOptionBodyRecv 
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

function lcl_findLeasableIPAddress() {
    return "192.168.10.5" # FIXME
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
        $dhcpOptionsRecv = $udpPacketRecv[236..299]

        echo ("I recieved a BOOTP/DHCP packet-->")
        echoDHCPPcakcet

        switch(CMDParseOption_DHCPMessageType) {
            $MSG_DHCPDISCOVER { 
                echo("Recieved DHCPDISCOVER message.")
                $TransactionID = ([string]::Join("", $udpPacketRecv[4..7]))
                $ClientIPAddress = lcl_findLeasableIPAddress
                $ClientHardwareAddress = ([string]::Join("", $udpPacketRecv[28..33]))
                if ($noreplymode -ne $TRUE) { replyDHCPOFFER } 
                }
            $MSG_DHCPREQUEST { 
                echo("Recieved DHCPREQUEST message.")
                $TransactionID = ([string]::Join("", $udpPacketRecv[4..7]))
                $ClientIPAddress = lcl_convertIPAddress ([string]::Join(".", $udpPacketRecv[12..15]))
                $ClientHardwareAddress = ([string]::Join("", $udpPacketRecv[28..33]))
                if ($noreplymode -ne $TRUE) { replyDHCPPACK }
                }
            default { echo("Do nothing.")}
        }
    }
}

getClientIPStartAndEndAddress

mainloop
