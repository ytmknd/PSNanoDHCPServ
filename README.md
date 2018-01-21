# PSNanoDHCPServ

***This script doesn't work yet.***

PSNanoDHCPServ is a very tiny and uncommonly DHCP server as a "Rescue Tool".

## Description

This server only works to send the network settings to a part of PCs into Network without any other DHCP servers.
Therefore this server *doesn't* have many functions that other servers have.
And this server *doesn't* compliant exactlry with [RFC2131](https://www.ietf.org/rfc/rfc2131.txt).

I assume that this server would used temporalily and should be terminated quickly after use(after sending the network settings to a target PC).

## Usage

    sudo pwsh ./psnanodhcpserv.ps1 -clientipaddresses 192.168.1.1-192.168.1.5 
        -subnetmask 255.255.255.0 -defaultgateway 192.168.1.254 -dnsserveraddress 8.8.8.8

- You must *run as administrator(or root).*
- Currently supports *IPv4 addresses only.*
- You can use *-noreplymode* option.

## Requirement

PowerShell 2.0 or later

## License
MIT
