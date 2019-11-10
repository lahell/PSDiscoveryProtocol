## PSDiscoveryProtocol

Capture and parse CDP and LLDP packets on local or remote computers

### CDP and LLDP
PSDiscoveryProtocol does not return all information available in CDP and LLDP packets. If you want to know what information is available use `Export-Pcap` and open the pcap file in Wireshark or another tool with a more complete implementation.

Some vendors only send mandatory TLVs in which case this module will only return Port from captured LLDP packets.

### Installation

```PowerShell
Install-Module -Name PSDiscoveryProtocol
```

### Usage
On this page you will find a few examples of how to use this module.

For more examples please read help:
```PowerShell
Get-Help -Name Invoke-DiscoveryProtocolCapture -Full
Get-Help -Name Get-DiscoveryProtocolData -Full
Get-Help -Name Export-Pcap -Full
```

### Capture and parse LLDP on local computer

```PowerShell
$Packet = Invoke-DiscoveryProtocolCapture -Type LLDP
Get-DiscoveryProtocolData -Packet $Packet
```

#### Output
```
Model       : WS-C2960-48TT-L
Description : HR Workstation
VLAN        : 10
Port        : Fa0/1
Device      : SWITCH1.domain.example
IPAddress   : 192.0.2.10
Computer    : COMPUTER1.domain.example
Type        : LLDP
```

### Capture and parse CDP on remote computers

```PowerShell
'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture -Type CDP | Get-DiscoveryProtocolData
```

#### Output
```
Port      : FastEthernet0/1
Device    : SWITCH1.domain.example
Model     : cisco WS-C2960-48TT-L
IPAddress : 192.0.2.10
VLAN      : 10
Computer  : COMPUTER1.domain.example
Type      : CDP

Port      : FastEthernet0/2
Device    : SWITCH1.domain.example
Model     : cisco WS-C2960-48TT-L
IPAddress : 192.0.2.10
VLAN      : 20
Computer  : COMPUTER2.domain.example
Type      : CDP
```

### Capture on remote computers and export to pcap

```PowerShell
'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture | Export-Pcap -Path packets.pcap
```

### Speed up capturing in PowerShell 7

By leveraging the new `-Parallel` parameter on `ForEach-Object` we can capture simultaneously on multiple computers.

```PowerShell
#Requires -Version 7
$Packets = 'COMPUTER1', 'COMPUTER2', 'COMPUTER3' | ForEach-Object -Parallel {
    Invoke-DiscoveryProtocolCapture -ComputerName $_ | Get-DiscoveryProtocolData
}
```
