## PSDiscoveryProtocol

Capture and parse CDP and LLDP packets on local or remote computers

### Installation

```PowerShell
Install-Module -Name PSDiscoveryProtocol
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
