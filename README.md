## PSDiscoveryProtocol

Capture and parse CDP and LLDP packets on local or remote computers

### Capture and parse on local computer

```PowerShell
$Packet = Capture-LLDPPacket
Parse-LLDPPacket -Packet $Packet
```

#### Output
```
Model       : WS-C2960-48TT-L 
Description : HR Workstation
VLAN        : 10
Port        : Fa0/1
Device      : SWITCH1.domain.example 
IPAddress   : 192.0.2.10
```

### Capture and parse on remote computers

```PowerShell
'COMPUTER1', 'COMPUTER2' | Capture-CDPPacket | Parse-CDPPacket
```

#### Output
```
Port      : FastEthernet0/1 
Device    : SWITCH1.domain.example 
Model     : cisco WS-C2960-48TT-L 
IPAddress : 192.0.2.10
VLAN      : 10

Port      : FastEthernet0/2 
Device    : SWITCH1.domain.example 
Model     : cisco WS-C2960-48TT-L 
IPAddress : 192.0.2.10
VLAN      : 20
```
