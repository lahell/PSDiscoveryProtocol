CaptureCDP
==========

Capture and parse CDP packets on local or remote computers

### Capture and parse on local computer

```PowerShell
$Packet = Capture-CDPPacket
Parse-CDPPacket -Packet $Packet
```

#### Output
```
Port      : FastEthernet0/1 
Device    : SWITCH1.domain.example 
Model     : cisco WS-C2960-48TT-L 
IPAddress : 192.0.2.10
VLAN      : 10
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
