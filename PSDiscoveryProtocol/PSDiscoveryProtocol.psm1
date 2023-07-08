#region classes
class DiscoveryProtocolPacket {
    [string]$MachineName
    [datetime]$TimeCreated
    [int]$FragmentSize
    [byte[]]$Fragment
    [int]$MiniportIfIndex
    [string]$Connection
    [string]$Interface

    DiscoveryProtocolPacket([PSCustomObject]$WinEvent) {
        $this.MachineName = $WinEvent.MachineName
        $this.TimeCreated = $WinEvent.TimeCreated
        $this.FragmentSize = $WinEvent.FragmentSize
        $this.Fragment = $WinEvent.Fragment
        $this.MiniportIfIndex = $WinEvent.MiniportIfIndex
        $this.Connection = $WinEvent.Connection
        $this.Interface = $WinEvent.Interface

        Add-Member -InputObject $this -MemberType ScriptProperty -Name IsDiscoveryProtocolPacket -Value {
            if (
                [UInt16]0x2000 -eq [BitConverter]::ToUInt16($this.Fragment[21..20], 0) -or
                [UInt16]0x88CC -eq [BitConverter]::ToUInt16($this.Fragment[13..12], 0)
            ) { return [bool]$true } else { return [bool]$false }
        }

        Add-Member -InputObject $this -MemberType ScriptProperty -Name DiscoveryProtocolType -Value {
            if ([UInt16]0x2000 -eq [BitConverter]::ToUInt16($this.Fragment[21..20], 0)) {
                return [string]'CDP'
            }
            elseif ([UInt16]0x88CC -eq [BitConverter]::ToUInt16($this.Fragment[13..12], 0)) {
                return [string]'LLDP'
            }
            else {
                return [string]::Empty
            }
        }

        Add-Member -InputObject $this -MemberType ScriptProperty -Name SourceAddress -Value {
            [PhysicalAddress]::new($this.Fragment[6..11]).ToString()
        }
    }
}
#endregion

#region function Invoke-DiscoveryProtocolCapture
function Invoke-DiscoveryProtocolCapture {

    <#

.SYNOPSIS

    Capture CDP or LLDP packets on local or remote computers

.DESCRIPTION

    Capture discovery protocol packets on local or remote computers. This function will start a packet capture and save the
    captured packets in a temporary ETL file. Only the first discovery protocol packet in the ETL file will be returned.

    Cisco devices will by default send CDP announcements every 60 seconds. Default interval for LLDP packets is 30 seconds.

    Requires elevation (Run as Administrator) for local capture.
    WinRM and PowerShell remoting must be enabled on target computer for remote capture.

.PARAMETER ComputerName

    Specifies one or more computers on which to capture packets. Defaults to $env:COMPUTERNAME.

    If specified, remote capture is assumed and therefore WinRM must be enabled on target.

.PARAMETER Duration

    Specifies the duration for which the discovery protocol packets are captured, in seconds.

    If Type is LLDP, Duration defaults to 32. If Type is CDP or omitted, Duration defaults to 62.

.PARAMETER Type

    Specifies what type of packet to capture, CDP or LLDP. If omitted, both types will be captured,
    but only the first one will be returned.

    If Type is LLDP, Duration defaults to 32. If Type is CDP or omitted, Duration defaults to 62.

.PARAMETER NoCleanup

    If specified, the ETL file will not be deleted from %TEMP%.

.PARAMETER Force

    If specified, any existing NetEventSession will be removed.

.PARAMETER Credential

    Use this with remote capture if current user do not have administrative privileges on the target computer.

.OUTPUTS

    DiscoveryProtocolPacket

.EXAMPLE

    PS C:\> $Packet = Invoke-DiscoveryProtocolCapture -Type CDP -Duration 60
    PS C:\> Get-DiscoveryProtocolData -Packet $Packet

    Port      : FastEthernet0/1
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 10
    Computer  : COMPUTER1
    Type      : CDP

.EXAMPLE

    PS C:\> Invoke-DiscoveryProtocolCapture -Computer COMPUTER1 | Get-DiscoveryProtocolData

    Port      : FastEthernet0/1
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 10
    Computer  : COMPUTER1
    Type      : CDP

.EXAMPLE

    PS C:\> 'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture | Get-DiscoveryProtocolData

    Port      : FastEthernet0/1
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 10
    Computer  : COMPUTER1
    Type      : CDP

    Port      : FastEthernet0/2
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 20
    Computer  : COMPUTER2
    Type      : CDP

#>

    [CmdletBinding(DefaultParametersetName = 'LocalCapture')]
    [OutputType('DiscoveryProtocolPacket')]
    [Alias('Capture-CDPPacket', 'Capture-LLDPPacket')]
    param(
        [Parameter(ParameterSetName = 'RemoteCapture',
            Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Alias('CN', 'Computer')]
        [String[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(ParameterSetName = 'LocalCapture',
            Position = 0)]
        [Parameter(ParameterSetName = 'RemoteCapture',
            Position = 1)]
        [Int16]$Duration = $(if ($Type -eq 'LLDP') { 32 } else { 62 }),

        [Parameter(ParameterSetName = 'LocalCapture',
            Position = 1)]
        [Parameter(ParameterSetName = 'RemoteCapture',
            Position = 2)]
        [ValidateSet('CDP', 'LLDP')]
        [String]$Type,

        [Parameter(ParameterSetName = 'RemoteCapture')]
        [ValidateNotNull()]
        [System.Management.Automation.Credential()]
        [PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter()]
        [switch]$NoCleanup,

        [Parameter()]
        [switch]$Force
    )

    begin {
        if ($PSCmdlet.ParameterSetName -eq 'LocalCapture') {
            $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $Principal = New-Object Security.Principal.WindowsPrincipal $Identity
            if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
                throw 'Invoke-DiscoveryProtocolCapture requires elevation. Please run PowerShell as administrator.'
            }
        }

        if ($MyInvocation.InvocationName -ne $MyInvocation.MyCommand) {
            if ($MyInvocation.InvocationName -eq 'Capture-CDPPacket') { $Type = 'CDP' }
            if ($MyInvocation.InvocationName -eq 'Capture-LLDPPacket') { $Type = 'LLDP' }
            $Warning = '{0} has been deprecated, please use {1}' -f $MyInvocation.InvocationName, $MyInvocation.MyCommand
            Write-Warning $Warning
        }
    }

    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "ParameterSetName: $($PSCmdlet.ParameterSetName)"
            Write-Verbose "TargetComputer: $Computer"

            if ($PSCmdlet.ParameterSetName -eq 'LocalCapture') {
                $CimSession = @{}
                $PSSession = @{}
            }
            else {
                $PSCredential = @{}
                if ($PSBoundParameters.ContainsKey('Credential')) {
                    $PSCredential.Add('Credential', $Credential)
                }

                try {
                    $CimSession = @{
                        CimSession = New-CimSession -ComputerName $Computer -ErrorAction Stop @PSCredential
                    }
                }
                catch [Microsoft.Management.Infrastructure.CimException] {
                    if ($_.CategoryInfo.Category -eq 'PermissionDenied') {
                        Write-Warning "Access Denied on $Computer. You can try to connect using -Credential."
                    }
                    elseif ($_.CategoryInfo.Category -eq 'ConnectionError') {
                        Write-Warning "Unable to create CimSession. Please make sure WinRM and PSRemoting is enabled on $Computer."
                    }
                    else {
                        Write-Error -ErrorRecord $_
                    }
                    continue
                }
                catch {
                    Write-Error -ErrorRecord $_
                    continue
                }

                try {
                    $PSSession = @{
                        Session = New-PSSession -ComputerName $Computer -ErrorAction Stop @PSCredential
                    }
                }
                catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
                    if ($_.Exception.ErrorCode -eq 5) {
                        Write-Warning "Access Denied on $Computer. You can try to connect using -Credential."
                    }
                    elseif ($_.Exception.ErrorCode -eq -2144108526) {
                        Write-Warning "Unable to create CimSession. Please make sure WinRM and PSRemoting is enabled on $Computer."
                    }
                    else {
                        Write-Error -ErrorRecord $_
                    }
                    continue
                }
                catch {
                    Write-Error -ErrorRecord $_
                    continue
                }
            }

            $ETLFilePath = Invoke-Command @PSSession -ScriptBlock {
                $TempFile = New-TemporaryFile
                $ETLFile = Rename-Item -Path $TempFile.FullName -NewName $TempFile.FullName.Replace('.tmp', '.etl') -PassThru
                $ETLFile.FullName
            }

            Write-Verbose "ETLFilePath: $ETLFilePath"

            $Adapters = Get-NetAdapter @CimSession |
            Where-Object { $_.Status -eq 'Up' -and $_.InterfaceType -eq 6 } |
            Select-Object Name, MacAddress, InterfaceDescription, InterfaceIndex

            if ($Adapters) {
                $MACAddresses = $Adapters.MacAddress.ForEach({ [PhysicalAddress]::Parse($_).ToString() })
                $SessionName = 'Capture-{0}' -f (Get-Date).ToString('s')

                if ($Force.IsPresent) {
                    Get-NetEventSession @CimSession | ForEach-Object {
                        if ($_.SessionStatus -eq 'Running') {
                            $_ | Stop-NetEventSession @CimSession
                        }
                        $_ | Remove-NetEventSession @CimSession
                    }
                }

                try {
                    New-NetEventSession -Name $SessionName -LocalFilePath $ETLFilePath -CaptureMode SaveToFile @CimSession -ErrorAction Stop | Out-Null
                }
                catch [Microsoft.Management.Infrastructure.CimException] {
                    if ($_.Exception.NativeErrorCode -eq 'AlreadyExists') {
                        $Message = "Another NetEventSession already exists. Run Invoke-DiscoveryProtocolCapture with -Force switch to remove existing NetEventSessions."
                        Write-Error -Message $Message
                    }
                    else {
                        Write-Error -ErrorRecord $_
                    }
                    continue
                }

                $LinkLayerAddress = switch ($Type) {
                    'CDP' { '01-00-0c-cc-cc-cc' }
                    'LLDP' { '01-80-c2-00-00-0e', '01-80-c2-00-00-03', '01-80-c2-00-00-00' }
                    Default { '01-00-0c-cc-cc-cc', '01-80-c2-00-00-0e', '01-80-c2-00-00-03', '01-80-c2-00-00-00' }
                }

                $PacketCaptureParams = @{
                    SessionName      = $SessionName
                    TruncationLength = 0
                    CaptureType      = 'Physical'
                    LinkLayerAddress = $LinkLayerAddress
                }

                Add-NetEventPacketCaptureProvider @PacketCaptureParams @CimSession | Out-Null

                foreach ($Adapter in $Adapters) {
                    Add-NetEventNetworkAdapter -Name $Adapter.Name -PromiscuousMode $True @CimSession | Out-Null
                }

                Start-NetEventSession -Name $SessionName @CimSession

                $Seconds = $Duration
                $End = (Get-Date).AddSeconds($Seconds)
                while ($End -gt (Get-Date)) {
                    $SecondsLeft = $End.Subtract((Get-Date)).TotalSeconds
                    $Percent = ($Seconds - $SecondsLeft) / $Seconds * 100
                    Write-Progress -Activity "Discovery Protocol Packet Capture" -Status "Capturing on $Computer..." -SecondsRemaining $SecondsLeft -PercentComplete $Percent
                    [System.Threading.Thread]::Sleep(500)
                }

                Stop-NetEventSession -Name $SessionName @CimSession

                $Events = Invoke-Command @PSSession -ScriptBlock {
                    param(
                        $ETLFilePath
                    )

                    try {
                        $Events = Get-WinEvent -Path $ETLFilePath -Oldest -FilterXPath "*[System[EventID=1001]]" -ErrorAction Stop
                    }
                    catch {
                        if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') {
                            Write-Error -ErrorRecord $_
                        }
                    }

                    [string[]]$XpathQueries = @(
                        "Event/EventData/Data[@Name='FragmentSize']"
                        "Event/EventData/Data[@Name='Fragment']"
                        "Event/EventData/Data[@Name='MiniportIfIndex']"
                    )

                    $PropertySelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new($XpathQueries)

                    foreach ($WinEvent in $Events) {
                        $EventData = $WinEvent | Select-Object MachineName, TimeCreated
                        $EventData | Add-Member -NotePropertyName FragmentSize -NotePropertyValue $null
                        $EventData | Add-Member -NotePropertyName Fragment -NotePropertyValue $null
                        $EventData | Add-Member -NotePropertyName MiniportIfIndex -NotePropertyValue $null
                        $EventData.FragmentSize, $EventData.Fragment, $EventData.MiniportIfIndex = $WinEvent.GetPropertyValues($PropertySelector)
                        $Adapter = @(Get-NetAdapter).Where({ $_.InterfaceIndex -eq $EventData.MiniportIfIndex })
                        $EventData | Add-Member -NotePropertyName Connection -NotePropertyValue $Adapter.Name
                        $EventData | Add-Member -NotePropertyName Interface -NotePropertyValue $Adapter.InterfaceDescription
                        $EventData
                    }
                } -ArgumentList $ETLFilePath

                $FoundPackets = $Events -as [DiscoveryProtocolPacket[]] | Where-Object {
                    $_.IsDiscoveryProtocolPacket -and $_.SourceAddress -notin $MACAddresses
                } | Group-Object MiniportIfIndex | ForEach-Object {
                    $_.Group | Select-Object -First 1
                }

                Remove-NetEventSession -Name $SessionName @CimSession

                if (-not $NoCleanup.IsPresent) {
                    Invoke-Command @PSSession -ScriptBlock {
                        param(
                            $ETLFilePath
                        )

                        Remove-Item -Path $ETLFilePath -Force
                    } -ArgumentList $ETLFilePath
                }

                if ($PSCmdlet.ParameterSetName -eq 'RemoteCapture') {
                    Remove-PSSession @PSSession
                    Remove-CimSession @CimSession
                }

                if ($FoundPackets) {
                    $FoundPackets
                }
                else {
                    Write-Warning "No discovery protocol packets captured on $Computer in $Seconds seconds."
                    return
                }
            }
            else {
                Write-Warning "Unable to find a connected wired adapter on $Computer."
                return
            }
        }
    }

    end {}
}
#endregion

#region function Get-DiscoveryProtocolData
function Get-DiscoveryProtocolData {

    <#

.SYNOPSIS

    Parse CDP or LLDP packets captured by Invoke-DiscoveryProtocolCapture

.DESCRIPTION

    Gets computername, type and packet details from a DiscoveryProtocolPacket.

    Calls ConvertFrom-CDPPacket or ConvertFrom-LLDPPacket to extract packet details
    from a byte array.

.PARAMETER Packet

    Specifies an object of type DiscoveryProtocolPacket.

.EXAMPLE

    PS C:\> $Packet = Invoke-DiscoveryProtocolCapture
    PS C:\> Get-DiscoveryProtocolData -Packet $Packet

    Port      : FastEthernet0/1
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 10
    Computer  : COMPUTER1
    Type      : CDP

.EXAMPLE

    PS C:\> Invoke-DiscoveryProtocolCapture -Computer COMPUTER1 | Get-DiscoveryProtocolData

    Port      : FastEthernet0/1
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 10
    Computer  : COMPUTER1
    Type      : CDP

.EXAMPLE

    PS C:\> 'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture | Get-DiscoveryProtocolData

    Port      : FastEthernet0/1
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 10
    Computer  : COMPUTER1
    Type      : CDP

    Port      : FastEthernet0/2
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 20
    Computer  : COMPUTER2
    Type      : CDP

#>

    [CmdletBinding()]
    [Alias('Parse-CDPPacket', 'Parse-LLDPPacket')]
    param(
        [Parameter(Position = 0,
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [DiscoveryProtocolPacket[]]
        $Packet
    )

    begin {
        if ($MyInvocation.InvocationName -ne $MyInvocation.MyCommand) {
            $Warning = '{0} has been deprecated, please use {1}' -f $MyInvocation.InvocationName, $MyInvocation.MyCommand
            Write-Warning $Warning
        }
    }

    process {
        foreach ($Item in $Packet) {
            switch ($Item.DiscoveryProtocolType) {
                'CDP' { $PacketData = ConvertFrom-CDPPacket -Packet $Item.Fragment }
                'LLDP' { $PacketData = ConvertFrom-LLDPPacket -Packet $Item.Fragment }
                Default { throw 'No valid CDP or LLDP found in $Packet' }
            }

            $PacketData | Add-Member -NotePropertyName Computer -NotePropertyValue $Item.MachineName
            $PacketData | Add-Member -NotePropertyName Connection -NotePropertyValue $Item.Connection
            $PacketData | Add-Member -NotePropertyName Interface -NotePropertyValue $Item.Interface
            $PacketData | Add-Member -NotePropertyName Type -NotePropertyValue $Item.DiscoveryProtocolType
            $PacketData
        }
    }

    end {}
}
#endregion

#region function ConvertFrom-CDPPacket
function ConvertFrom-CDPPacket {

    <#

.SYNOPSIS

    Parse CDP packet.

.DESCRIPTION

    Parse CDP packet to get port, device, model, ipaddress and vlan.

    This function is used by Get-DiscoveryProtocolData to parse the
    Fragment property of a DiscoveryProtocolPacket object.

.PARAMETER Packet

    Raw CDP packet as byte array.

    This function is used by Get-DiscoveryProtocolData to parse the
    Fragment property of a DiscoveryProtocolPacket object.

.EXAMPLE

    PS C:\> $Packet = Invoke-DiscoveryProtocolCapture -Type CDP
    PS C:\> ConvertFrom-CDPPacket -Packet $Packet.Fragment

    Port      : FastEthernet0/1
    Device    : SWITCH1.domain.example
    Model     : cisco WS-C2960-48TT-L
    IPAddress : 192.0.2.10
    VLAN      : 10

#>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0,
            Mandatory = $true)]
        [byte[]]$Packet
    )

    $Stream = New-Object System.IO.MemoryStream (, $Packet)
    $Reader = New-Object System.IO.BinaryReader $Stream

    $Destination = [PhysicalAddress]$Reader.ReadBytes(6)
    $Source = [PhysicalAddress]$Reader.ReadBytes(6)
    $Length = [System.BitConverter]::ToUInt16($Reader.ReadBytes(2)[1..0], 0)

    $null = $Reader.ReadBytes(6)

    $CDP = [System.BitConverter]::ToString($Reader.ReadBytes(2))
    $Version = $Reader.ReadByte()
    $TimeToLive = $Reader.ReadByte()

    $null = $Reader.ReadBytes(2)

    $Tlv = @{
        0x0001 = 'Device'
        0x0002 = 'IPAddress'
        0x0003 = 'Port'
        0x0004 = 'Capabilities'
        0x0005 = 'SoftwareVersion'
        0x0006 = 'Model'
        0x000A = 'VLAN'
        0x000B = 'Duplex'
        0x0012 = 'TrustBitmap'
        0x0013 = 'UntrustedPortCoS'
        0x0014 = 'SystemName'
        0x0016 = 'Management'
    }

    $TypeString = 0x0001, 0x0003, 0x0005, 0x0006, 0x0014
    $TypeAddress = 0x0002, 0x0016
    $TypeByte = 0x000B, 0x0012, 0x0013
    $TypeShort = 0x000A
    $TypeInt = 0x0004

    $IPv4 = 0xCC
    $IPv6 = 0xAAAA0300000086DD

    $Properties = @{}

    Write-Verbose "Destination    : $Destination"
    Write-Verbose "Source         : $Source"
    Write-Verbose "Length         : $Length"
    Write-Verbose "Protocol ID    : $CDP"
    Write-Verbose "CDP Version    : $Version"
    Write-Verbose "Time To Live   : $TimeToLive seconds"
    Write-Verbose "----------------------------------------------------------------"

    while ($Reader.PeekChar() -ne -1) {
        $TlvType = [System.BitConverter]::ToUInt16($Reader.ReadBytes(2)[1..0], 0)
        $TlvLength = [System.BitConverter]::ToUInt16($Reader.ReadBytes(2)[1..0], 0)

        switch ($TlvType) {
            { $_ -in $TypeString } {
                $String = $Reader.ReadChars($TlvLength - 4) -join ''
                $Properties.Add($Tlv.Item([int]$TlvType), $String)
            }

            { $_ -in $TypeAddress } {
                $NumberOfAddresses = [System.BitConverter]::ToUInt32($Reader.ReadBytes(4)[3..0], 0)
                $Addresses = New-Object System.Collections.Generic.List[String]

                if ($NumberOfAddresses -gt 0) {
                    1..$NumberOfAddresses | ForEach-Object {
                        $ProtocolType = $Reader.ReadByte()
                        $ProtocolLength = $Reader.ReadByte()

                        if ($ProtocolLength -eq 1) {
                            $Protocol = $Reader.ReadByte()
                        }
                        else {
                            $Protocol = [System.BitConverter]::ToInt64($Reader.ReadBytes(8)[7..0], 0)
                        }

                        $AddressLength = [System.BitConverter]::ToUInt16($Reader.ReadBytes(2)[1..0], 0)
                        $AddressBytes = $Reader.ReadBytes($AddressLength)

                        if (($ProtocolType -eq 0x01 -and $Protocol -eq $IPv4) -or ($ProtocolType -eq 0x02 -and $Protocol -eq $IPv6)) {
                            $IPAddress = [System.Net.IPAddress]::new($AddressBytes).IPAddressToString
                            $Addresses.Add($IPAddress)
                        }
                        else {
                            $ProtocolBytes = [System.BitConverter]::GetBytes($Protocol)[7..0]
                            $ProtocolHex = [System.BitConverter]::ToString($ProtocolBytes)
                            $AddressHex = [System.BitConverter]::ToString($AddressBytes)

                            Write-Verbose "TlvType        : $TlvType"
                            Write-Verbose "TlvLength      : $TlvLength"
                            Write-Verbose "ProtocolType   : $ProtocolType"
                            Write-Verbose "ProtocolLength : $ProtocolLength"
                            Write-Verbose "ProtocolHex    : $ProtocolHex"
                            Write-Verbose "AddressLength  : $AddressLength"
                            Write-Verbose "AddressHex     : $AddressHex"
                            Write-Verbose "----------------------------------------------------------------"
                        }
                    }
                }
                else {
                    Write-Verbose "TlvType        : $TlvType"
                    Write-Verbose "TlvLength      : $TlvLength"
                    Write-Verbose "NumOfAddresses : $NumberOfAddresses"
                    Write-Verbose "----------------------------------------------------------------"
                }

                if ($Addresses.Count -gt 0) {
                    $Properties.Add($Tlv.Item([int]$TlvType), $Addresses)
                }
            }

            { $_ -in $TypeByte } {
                $Value = $Reader.ReadBytes(1)[0]
                $Properties.Add($Tlv.Item([int]$TlvType), $Value)
            }

            { $_ -in $TypeShort } {
                $Value = [System.BitConverter]::ToUInt16($Reader.ReadBytes(2)[1..0], 0)
                $Properties.Add($Tlv.Item([int]$TlvType), $Value)
            }

            { $_ -in $TypeInt } {
                $Value = [System.BitConverter]::ToUInt32($Reader.ReadBytes(4)[3..0], 0)
                $Properties.Add($Tlv.Item([int]$TlvType), $Value)
            }

            default {
                $Bytes = $Reader.ReadBytes($TlvLength - 4)
                $Chars = $Bytes -as [System.Char[]]
                $Hex = [System.BitConverter]::ToString($Bytes)
                $Ascii = $Chars -join ''

                Write-Verbose "TlvType        : $TlvType"
                Write-Verbose "TlvLength      : $TlvLength"
                Write-Verbose "Hex            : $Hex"
                Write-Verbose "Ascii          : $Ascii"
                Write-Verbose "----------------------------------------------------------------"
            }
        }
    }

    New-Object PSObject -Property $Properties
}
#endregion

#region function ConvertFrom-LLDPPacket
function ConvertFrom-LLDPPacket {

    <#

.SYNOPSIS

    Parse LLDP packet.

.DESCRIPTION

    Parse LLDP packet to get port, description, device, model, ipaddress and vlan.

.PARAMETER Packet

    Raw LLDP packet as byte array.

    This function is used by Get-DiscoveryProtocolData to parse the
    Fragment property of a DiscoveryProtocolPacket object.

.EXAMPLE

    PS C:\> $Packet = Invoke-DiscoveryProtocolCapture -Type LLDP
    PS C:\> ConvertFrom-LLDPPacket -Packet $Packet.Fragment

    Model       : WS-C2960-48TT-L
    Description : HR Workstation
    VLAN        : 10
    Port        : Fa0/1
    Device      : SWITCH1.domain.example
    IPAddress   : 192.0.2.10

#>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0,
            Mandatory = $true)]
        [byte[]]$Packet
    )

    begin {
        $TlvType = @{
            EndOfLLDPDU          = 0
            ChassisId            = 1
            PortId               = 2
            TimeToLive           = 3
            PortDescription      = 4
            SystemName           = 5
            SystemDescription    = 6
            ManagementAddress    = 8
            OrganizationSpecific = 127
        }
    }

    process {

        $Destination = [PhysicalAddress]::new($Packet[0..5])
        $Source = [PhysicalAddress]::new($Packet[6..11])
        $EtherType = [BitConverter]::ToString($Packet[12..13])

        Write-Verbose "Destination    : $Destination"
        Write-Verbose "Source         : $Source"
        Write-Verbose "EtherType      : $EtherType"
        Write-Verbose "----------------------------------------------------------------"

        $Offset = 14
        $Mask = 0x01FF
        $Hash = @{}

        while ($Offset -lt $Packet.Length) {
            $Type = $Packet[$Offset] -shr 1
            $Length = [BitConverter]::ToUInt16($Packet[($Offset + 1)..$Offset], 0) -band $Mask
            $Offset += 2

            switch ($Type) {
                $TlvType.ChassisId {
                    $Subtype = $Packet[($Offset)]

                    if ($SubType -in (1, 2, 3, 6, 7)) {
                        $Hash.Add('ChassisId', [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }

                    if ($Subtype -eq 5) {
                        $AddressFamily = $Packet[($Offset + 1)]
                        if ($AddressFamily -in 1, 2) {
                            $Hash.Add('ChassisId', [IPAddress]::new($Packet[($Offset + 2)..($Offset + $Length - 1)]))
                        }
                        else {
                            $Bytes = $Packet[($Offset + 2)..($Offset + $Length - 1)]
                            $Hex = [System.BitConverter]::ToString($Bytes)
                            $Ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)

                            Write-Verbose "TlvType        : $Type"
                            Write-Verbose "TlvLength      : $Length"
                            write-Verbose "SubType        : $Subtype"
                            Write-Verbose "AddressFamily  : $AddressFamily"
                            Write-Verbose "Hex            : $Hex"
                            Write-Verbose "Ascii          : $Ascii"
                            Write-Verbose "----------------------------------------------------------------"
                        }
                    }

                    if ($Subtype -eq 4) {
                        $Hash.Add('ChassisId', [PhysicalAddress]::new($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }

                    $Offset += $Length
                    break
                }

                $TlvType.PortId {
                    $Subtype = $Packet[($Offset)]

                    if ($SubType -in (1, 2, 5, 6, 7)) {
                        $Hash.Add('Port', [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }

                    if ($Subtype -eq 4) {
                        $AddressFamily = $Packet[($Offset + 1)]
                        if ($AddressFamily -in 1, 2) {
                            $Hash.Add('Port', [IPAddress]::new($Packet[($Offset + 2)..($Offset + $Length - 1)]))
                        }
                        else {
                            $Bytes = $Packet[($Offset + 2)..($Offset + $Length - 1)]
                            $Hex = [System.BitConverter]::ToString($Bytes)
                            $Ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)

                            Write-Verbose "TlvType        : $Type"
                            Write-Verbose "TlvLength      : $Length"
                            write-Verbose "SubType        : $Subtype"
                            Write-Verbose "AddressFamily  : $AddressFamily"
                            Write-Verbose "Hex            : $Hex"
                            Write-Verbose "Ascii          : $Ascii"
                            Write-Verbose "----------------------------------------------------------------"
                        }
                    }

                    if ($Subtype -eq 3) {
                        $Hash.Add('Port', [PhysicalAddress]::new($Packet[($Offset + 1)..($Offset + $Length - 1)]))
                    }

                    $Offset += $Length
                    break
                }

                $TlvType.TimeToLive {
                    $Hash.Add('TimeToLive', [BitConverter]::ToUInt16($Packet[($Offset + 1)..$Offset], 0))
                    $Offset += $Length
                    break
                }

                $TlvType.PortDescription {
                    $Hash.Add('PortDescription', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                    $Offset += $Length
                    break
                }

                $TlvType.SystemName {
                    $Hash.Add('Device', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                    $Offset += $Length
                    break
                }

                $TlvType.SystemDescription {
                    $Hash.Add('SystemDescription', [System.Text.Encoding]::ASCII.GetString($Packet[$Offset..($Offset + $Length - 1)]))
                    $Offset += $Length
                    break
                }

                $TlvType.ManagementAddress {
                    $AddrLen = $Packet[($Offset)]
                    $Subtype = $Packet[($Offset + 1)]

                    if (-not $Hash.ContainsKey('IPAddress') -and $Subtype -in 1, 2) {
                        $Addresses = New-Object System.Collections.Generic.List[String]
                        $Hash.Add('IPAddress', $Addresses)
                    }

                    if ($Subtype -in 1, 2) {
                        $Addresses.Add(([System.Net.IPAddress][byte[]]$Packet[($Offset + 2)..($Offset + $AddrLen)]).IPAddressToString)
                    }
                    else {
                        $Bytes = $Packet[($Offset + 2)..($Offset + $AddrLen)]
                        $Hex = [System.BitConverter]::ToString($Bytes)
                        $Ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)

                        Write-Verbose "TlvType        : $Type"
                        Write-Verbose "TlvLength      : $Length"
                        Write-Verbose "AddressLength  : $AddrLen"
                        write-Verbose "SubType        : $Subtype"
                        Write-Verbose "Hex            : $Hex"
                        Write-Verbose "Ascii          : $Ascii"
                        Write-Verbose "----------------------------------------------------------------"
                    }

                    $Offset += $Length
                    break
                }

                $TlvType.OrganizationSpecific {
                    $OUI = [System.BitConverter]::ToString($Packet[($Offset)..($Offset + 2)])
                    $Subtype = $Packet[($Offset + 3)]

                    if ($OUI -eq '00-12-BB' -and $Subtype -eq 10) {
                        $Hash.Add('Model', [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 4)..($Offset + $Length - 1)]))
                    }

                    if ($OUI -eq '00-80-C2' -and $Subtype -eq 1) {
                        $Hash.Add('VLAN', [BitConverter]::ToUInt16($Packet[($Offset + 5)..($Offset + 4)], 0))
                    }

                    if ($OUI -eq '00-80-C2' -and $Subtype -eq 9) {
                        $ETSMask = [uint16]0x000F
                        $Pri0To3 = [BitConverter]::ToUInt16($Packet[($Offset + 6)..($Offset + 5)], 0)
                        $Pri4To7 = [BitConverter]::ToUInt16($Packet[($Offset + 8)..($Offset + 7)], 0)

                        $ETS = [PSCustomObject]@{
                            Willing = ($Packet[($Offset + 4)] -band (1 -shl 7)) -ne 0
                            PriorityAssignmentTable = @(
                                [PSCustomObject]@{
                                    Priority = 0
                                    TrafficClass = ($Pri0To3 -shr 12) -band $ETSMask
                                }
                                [PSCustomObject]@{
                                    Priority = 1
                                    TrafficClass = ($Pri0To3 -shr 8) -band $ETSMask
                                }
                                [PSCustomObject]@{
                                    Priority = 2
                                    TrafficClass = ($Pri0To3 -shr 4) -band $ETSMask
                                }
                                [PSCustomObject]@{
                                    Priority = 3
                                    TrafficClass = $Pri0To3 -band $ETSMask
                                }
                                [PSCustomObject]@{
                                    Priority = 4
                                    TrafficClass = ($Pri4To7 -shr 12) -band $ETSMask
                                }
                                [PSCustomObject]@{
                                    Priority = 5
                                    TrafficClass = ($Pri4To7 -shr 8) -band $ETSMask
                                }
                                [PSCustomObject]@{
                                    Priority = 6
                                    TrafficClass = ($Pri4To7 -shr 4) -band $ETSMask
                                }
                                [PSCustomObject]@{
                                    Priority = 7
                                    TrafficClass = $Pri4To7 -band $ETSMask
                                }
                            )
                            BandwidthAssignmentTable = @(
                                [PSCustomObject]@{
                                    Priority = 0
                                    Bandwidth = $Packet[($Offset + 9)]
                                }
                                [PSCustomObject]@{
                                    Priority = 1
                                    Bandwidth = $Packet[($Offset + 10)]
                                }
                                [PSCustomObject]@{
                                    Priority = 2
                                    Bandwidth = $Packet[($Offset + 11)]
                                }
                                [PSCustomObject]@{
                                    Priority = 3
                                    Bandwidth = $Packet[($Offset + 12)]
                                }
                                [PSCustomObject]@{
                                    Priority = 4
                                    Bandwidth = $Packet[($Offset + 13)]
                                }
                                [PSCustomObject]@{
                                    Priority = 5
                                    Bandwidth = $Packet[($Offset + 14)]
                                }
                                [PSCustomObject]@{
                                    Priority = 6
                                    Bandwidth = $Packet[($Offset + 15)]
                                }
                                [PSCustomObject]@{
                                    Priority = 7
                                    Bandwidth = $Packet[($Offset + 16)]
                                }
                            )
                        }

                        if (-not ($Hash.ContainsKey('DCBX'))) {
                            $Hash.Add('DCBX', [PSCustomObject]@{IEEE = [PSCustomObject]@{}})
                        }

                        $Hash.DCBX.IEEE | Add-Member -NotePropertyName ETS -NotePropertyValue $ETS
                    }

                    if ($OUI -eq '00-80-C2' -and $Subtype -eq 11) {
                        $PFC = [PSCustomObject]@{
                            Willing = ($Packet[($Offset + 4)] -band (1 -shl 7)) -ne 0
                            FlowControl = 0..7 | ForEach-Object {
                                [PSCustomObject]@{
                                    Priority = $_
                                    Enabled = ($Packet[($Offset + 5)] -band (1 -shl $_)) -ne 0
                                }
                            }
                        }

                        if (-not ($Hash.ContainsKey('DCBX'))) {
                            $Hash.Add('DCBX', [PSCustomObject]@{IEEE = [PSCustomObject]@{}})
                        }

                        $Hash.DCBX.IEEE | Add-Member -NotePropertyName PFC -NotePropertyValue $PFC
                    }

                    if ($OUI -eq '00-1B-21' -and $Subtype -eq 2) {
                        if (-not ($Hash.ContainsKey('DCBX'))) {
                            $Hash.Add('DCBX', [PSCustomObject]@{CEE = [PSCustomObject]@{}})
                        }

                        $DCBXTLVBuffer = $Packet[($Offset + 4)..($Offset + $Length - 1)]
                        $DCBXTLVOffset = 0

                        while ($DCBXTLVOffset -lt $DCBXTLVBuffer.Length) {
                            $DCBXTLVType = $DCBXTLVBuffer[($DCBXTLVOffset)] -shr 1
                            $DCBXTLVLength = [BitConverter]::ToUInt16($DCBXTLVBuffer[($DCBXTLVOffset + 1)..$DCBXTLVOffset], 0) -band $Mask
                            $DCBXTLVOffset += 2

                            Write-Verbose "DCBXTLVType    : $DCBXTLVType"
                            Write-Verbose "DCBXTLVLength  : $DCBXTLVLength"

                            if ($DCBXTLVType -eq 2) {
                                $ETSMask = [uint16]0x000F
                                $Pri0To3 = [BitConverter]::ToUInt16($DCBXTLVBuffer[($DCBXTLVOffset + 5)..($DCBXTLVOffset + 4)], 0)
                                $Pri4To7 = [BitConverter]::ToUInt16($DCBXTLVBuffer[($DCBXTLVOffset + 7)..($DCBXTLVOffset + 6)], 0)

                                $ETS = [PSCustomObject]@{
                                    Enabled = ($DCBXTLVBuffer[($DCBXTLVOffset + 2)] -band (1 -shl 7)) -ne 0
                                    Willing = ($DCBXTLVBuffer[($DCBXTLVOffset + 2)] -band (1 -shl 6)) -ne 0
                                    PriorityAssignmentTable = @(
                                        [PSCustomObject]@{
                                            Priority = 0
                                            TrafficClass = ($Pri0To3 -shr 12) -band $ETSMask
                                        }
                                        [PSCustomObject]@{
                                            Priority = 1
                                            TrafficClass = ($Pri0To3 -shr 8) -band $ETSMask
                                        }
                                        [PSCustomObject]@{
                                            Priority = 2
                                            TrafficClass = ($Pri0To3 -shr 4) -band $ETSMask
                                        }
                                        [PSCustomObject]@{
                                            Priority = 3
                                            TrafficClass = $Pri0To3 -band $ETSMask
                                        }
                                        [PSCustomObject]@{
                                            Priority = 4
                                            TrafficClass = ($Pri4To7 -shr 12) -band $ETSMask
                                        }
                                        [PSCustomObject]@{
                                            Priority = 5
                                            TrafficClass = ($Pri4To7 -shr 8) -band $ETSMask
                                        }
                                        [PSCustomObject]@{
                                            Priority = 6
                                            TrafficClass = ($Pri4To7 -shr 4) -band $ETSMask
                                        }
                                        [PSCustomObject]@{
                                            Priority = 7
                                            TrafficClass = $Pri4To7 -band $ETSMask
                                        }
                                    )
                                    BandwidthAssignmentTable = @(
                                        [PSCustomObject]@{
                                            Priority = 0
                                            Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 8)]
                                        }
                                        [PSCustomObject]@{
                                            Priority = 1
                                            Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 9)]
                                        }
                                        [PSCustomObject]@{
                                            Priority = 2
                                            Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 10)]
                                        }
                                        [PSCustomObject]@{
                                            Priority = 3
                                            Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 11)]
                                        }
                                        [PSCustomObject]@{
                                            Priority = 4
                                            Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 12)]
                                        }
                                        [PSCustomObject]@{
                                            Priority = 5
                                            Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 13)]
                                        }
                                        [PSCustomObject]@{
                                            Priority = 6
                                            Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 14)]
                                        }
                                        [PSCustomObject]@{
                                            Priority = 7
                                            Bandwidth = $DCBXTLVBuffer[($DCBXTLVOffset + 15)]
                                        }
                                    )
                                }

                                $Hash.DCBX.CEE | Add-Member -NotePropertyName ETS -NotePropertyValue $ETS
                            }

                            if ($DCBXTLVType -eq 3) {
                                $PFC = [PSCustomObject]@{
                                    Enabled = ($DCBXTLVBuffer[($DCBXTLVOffset + 2)] -band (1 -shl 7)) -ne 0
                                    Willing = ($DCBXTLVBuffer[($DCBXTLVOffset + 2)] -band (1 -shl 6)) -ne 0
                                    FlowControl = 0..7 | ForEach-Object {
                                        [PSCustomObject]@{
                                            Priority = $_
                                            Enabled = ($DCBXTLVBuffer[($DCBXTLVOffset + 4)] -band (1 -shl $_)) -ne 0
                                        }
                                    }
                                }

                                $Hash.DCBX.CEE | Add-Member -NotePropertyName PFC -NotePropertyValue $PFC
                            }

                            $DCBXTLVOffset += $DCBXTLVLength
                        }
                    }

                    $Bytes = $Packet[($Offset + 4)..($Offset + $Length - 1)]
                    $Hex = [System.BitConverter]::ToString($Bytes)
                    $Ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)

                    Write-Verbose "TlvType        : $Type"
                    Write-Verbose "TlvLength      : $Length"
                    Write-Verbose "OUI            : $OUI"
                    write-Verbose "SubType        : $SubType"
                    Write-Verbose "Hex            : $Hex"
                    Write-Verbose "Ascii          : $Ascii"
                    Write-Verbose "----------------------------------------------------------------"

                    $Offset += $Length
                    break
                }

                $TlvType.EndOfLLDPDU {
                    Write-Verbose "TlvName        : End Of LLDPDU"
                    Write-Verbose "TlvType        : $Type"
                    Write-Verbose "TlvLength      : $Length"
                    Write-Verbose "----------------------------------------------------------------"
                }

                default {
                    $Bytes = $Packet[$Offset..($Offset + $Length - 1)]
                    $Hex = [System.BitConverter]::ToString($Bytes)
                    $Ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)

                    Write-Verbose "TlvType        : $Type"
                    Write-Verbose "TlvLength      : $Length"
                    Write-Verbose "Hex            : $Hex"
                    Write-Verbose "Ascii          : $Ascii"
                    Write-Verbose "----------------------------------------------------------------"

                    $Offset += $Length
                    break
                }
            }
        }
        [PSCustomObject]$Hash
    }

    end {}
}
#endregion

#region function Export-Pcap
function Export-Pcap {

    <#

.SYNOPSIS

    Export packets to pcap

.DESCRIPTION

    Export packets, captured using Invoke-DiscoveryProtocolCapture, to pcap format.

.PARAMETER Packet

    Specifies one or more objects of type DiscoveryProtocolPacket.

.PARAMETER Path

    Relative or absolute path to pcap file.

.PARAMETER Invoke

    If Invoke is set, exported file is opened in the program associated with pcap files.

.EXAMPLE

    PS C:\> $Packet = Invoke-DiscoveryProtocolCapture
    PS C:\> Export-Pcap -Packet $Packet -Path C:\Windows\Temp\captures.pcap -Invoke

    Export captured packet to C:\Windows\Temp\captures.pcap and open file in
    the program associated with pcap files.

.EXAMPLE

    PS C:\> 'COMPUTER1', 'COMPUTER2' | Invoke-DiscoveryProtocolCapture | Export-Pcap -Path captures.pcap

    Export captured packets to captures.pcap in current directory. Export-Pcap supports input from pipeline.

#>

    [CmdletBinding(DefaultParameterSetName = 'DiscoveryProtocolPacket')]
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'DiscoveryProtocolPacket')]
        [DiscoveryProtocolPacket[]]$Packet,

        [Parameter(Mandatory = $true,
            ParameterSetName = 'BytesAndDateTime')]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $false,
            ParameterSetName = 'BytesAndDateTime')]
        [datetime]$DateTime = (Get-Date),

        [Parameter(Mandatory = $true)]
        [ValidateScript( {
                if ([System.IO.Path]::IsPathRooted($_)) {
                    $AbsolutePath = $_
                }
                else {
                    $AbsolutePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_)
                }
                if (-not(Test-Path (Split-Path $AbsolutePath -Parent))) {
                    throw "Folder does not exist"
                }
                if ($_ -notmatch '\.pcap$') {
                    throw "Extension must be pcap"
                }
                return $true
            })]
        [System.IO.FileInfo]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$Invoke
    )

    begin {
        [uint32]$magicNumber = '0xa1b2c3d4'
        [uint16]$versionMajor = 2
        [uint16]$versionMinor = 4
        [int32] $thisZone = 0
        [uint32]$sigFigs = 0
        [uint32]$snapLen = 65536
        [uint32]$network = 1

        $stream = New-Object System.IO.MemoryStream
        $writer = New-Object System.IO.BinaryWriter $stream

        $writer.Write($magicNumber)
        $writer.Write($versionMajor)
        $writer.Write($versionMinor)
        $writer.Write($thisZone)
        $writer.Write($sigFigs)
        $writer.Write($snapLen)
        $writer.Write($network)
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'DiscoveryProtocolPacket' {
                foreach ($item in $Packet) {
                    [uint32]$tsSec = ([DateTimeOffset]$item.TimeCreated).ToUnixTimeSeconds()
                    [uint32]$tsUsec = $item.TimeCreated.Millisecond
                    [uint32]$inclLen = $item.FragmentSize
                    [uint32]$origLen = $inclLen

                    $writer.Write($tsSec)
                    $writer.Write($tsUsec)
                    $writer.Write($inclLen)
                    $writer.Write($origLen)
                    $writer.Write($item.Fragment)
                }
            }
            'BytesAndDateTime' {
                [uint32]$tsSec = ([DateTimeOffset]$DateTime).ToUnixTimeSeconds()
                [uint32]$tsUsec = $DateTime.Millisecond
                [uint32]$inclLen = $Bytes.Length
                [uint32]$origLen = $inclLen

                $writer.Write($tsSec)
                $writer.Write($tsUsec)
                $writer.Write($inclLen)
                $writer.Write($origLen)
                $writer.Write($Bytes)
            }
        }
    }

    end {
        $bytes = $stream.ToArray()

        $stream.Dispose()
        $writer.Dispose()

        if (-not([System.IO.Path]::IsPathRooted($Path))) {
            $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        }

        [System.IO.File]::WriteAllBytes($Path, $bytes)

        if ($Invoke) {
            Invoke-Item -Path $Path
        }
    }
}
#endregion
