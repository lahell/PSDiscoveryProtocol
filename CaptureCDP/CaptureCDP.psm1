#region function Capture-CDPPacket
function Capture-CDPPacket {

<#

.SYNOPSIS

    Capture CDP packets on local or remote computers

.DESCRIPTION

    Capture CDP packets on local or remote computers. Cisco devices will by default send CDP announcements every 60 seconds.
    This cmdlet will start a packet capture and save the captured packets in a temporary ETL file. Only the first CDP packet
    in the ETL file will be returned.

    Requires elevation (Run as Administrator).
    WinRM and PowerShell remoting must be enabled on the target computer.

.PARAMETER ComputerName

    Specifies one or more computers on which to capture CDP packets. Defaults to $env:COMPUTERNAME.

.PARAMETER Duration

    Specifies the duration for which the CDP packets are captured, in seconds. Defaults to 62.

.EXAMPLE

    PS> $Packet = Capture-CDPPacket
    PS> Parse-CDPPacket -Packet $Packet

    Port      : FastEthernet0/1 
    Device    : SWITCH1.domain.example 
    Model     : cisco WS-C2960-48TT-L 
    IPAddress : 192.0.2.10
    VLAN      : 10

.EXAMPLE

    PS> Capture-CDPPacket -Computer COMPUTER1 | Parse-CDPPacket

    Port      : FastEthernet0/1 
    Device    : SWITCH1.domain.example 
    Model     : cisco WS-C2960-48TT-L 
    IPAddress : 192.0.2.10
    VLAN      : 10

.EXAMPLE

    PS> 'COMPUTER1', 'COMPUTER2' | Capture-CDPPacket | Parse-CDPPacket

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

#>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
        [Alias('CN', 'Computer')]
        [String[]]$ComputerName = $env:COMPUTERNAME,

        [Parameter(Position=1)] 
        [Int16]$Duration = 62
    )


    begin {
        $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object Security.Principal.WindowsPrincipal $Identity
        if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
            throw 'Capture-CDPPacket requires elevation. Please run PowerShell as administrator.'
        }
    }

    process {
    
        foreach ($Computer in $ComputerName) {

            try {
                $CimSession = New-CimSession -ComputerName $Computer -ErrorAction Stop
            } catch {
                Write-Warning "Unable to create CimSession. Please make sure WinRM and PSRemoting is enabled on $Computer."
                continue
            }

            $ETLFile = Invoke-Command -ComputerName $Computer -ScriptBlock {
                $TempFile = New-TemporaryFile
                Rename-Item -Path $TempFile.FullName -NewName $TempFile.FullName.Replace('.tmp', '.etl') -PassThru
            }

            $Adapter = Get-NetAdapter -Physical -CimSession $CimSession | 
                Where-Object {$_.Status -eq 'Up' -and $_.InterfaceType -eq 6} | 
                Select-Object -First 1 -ExpandProperty Name

            if ($Adapter) {
                $Session = New-NetEventSession -Name CDP -LocalFilePath $ETLFile.FullName -CaptureMode SaveToFile -CimSession $CimSession

                Add-NetEventPacketCaptureProvider -SessionName CDP -LinkLayerAddress '01-00-0c-cc-cc-cc' -TruncationLength 1024 -CaptureType BothPhysicalAndSwitch -CimSession $CimSession | Out-Null
                Add-NetEventNetworkAdapter -Name $Adapter -PromiscuousMode $True -CimSession $CimSession | Out-Null

                Start-NetEventSession -Name CDP -CimSession $CimSession

                $Seconds = $Duration
                $End = (Get-Date).AddSeconds($Seconds)
                while ($End -gt (Get-Date)) {
                    $SecondsLeft = $End.Subtract((Get-Date)).TotalSeconds
                    $Percent = ($Seconds - $SecondsLeft) / $Seconds * 100
                    Write-Progress -Activity "CDP Packet Capture" -Status "Capturing on $Computer..." -SecondsRemaining $SecondsLeft -PercentComplete $Percent
                    [System.Threading.Thread]::Sleep(500)
                }

                Stop-NetEventSession -Name CDP -CimSession $CimSession

                $Log = Invoke-Command -ComputerName $Computer -ScriptBlock {
                    Get-WinEvent -Path $args[0] -Oldest | 
                        Where-Object {$_.Id -eq 1001 -and [BitConverter]::ToUInt16($_.Properties[3].Value[21..20], 0) -eq [UInt16]0x2000} |
                        Select-Object -Last 1 -ExpandProperty Properties
                } -ArgumentList $Session.LocalFilePath

                Remove-NetEventSession -Name CDP -CimSession $CimSession
                Start-Sleep -Seconds 2
                Invoke-Command -ComputerName $Computer -ScriptBlock { 
                    Remove-Item -Path $args[0] -Force
                } -ArgumentList $ETLFile.FullName

                if ($Log) {
                    $Packet = $Log[3].Value
                    ,$Packet
                } else {
                    Write-Warning "No CDP packets captured on $Computer in $Seconds seconds."
                    return
                }
            } else {
                Write-Warning "Unable to find a connected wired adapter on $Computer."
                return
            }
        }
    }
}
#endregion

#region function Parse-CDPPacket
function Parse-CDPPacket {

<#

.SYNOPSIS

    Parse CDP packet returned from Capture-CDPPacket.

.DESCRIPTION

    Parse CDP packet to get port, switch, model, ipaddress and vlan.

.PARAMETER Packet

    Array of one or more byte arrays from Capture-CDPPacket.

.EXAMPLE

    PS> $Packet = Capture-CDPPacket
    PS> Parse-CDPPacket -Packet $Packet

    Port      : FastEthernet0/1 
    Device    : SWITCH1.domain.example 
    Model     : cisco WS-C2960-48TT-L 
    IPAddress : 192.0.2.10
    VLAN      : 10

.EXAMPLE

    PS> Capture-CDPPacket -Computer COMPUTER1 | Parse-CDPPacket

    Port      : FastEthernet0/1 
    Device    : SWITCH1.domain.example 
    Model     : cisco WS-C2960-48TT-L 
    IPAddress : 192.0.2.10
    VLAN      : 10

.EXAMPLE

    PS> 'COMPUTER1', 'COMPUTER2' | Capture-CDPPacket | Parse-CDPPacket

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

#>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, 
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
        [object[]]$Packet
    )

    process {

        $Offset = 26
        $Hash = @{}

        while ($Offset -lt ($Packet.Length - 4)) {

            $Type   = [BitConverter]::ToUInt16($Packet[($Offset + 1)..$Offset], 0)
            $Length = [BitConverter]::ToUInt16($Packet[($Offset + 3)..($Offset + 2)], 0)

            switch ($Type)
            {
                1  { $Hash.Add('Device',    [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 4)..($Offset + $Length)])) }
                2  { $Hash.Add('IPAddress', ([System.Net.IPAddress][byte[]]$Packet[($Offset + 13)..($Offset + 16)]).IPAddressToString) }
                3  { $Hash.Add('Port',      [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 4)..($Offset + $Length)])) }
                6  { $Hash.Add('Model',     [System.Text.Encoding]::ASCII.GetString($Packet[($Offset + 4)..($Offset + $Length)])) }
                10 { $Hash.Add('VLAN',      [BitConverter]::ToUInt16($Packet[($Offset + 5)..($Offset + 4)], 0)) }
            }

	        if ($Length -eq 0 ) {
		        $Offset = $Packet.Length
	        }

	        $Offset = $Offset + $Length

        }

        return [PSCustomObject]$Hash

    }

}
#endregion
