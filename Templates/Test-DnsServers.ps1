<#
    .SYNOPSIS
    Tests dns servers for validity
    
    .DESCRIPTION
    Full description: Tests dns servers on the primary (public) adapter. Tests specified servers first for a response. If current host is domain-bound, tests for correct resolution of AD domain records. If current host is on workgroup, tests for correct resolution of intensive.int.

    .PARAMETER DnsServers
    Description: IP addresses of DNS servers to test
    WHAM Prompt: Enter DNS servers to test (or leave blank to test machine's current DNS svrs)
    Example use: Set-DnsServers -DnsServers "83.138.151.80", "83.138.151.81"
    Default: None

    .EXAMPLE
    Full command: Test-DnsServers -DnsServers "83.138.151.80", "83.138.151.81"
    Output: Detail of changes made

        
    .NOTES
    Minimum OS: 2008 R2
    Minimum PoSh: 2.0

#>
function Test-DnsServers {
    param(
        [Parameter(Mandatory=$false)]
        #[ipaddress[]]$DnsServers   #Not wham-compatible
        [string[]]$DnsServers
    )
    #Wham hack - it passes arrays as strings
    if ($DnsServers.Count -eq 1) {$DnsServers = $DnsServers -split '[\s,]+'}


#region Module import

$FormattingPsm1 = @'
<#
    .AUTHOR
    Copyright Freddie Sackur 2017
    https://github.rackspace.com/Windows-Automation/RaxNet
    https://jira.rax.io/browse/IAWW-45 etc etc
#>

function Add-DefaultMembers {
    <#
        .Synopsis
        Applies formatting data to a custom object
        
        .Description
        This works by pass-by-reference - the original object is updated. If you want to have an object returned, use the -PassThru switch.

        Please note that most default objects will not work if they are of a standard pre-defined type. You can convert them by piping them to a select statement.

            #This will throw an exception:
            Get-Process svchost | select * | Add-DefaultMembers -DisplayProperties 'ProcessName', 'Id'

            #This will work, but you will lose the built-in methods:
            Get-Process svchost | select * | Add-DefaultMembers -DisplayProperties 'ProcessName', 'Id' -PassThru


        .Inputs
        InputObject: The object to be configured with custom properties

        DisplayProperties: An array of property names that will be displayed on the object by default

        SortProperties: An array of property names that will determine sorting, in order of precedence

        PassThru: specifies to return the updated object to the pipeline (by default it is not returned; either way, the original reference is updated)
    #>
    [CmdletBinding(DefaultParameterSetName='Default')]
    [OutputType([void], ParameterSetName='Default')]
    [OutputType([psobject], ParameterSetName='PassThru')]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true)]
        [psobject]$InputObject,
        [Parameter(Position=1)]
        [string[]]$DisplayProperties,
        [Parameter(Position=2)]
        [string[]]$SortProperties,
        [string]$TypeName,
        [Parameter(Mandatory=$true, ParameterSetName='PassThru')]
        [switch]$PassThru
    )

    if ($TypeName) {$InputObject.PSTypeNames.Insert(0, $TypeName)}
    
    if ($DisplayProperties) {
        $Display = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', $DisplayProperties)
    }
    if ($SortProperties) {
        $Sort =    New-Object System.Management.Automation.PSPropertySet('DefaultKeyPropertySet', $SortProperties)
    }

    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($Display, $Sort)

    try {
        Add-Member -InputObject $InputObject -MemberType MemberSet -Name PSStandardMembers `
            -Value $PSStandardMembers -Force -ErrorAction Stop
    } catch {
        if ($_ -match 'Cannot force the member with name "PSStandardMembers" and type "MemberSet" to be added. A member with that name and type already exists, and the existing member is not an instance extension.') {
            throw (New-Object System.ArgumentException (
                "Cannot add new default members to a fixed object type. Try running your input object through a select statement first."
            ))
        } else {
            throw $_
        }
    }

    if ($PassThru) {return $InputObject}
}

'@

$RaxNetPsm1 = @'
<#
    .AUTHOR
    Copyright Freddie Sackur 2017
    https://github.rackspace.com/Windows-Automation/RaxNet
    https://jira.rax.io/browse/IAWW-45 etc etc
#>

#requires -version 2



######### Helpers: WMI fetchers and 'objects with methods' #########
function Get-WmiAdapter {
    <#
        .Synopsis
        Get WMI objects for network adapters

        .Description
        Returns WMI objects of class Win32_NetworkAdapter.
        
        By default, gets all network adapters that have a display name configured in ncpa.cpl - this excludes Bluetooth, Teredo etc

        The Primary switch causes only the primary adapter to be returned. This is chosen by looking at all adapters that have a
        default gateway configured and picking the default gateway with the lowest metric.

        .Parameter Primary
        return the primary IP adapter, as chosen by examination of the routing table

        .Parameter Identity
        return adapter by display name (as configured in ncpa.cpl)

        .Parameter IncludeUnnamed
        also return adapters that have no display name configured in ncpa.cpl, e.g. Bluetooth adapters.

        .Outputs
        Array of WMI objects of class Win32_NetworkAdapter
    #>
    [CmdletBinding(DefaultParameterSetName='Default')]
    [OutputType([System.Management.ManagementObject[]])] #root\cimv2\Win32_NetworkAdapter])]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='Primary')]
        [switch]$Primary,

        [Parameter(Mandatory=$true, ParameterSetName='Identity', Position=0)]
        [string]$Identity,

        [Parameter(Mandatory=$true, ParameterSetName='IncludeUnnamed')]
        [switch]$IncludeUnnamed
    )

    switch ($PSCmdlet.ParameterSetName) {
        'Primary'
                        {
                            $DefaultRouteInterfaceIndex = Get-WmiObject Win32_IP4RouteTable -Filter "Name='0.0.0.0'" |
                                sort Metric1 | select -First 1 -ExpandProperty InterfaceIndex
                            $Filter = "InterfaceIndex='$DefaultRouteInterfaceIndex'"
                            break
                        }

        'Identity'
                        {
                            $Filter = "NetConnectionID LIKE '$Identity'"
                        }

        'IncludeUnnamed'
                        {
                            $Filter = ""
                            break
                        }

        default
                        {
                            $Filter = "NetConnectionID LIKE '%'"
                        }

    }


    $NetworkAdapters = Get-WmiObject Win32_NetworkAdapter -Filter $Filter

    return $NetworkAdapters
}

function Get-WmiAdapterConfiguration {
    <#
        .Synopsis
        Get WMI objects for network adapter configurations

        .Description
        Returns WMI objects of class Win32_NetworkAdapterConfiguration.
        
        By default, gets all network adapters that have a display name configured in ncpa.cpl - this excludes Bluetooth, Teredo etc

        The Primary switch causes only the primary adapter to be returned. This is chosen by looking at all adapters that have a
        default gateway configured and picking the default gateway with the lowest metric.

        .Inputs
        .Parameter Primary
        return the primary IP adapter, as chosen by examination of the routing table

        .Parameter Identity
        return adapter by display name (as configured in ncpa.cpl)

        .Parameter IncludeUnnamed
        also return adapters that have no display name configured in ncpa.cpl, e.g. Bluetooth adapters.

        .Parameter WmiAdapter
        return the configuration object associated with the specified network adapter WMI object.

        .Outputs
        Array of WMI objects of class Win32_NetworkAdapterConfiguration
    #>
    [CmdletBinding(DefaultParameterSetName='Default')]
    [OutputType([System.Management.ManagementObject[]])] #root\cimv2\Win32_NetworkAdapter])]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='Primary')]
        [switch]$Primary,

        [Parameter(Mandatory=$true, ParameterSetName='Identity', Position=0)]
        [string]$Identity,

        [Parameter(Mandatory=$true, ParameterSetName='GetAssociated', Position=0, ValueFromPipeline=$true)]
        [ValidateScript({$_.__CLASS -like "Win32_NetworkAdapter"})]
        [System.Management.ManagementObject[]]$WmiAdapter,

        [Parameter(Mandatory=$true, ParameterSetName='IncludeUnnamed')]
        [switch]$IncludeUnnamed
    )

    begin {
        if ($WmiAdapter) {
            $WmiAdapter | foreach {
                if ($_.__CLASS -notlike "Win32_NetworkAdapter") {
                    throw "WmiAdapter must be an instance of Win32_NetworkAdapter"
                }
            }
        }
    }

    process {

        if ($PSCmdlet.ParameterSetName -ne 'GetAssociated') {
            $WmiAdapter = Get-WmiAdapter @PSBoundParameters
        }


        $WmiAdapter | foreach {
            Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "Index='$($_.DeviceID)'"
        }
    }
}

function Add-AdapterMagic {
    <#
    .Synopsis
    Turns a WMI Win32_NetworkAdapter object into a much more useful object.
    
    .Description
    Creates a PSCustomObject with typename of Dusty.Net.NetworkAdapter. Note that the underlying object is pscustomobject, as revealed by GetType(). This has the most commonly-used properties of the Win32_NetworkAdapter and Win32_NetworkAdapterConfiguration classes, as well as some useful transformations (IP addresses are converted into an array of Dusty.Net.SubnetIpAddress objects, for example)

    The Win32_NetworkAdapter and Win32_NetworkAdapterConfiguration objects are also added themselves as properties - so, any method you need from the WMI object is accessible.

    .Parameter WmiAdapter
    the instance of Win32_NetworkAdapter that you wish to base the resulting object on.

    .Example
    Get-WmiAdapter -Primary | Add-AdapterMagic

    #>
    [CmdletBinding(ConfirmImpact='Medium')]
    [OutputType([System.Management.ManagementObject])]

    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$True)]
        [ValidateScript({$_.__CLASS -like "Win32_NetworkAdapter"})]
        [System.Management.ManagementObject]$WmiAdapter
    )

    process {

        if ($WmiAdapter.__CLASS -notlike "Win32_NetworkAdapter") {
            Write-Error "WmiAdapter must be an instance of Win32_NetworkAdapter"
            return
        }

        $PropertiesToKeep = @(
            @{Name="Name"; Expression={$_.NetConnectionID}}
            "*?Name"
            'AdapterType',
            'AdapterTypeId',
            'Caption',
            'Description',
            'GUID',
            'Index',
            'InstallDate',
            'Installed',
            'InterfaceIndex',
            'MACAddress',
            'Manufacturer',
            'NetConnectionID',
            'NetConnectionStatus',
            'NetEnabled',
            'PhysicalAdapter',
            'PNPDeviceID',
            'PowerManagementCapabilities',
            'Speed'
        )

        $RaxAdapter = $WmiAdapter | select $PropertiesToKeep

        $WmiConfiguration = Get-WmiAdapterConfiguration -WmiAdapter $WmiAdapter
        Add-Member -InputObject $RaxAdapter -MemberType ScriptProperty -Name WmiAdapter -Value {Get-WmiAdapter -Identity $this.Name}
        Add-Member -InputObject $RaxAdapter -MemberType ScriptProperty -Name WmiConfiguration -Value {Get-WmiAdapterConfiguration -Identity $this.Name}
    
        $ConfPropertiesToAdd = @(
            'DHCPLeaseExpires',
            'DHCPEnabled',
            'DHCPLeaseObtained',
            'DHCPServer',
            'DNSDomainSuffixSearchOrder',
            'DNSEnabledForWINSResolution',
            'DNSHostName',
            'DomainDNSRegistrationEnabled',
            'FullDNSRegistrationEnabled',
            'IPConnectionMetric',
            'IPEnabled',
            'IPSubnet',
            'MTU'
        )

        $ConfPropertiesToAdd | foreach {
            Add-Member -InputObject $RaxAdapter -MemberType NoteProperty -Name $_ -Value $($WmiConfiguration.$_)
        }

        Add-Member -InputObject $RaxAdapter -MemberType NoteProperty -Name DnsServers -Value $(($WmiConfiguration).DNSServerSearchOrder | %{[ipaddress]$_})
        Add-Member -InputObject $RaxAdapter -MemberType NoteProperty -Name DefaultGateway -Value $($WmiConfiguration.DefaultIPGateway | %{[ipaddress]$_})
        Add-Member -InputObject $RaxAdapter -MemberType NoteProperty -Name IPAddresses -Value $(
            $IPAddresses = [ipaddress[]]@()
            for ($i=0; $i -lt $WmiConfiguration.IPAddress.Count; $i++) {
                $IPAddress = [ipaddress]$WmiConfiguration.IPAddress[$i]
                if ($IPAddress.AddressFamily -like "InterNetworkV6") {continue}  #Skip IPv6
                $IPAddress = $IPAddress | New-SubnetIpAddress -SubnetMask $WmiConfiguration.IPSubnet[$i]
                $IPAddresses += $IPAddress
            }
            $IPAddresses | sort Binary
        )



        Add-Member -InputObject $RaxAdapter -MemberType NoteProperty -Name IPv6Addresses -Value $(
            $IPv6Addresses = [ipaddress[]]@()
            for ($i=0; $i -lt $WmiConfigurationObject.IPAddress.Count; $i++) {
                $IPAddress = [ipaddress]$WmiConfigurationObject.IPAddress[$i]
                if ($IPAddress.AddressFamily -like "InterNetwork") {continue}  #Skip IPv4
                $IPv6Addresses += $IPAddress
            }
        )

    
        $DisplayProperties = @('Name', 'IPAddresses', 'DefaultGateway', 'DnsServers')
        $SortProperties = @('NetEnabled', 'IPEnabled', 'Name', 'InterfaceIndex', 'Index')

        $RaxAdapter | Add-DefaultMembers -DisplayProperties $DisplayProperties -SortProperties $SortProperties -TypeName "Dusty.Net.NetworkAdapter"

        return $RaxAdapter
    }
}

function New-SubnetIpAddress {
    <#
    .Synopsis
    Turns a System.Net.IpAddress object into a more useful object.
    
    .Description
    Creates a PSCustomObject with typename of Dusty.Net.SubnetIpAddress. This has additional properties that encapsulate the subnet that the IP address is located in, which makes it easier to perform netowrking operations.

    This also makes it possible to sort the resulting objects.

    .Parameter Ip
    the ip address in question. IPv6 is not currently supported.

    .Parameter SubnetMask
    specifies the subnet mask of the IP address, as a System.Net.IpAddress object

    .Parameter Cidr
    specifies the subnet mask of the IP address as the number of bits in the network section

    .Example
    PS C:\> "10.0.0.2" | New-SubnetIpAddress -Cidr 27


    SubnetMask         : 255.255.255.224
    Cidr               : 27
    Binary             : 00001010000000000000000000000010
    Address            : 33554442
    AddressFamily      : InterNetwork
    ScopeId            : 
    IsIPv6Multicast    : False
    IsIPv6LinkLocal    : False
    IsIPv6SiteLocal    : False
    IsIPv6Teredo       : False
    IsIPv4MappedToIPv6 : False
    IPAddressToString  : 10.0.0.2


    Returns an ip address with subnet mask


    .Example
    PS C:\> $Ip1 = "10.0.0.2" | New-SubnetIpAddress -SubnetMask "255.255.255.224"

    PS C:\> $Ip1.GetNetworkPrefix()
    10.0.0.0/27


    .Example
    PS C:\> $Ip1 = "10.0.0.2" | New-SubnetIpAddress -Cidr 27

    PS C:\> $Ip2 = "10.0.0.8" | New-SubnetIpAddress -Cidr 27

    PS C:\> $Ip3 = "192.168.20.10" | New-SubnetIpAddress -Cidr 20

    PS C:\> $Ip1.IsInSameSubnet($Ip2)
    True

    PS C:\> $Ip1.IsInSameSubnet($Ip3)
    False


    .Example
    PS C:\> $Ip1 = "10.0.20.20" | New-SubnetIpAddress -SubnetMask "255.255.252.0"

    PS C:\> $Ip1.Binary
    00001010000000000001010000010100


    .Example
    PS C:\> $Ip1 = "172.24.0.7" | New-SubnetIpAddress -SubnetMask "255.255.252.0"

    PS C:\> $Ip2 = "172.16.0.3" | New-SubnetIpAddress -SubnetMask "255.255.252.0"

    PS C:\> $Ip1, $Ip2 | sort


    SubnetMask         : 255.255.252.0
    Cidr               : 22
    Binary             : 10101100000100000000000000000011
    Address            : 50335916
    AddressFamily      : InterNetwork
    ScopeId            : 
    IsIPv6Multicast    : False
    IsIPv6LinkLocal    : False
    IsIPv6SiteLocal    : False
    IsIPv6Teredo       : False
    IsIPv4MappedToIPv6 : False
    IPAddressToString  : 172.16.0.3

    SubnetMask         : 255.255.252.0
    Cidr               : 22
    Binary             : 10101100000110000000000000000111
    Address            : 117446828
    AddressFamily      : InterNetwork
    ScopeId            : 
    IsIPv6Multicast    : False
    IsIPv6LinkLocal    : False
    IsIPv6SiteLocal    : False
    IsIPv6Teredo       : False
    IsIPv4MappedToIPv6 : False
    IPAddressToString  : 172.24.0.7

    In this example, two IP addresses are sorted numerically. Objects of type [ipaddress] do not sort as expected in Windows, but these objects do.

    #>
    [CmdletBinding(DefaultParameterSetName='Cidr')]
    [OutputType([ipaddress])]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline = $true)]
        [ipaddress]$Ip,
        [Parameter(Mandatory=$false, Position=1, ParameterSetName='SubnetMask')]
        [ValidateScript({ConvertTo-Binary -IpAddress $_ | foreach {($_ -match '^1*0*$') -and ($_.Length -eq 32)}})]
        [ipaddress]$SubnetMask,
        [Parameter(Mandatory=$false, Position=1, ParameterSetName='Cidr')]
        [ValidateRange(0,32)]
        [uint16]$Cidr
    )

    if ($Ip.AddressFamily -like "InterNetworkV6") {
        throw "IPv6 support is not implemented yet"
    }

    #Create a new object
    $Ip = [ipaddress]$Ip.ToString()
    #Passing happens by reference. If we don't take this step, the original object 
    #gets updated, which is probably not intended.


    $Ip.PSTypeNames.Insert(0, 'Dusty.Net.SubnetIpAddress')

    if ($Cidr) {$SubnetMask = ConvertFrom-Binary -BinaryIPAddress ("1" * $Cidr).PadRight(32, '0')}

    Add-Member -InputObject $Ip -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask
    Add-Member -InputObject $Ip -MemberType ScriptMethod -Name GetNetworkPrefix -Value {Get-NetworkPrefix -IpAddress $this -SubnetMask $this.SubnetMask}


    switch ($PSCmdlet.ParameterSetName) {
        'SubnetMask' {
            if ($Ip.AddressFamily -ne $SubnetMask.AddressFamily) {throw (New-Object System.FormatException ("IP and subnet mask must be of same family"))}
            Add-Member -InputObject $Ip -MemberType ScriptProperty -Name Cidr -Value {(ConvertTo-Binary -IpAddress $this.SubnetMask).IndexOf('0')}
        }
        'Cidr' {
            Add-Member -InputObject $Ip -MemberType NoteProperty -Name Cidr -Value $Cidr
        }
    }

    
    Add-Member -InputObject $Ip -MemberType ScriptMethod -Name IsInSameSubnet -Value {
        param([ipaddress]$Ip)
        if (-not $this.GetNetworkPrefix()) {
            throw "You cannot call this method on an IpAddress that did not have a subnet or cidr configured at creation time using Add-AdapterMagic"
        }
        return Test-IsInSameSubnet -NetworkPrefix $this.GetNetworkPrefix() -IPAddress $Ip
    }

    Add-Member -InputObject $Ip -MemberType ScriptProperty -Name Binary -Value {
        return ConvertTo-Binary -IpAddress $this
    }

    Add-Member -InputObject $Ip -MemberType ScriptMethod -Name CompareTo -Value {
        [Outputtype([Int32])]
        param([ipaddress]$Ip)
        $BytesThis = $this -split '\.'
        $BytesThat = $Ip -split '\.'
        for ($i=0; $i -lt $BytesThis.Count; $i++) {
            $c = ([int]$BytesThis[$i]).CompareTo(([int]$BytesThat[$i]))
            if ($c) {return $c}
        }
        return 0
    }

    return $Ip
}


######### Utility functions for, e.g., subnet calculations #########
function ConvertTo-Binary {
    <#
        .Synopsis
        Converts an IP address into its string representation in binary format

        .Description
        Converts an address to binary format, namely, a string with length 32 (IPv4) or 128 (IPv6) composed of 1s and 0s
        
        .Example
        ConvertTo-Binary -IPAddress 192.168.100.24

        .Output
        String: representation of the address in binary

        .Notes
        Non-destructive
    #>
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, ValueFromRemainingArguments=$true, Position=0)]
        [ipaddress]$IpAddress
    )
    
    #String in 1s and 0s
    $BinaryBytes = $IPAddress | %{$_.GetAddressBytes() | %{[Convert]::ToString($_, 2).PadLeft(8, '0')}}
    
    #32 character string of 1s and 0s (or 128 if we go with IPv6)
    return $BinaryBytes -join ''
    
}

function ConvertFrom-Binary {
    <#
    .Synopsis
    Converts a string representation of an address in binary back to an ip address

    .Description
    Converts an address to binary format, namely, a string with length 32 (IPv4) or 128 (IPv6) composed of 1s and 0s
        
    .Example
    ConvertTo-Binary -IPAddress 192.168.100.24

    .Outputs
    String: representation of the address in binary

    .Notes
    Non-destructive
    #>
    param(
        [ValidateScript({($_.Length -eq 32 -or $_.Length -eq 128) -and $_ -match "^(0|1)*$"})]
        [string]$BinaryIPAddress
    )

    if ($BinaryIPAddress.Length -eq 128) {throw "IPv6 support is not implemented yet"}

    $Bin = $BinaryIPAddress  #required due to validation  
    $Bytes = @()
    while ($Bin.Length -ge 8) {
        $Byte = [convert]::ToInt32($Bin.Substring(0,8),2)
        $Bytes += $Byte
        $Bin = $Bin.Substring(8)

    }

    return $Bytes -join "."
}

function Get-NetworkPrefix {
    <#
    .Synopsis
    Returns a network address in CIDR format
       
    .Example
    #Returns 192.168.100.24/16
    Get-NetworkPrefix -IPAddress 192.168.100.24 -SubnetMask 255.255.0.0

    .Outputs
    String: representation of the network address in CIDR format
    #>
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ipaddress]$IpAddress,

        [Parameter(Mandatory=$true, Position=1)]
        [ipaddress]$SubnetMask
    )

    $NetworkAddress = ([ipaddress]($IpAddress.Address -band $SubnetMask.Address)).ToString()

    $CidrLength = (ConvertTo-Binary -IpAddress $SubnetMask).IndexOf('0')

    return "$NetworkAddress/$CidrLength"
}

function Test-IsInSameSubnet {
    <#
    .Synopsis
    Returns whether or not two or more IP Addresses are in the same subnet

    .Description
        
    .Example
    Test-IsInSameSubnet -IPAddresses 192.168.100.24, 192.168.102.65 -PrefixLength 24

    Returns false
    
    .Example
    Test-IsInSameSubnet -IPAddress 192.168.100.24 -NetworkPrefix 192.168.100.65/24
    
    Returns true

    .Outputs
    Boolean: Whether or not the specified IP addresses are in the same subnet

    .Notes
    Non-destructive
    
    #>
    [CmdletBinding(ConfirmImpact='Low')]
    [OutputType([bool])]

    param(
        [Parameter(Mandatory=$true, ParameterSetName='IPArray', Position=0)]
        [ValidateCount(2,100)]
        [ipaddress[]]$IPAddresses,
        [Parameter(Mandatory=$true, ParameterSetName='IPArray', Position=1)]
        [ValidateRange(0,32)]
        [int]$PrefixLength,

        [Parameter(Mandatory=$true, ParameterSetName='IPAndPrefix', Position=0)]
        [ipaddress]$IPAddress,
        [Parameter(Mandatory=$true, ParameterSetName='IPAndPrefix', Position=1)]
        [ValidateScript({$_ -match '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'})]
        [string]$NetworkPrefix             #CIDR format, e.g. 1.2.3.4/16
    )

    if ($PSCmdlet.ParameterSetName -like "IPAndPrefix") {
        $IPAddresses = @($IPAddress, [ipaddress]($NetworkPrefix -split '/')[0])
        $PrefixLength = ($NetworkPrefix -split '/')[1]
    }

    $BinaryIPs = $IPAddresses | %{ConvertTo-Binary -IPAddress $_}
    $BinaryPrefixes = $BinaryIPs | %{$_.Substring(0, $PrefixLength)}
    return !(($BinaryPrefixes | sort -Unique).Count -gt 1)

}


######### DNS utility function #########
function Invoke-Nslookup {
    <#
        .Synopsis
        Query DNS - for compatibility with versions that do not have the newer cmdlets

        .Description
        Query a DNS record 

        .Parameter Domain
        The name to resolve
            
        .Parameter DnsServer
        The server to query

        Parameter RecordType
        The type of the record
            
        .Output
        PSCustomObject
    #>
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Domain,

        [Parameter(Mandatory=$false, Position=1)]
        [string]$DnsServer,

        [Parameter(Mandatory=$false, Position=2)]
        [ValidateSet("A","AAAA","SRV","CNAME","PTR","NS","SOA")]   #Just add them as you need them
        [string]$RecordType="A"

    )
        
    $Invocation = "nslookup -querytype=$RecordType $Domain $DnsServer"
    $EapPush = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    Write-Debug "Invoking: $Invocation"
    $Text = (Invoke-Expression "$Invocation 2>`$null") -join "`n"
    $ErrorActionPreference = $EapPush

    <#
        $Pattern = '\w.+?(?=$|\n\s*(\n|$))'
    
        first expression: '\w.+?'
            starts with a word character
            '.+' => any sequence of characters
            '?' => non-greedy; matches up until the next capture expression

        second expression: (?=$|\n\s*(\n|$))
            '?=' => look-ahead group. Defines the end of the previous expression, but doesn't go into the output
            matches either '$' or '\n\s*(\n|$)'
            subexpression: '\n\s*(\n|$)'
                matches a blank line.
                must start with a newline '\n'
                contains any number of whitespace characters '\s*'
                then matches either another newline '\n' or end-of-string '$'

    #>
    $Pattern = '\w.+?(?=$|\n\s*(\n|$))'

    $HeaderText, $ResponseText = (
        [regex]::Matches(
            $Text, 
            $Pattern, 
            [System.Text.RegularExpressions.RegexOptions]::Singleline
        )
    ) | select -ExpandProperty Value
      
    Write-Debug '------ Server header --------------'
    if ($null -eq $HeaderText) {Write-Debug 'null'} else {Write-Debug $HeaderText}
    Write-Debug '------ Response -------------------'
    if ($null -eq $ResponseText) {Write-Debug 'null'} else {Write-Debug $ResponseText}

    $HasTimedOut = (
        ($ResponseText -match "(request .* timed out|No response from server)") -or
        ($ResponseText -match "^(DNS request timed out\.\n\s*timeout was \d+ seconds\.(\n|$))+$")
    )

    Write-Debug "Server timed out: $HasTimedOut"
    if ($HasTimedOut) {Write-Verbose "$DnsServer timed out"}

    
    $Output = @{}
    $Output.ConnectionSuccess = -not $HasTimedOut

    $Output.Response = switch ($RecordType) {
        "A"     {[string[]]([regex]::Matches($ResponseText, '(?:\d{1,3}\.){3}(?:\d{1,3})') | select -ExpandProperty Value)}
        "SRV"   {[string[]]([regex]::Matches($ResponseText, '(?:svr hostname   = ([\S\.]*))') | select -ExpandProperty Groups | select -Skip 1 -ExpandProperty Value)}
        default {$ResponseText}
    }

    return [pscustomobject]$Output
}


######### Larger test and set functions, for end users #########
function Add-IPAddressToPrimaryAdapter {
    <#
    .Synopsis
    Creates and configures an IP address on the primary network adapter
    
    .Description
    The primary network adapter is defined as the adapter that has the default gateway that has the highest metric.

    This function accepts an IP address and subnet mask, as a [System.Net.IPAddress] that has had extra properties added. To generate this input argument, pass an IP address object to New-SubnetIpAddress and specify either the SubnetMask or Cidr parameter.
    
    This function will not make changes if any of the following checks fail:
        DHCP is disabled
        The new IP address is already present on the adapter
        Multiple default gateways are configured on the adapter
        The new IP address, the default gateway and all the current IP addresses on the adapter are not all in the same subnet
        The new IP address is numerically between existing IP addresses on the adapter
        The new IP address is numerically closer to the default gateway than any existing IP addresses on the adapter
    Part of this is due to the -SkipAsSource behaviour.

    .Parameter NewIP
    The new IPv4 address to configure on the primary adapter

    .Parameter Force
    Skip confirmation dialogue

    .Example
    Add-IPAddressToPrimaryAdapter -NewIP 192.168.103.22

    Adds the address 192.168.103.22 to the primary network adapter

    .Output
    Diagnostic text
    #>

    [CmdletBinding(ConfirmImpact='Medium')]
    [OutputType([void])]

    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ipaddress]$NewIP,
        [switch]$Force
    )

    #https://msdn.microsoft.com/en-us/library/aa390383(v=vs.85).aspx
    $EnableStaticErrorLookup = @{
        '0'='Successful completion, no reboot required';
        '1'='Successful completion, reboot required';
        '64'='Method not supported on this platform';
        '65'='Unknown failure';
        '66'='Invalid subnet mask';
        '67'='An error occurred while processing an Instance that was returned';
        '68'='Invalid input parameter';
        '69'='More than 5 gateways specified';
        '70'='Invalid IP address';
        '71'='Invalid gateway IP address';
        '72'='An error occurred while accessing the Registry for the requested information';
        '73'='Invalid domain name';
        '74'='Invalid host name';
        '75'='No primary/secondary WINS server defined';
        '76'='Invalid file';
        '77'='Invalid system path';
        '78'='File copy failed';
        '79'='Invalid security parameter';
        '80'='Unable to configure TCP/IP service';
        '81'='Unable to configure DHCP service';
        '82'='Unable to renew DHCP lease';
        '83'='Unable to release DHCP lease';
        '84'='IP not enabled on adapter';
        '85'='IPX not enabled on adapter';
        '86'='Frame/network number bounds error';
        '87'='Invalid frame type';
        '88'='Invalid network number';
        '89'='Duplicate network number';
        '90'='Parameter out of bounds';
        '91'='Access denied';
        '92'='Out of memory';
        '93'='Already exists';
        '94'='Path, file or object not found';
        '95'='Unable to notify service';
        '96'='Unable to notify DNS service';
        '97'='Interface not configurable';
        '98'='Not all DHCP leases could be released/renewed';
        '100'='DHCP not enabled on adapter';
        #'2147786788'='Write lock not enabled. For more information, see INetCfgLock::AcquireWriteLock.'
        '2147786788'='Could not get exclusive write lock. Try running as administrator, and closing any other network configuration utilities'
    }

    #Unit testing - RaxNet.pester.ps1
    $TestReturnValues = @{
        '11110' = 'Test: setting IP address(es)'
        '11111' = 'Test: failed to set IP address(es) - IP / subnet count mismatch'
        '11112' = 'Test: Something wonky about the IPv4 addresses specified'
        '11113' = 'Test: No IP addresses specified to add'
    }
    $EnableStaticErrorLookup += $TestReturnValues

    $Log = @()

    $Adapter = Get-WmiAdapter -Primary | Add-AdapterMagic


    $Log += "Adapter $($Adapter.Name)"

    if ((-not $Force) -and ((Read-Host "Add $NewIP to adapter $($Adapter.Name) (Y/N)") -notlike "y")) {
        $Log += "User selected quit"
        return $Log
    }

    #PSv2 hack
    if ($Adapter.IPAddresses -is [array]) {
        $ExistingIpAddresses = $Adapter.IPAddresses
    } else {
        $ExistingIpAddresses = @(,$Adapter.IPAddresses)
    }

    #Test Multiple subnets on interface
    $NetworkPrefix = $ExistingIpAddresses[0].GetNetworkPrefix()
    if ($NetworkPrefix -notlike $ExistingIpAddresses[-1].GetNetworkPrefix()) {
        $Log += "Multiple subnets on interface; quitting"
        return $Log
    }

    $IP = New-SubnetIpAddress -Ip $NewIP -Cidr ($NetworkPrefix -replace '^[^/]*/')

    #Test DHCP is enabled
    if ($Adapter.DHCPEnabled) {
        $Log += "DHCP is enabled; quitting"
        return $Log
    }

    #Test IP is already present
    if (($ExistingIpAddresses | select -ExpandProperty IPAddressToString) -contains $IP.IPAddressToString) {
        $Log += "$IP is already present; quitting"
        return $Log
    }
    
    #Test Not exactly one default gateway on interface
    if ($Adapter.DefaultGateway.Count -gt 1) {
        $Log += "Not exactly one default gateway on interface; quitting"
        return $Log
    }

    #Check arp to see if the address exists on the subnet already
    [void](ping $IP -n 2 -w 100)
    $Arp = arp -a | Select-String ([regex]::Escape($IP.ToString())) | Select-String '^invalid'
    if ($Arp) {
        $Mac = $Arp -split ' ' | where {$_ -match '([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}'}
        $Log += "$IP is assigned to device with MAC address $Mac; quitting"
        return $Log
    }
    
    #Test Default gateway not in same subnet
    $GW = New-SubnetIpAddress -Ip $Adapter.DefaultGateway -Cidr ($NetworkPrefix -replace '^[^/]*/')
    if ($GW.GetNetworkPrefix() -notlike $NetworkPrefix) {
        $Log += "Default gateway not in same subnet; quitting"
        return $Log
    }

    #Test New IP address not in same subnet
    if (-not (Test-IsInSameSubnet -NetworkPrefix $NetworkPrefix -IPAddress $IP)) {
        $Log += "New IP address not in same subnet; quitting"
        return $Log
    }

    #Test Default gateway falls inside range of existing IP addresses
    $GwCompare = $GW.CompareTo($ExistingIpAddresses[0]) + $GW.CompareTo($ExistingIpAddresses[-1])
    if ([Math]::Abs($GwCompare) -ne 2) {
        Must be on the same side as both first and last, and not the same as either
        Example: ([int]1).CompareTo(([int]2)) + ([int]1).CompareTo(([int]9));   ([int]11).CompareTo(([int]2)) + ([int]11).CompareTo(([int]9))
        $Log += "Default gateway falls inside range of existing IP addresses; quitting"
        return $Log
    }

    #Test New IP address falls inside range of existing IP addresses
    $IPCompare = $IP.CompareTo($ExistingIpAddresses[0]) + $IP.CompareTo($ExistingIpAddresses[-1])
    if ([Math]::Abs($IPCompare) -ne 2) {
        $Log += "New IP address falls inside range of existing IP addresses; quitting"
        return $Log
    }

    #Test New IP address is closer to default gateway than existing IP addresses
    if (($IPCompare + $GwCompare) -ne 0) {
        $Log += "New IP address is closer to default gateway than existing IP addresses; quitting"
        return $Log
    }


    #EnableStatic takes two string arrays - an array of IPs and an array of subnet masks. The two must tally up.
    #https://msdn.microsoft.com/en-us/library/aa390383(v=vs.85).aspx
    #It does not change IPv6 settings, and it does not accept IPv6 addresses.
    [string[]]$WmiIPs = $ExistingIpAddresses + $IP | foreach {$_.ToString()}
    [string[]]$WmiMasks = $ExistingIpAddresses + $IP | foreach {$_.SubnetMask.ToString()}
    #return $Log + $EnableStaticErrorLookup['11110']
    $WmiResult = $Adapter.WmiConfiguration.EnableStatic($WmiIPs, $WmiMasks)

    $ReturnValue = $WmiResult.ReturnValue.ToString()
    #$ReturnValue = '11110'
    if ($EnableStaticErrorLookup.ContainsKey($ReturnValue)) {
        $Log += $EnableStaticErrorLookup[$ReturnValue]
    } else {
        $Log += "IP addition failed with unknown return code $ReturnValue"
    }

    return $Log
}


function Get-RaxNetAdapter {
    <#
        .Synopsis
        Get network adapters

        .Description
        Returns custom objects representing network adapters, for IP configuration and other tasks. They have a number of properties derived from the WMI Win32_NetworkAdapter and Win32_NetworkAdapterConfiguration classes.

        The associated WMI classes, Win32_NetworkAdapter and Win32_NetworkAdapterConfiguration, are available on the object as the WmiAdapter and WmiConfiguration properties. These are script proerties that query WMI each time they are examined, so they are always current.

        .Parameter Primary
        return the primary IP adapter, as chosen by examination of the routing table. The primary adapter is defined as the one that has the highest-metric default gateway.

        .Parameter Identity
        return adapter by display name (as configured in ncpa.cpl)

        .Parameter IncludeUnnamed
        also return adapters that have no display name configured in ncpa.cpl, e.g. Bluetooth adapters.

        .Example
        PS C:\> Get-RaxNetAdapter

        Name                   IPAddresses    DefaultGateway DnsServers                              
        ----                   -----------    -------------- ----------                              
        Ethernet               10.2.216.178   10.2.216.1     {10.2.204.154, 10.9.97.172, 10.9.97.179}
        Npcap Loopback Adapter 169.254.206.97                                                        
        Ethernet 2                                                                                   

        Returns all the named network adapters in the system


        .Example
        PS C:\> Get-RaxNetAdapter -IncludeUnnamed

        Name                   IPAddresses    DefaultGateway DnsServers                              
        ----                   -----------    -------------- ----------                              
                                                                                             
        Ethernet               10.2.216.178   10.2.216.1     {10.2.204.154, 10.9.97.172, 10.9.97.179}
                                                                                             
        Npcap Loopback Adapter 169.254.206.97                                                        
        Ethernet 2                                                                                   
                                                                                             
        Also includes unnamed adapters, such as Bluetooth adapters.


        .Example
        PS C:\> Get-RaxNetAdapter -Identity Ethernet

        Name     IPAddresses  DefaultGateway DnsServers                              
        ----     -----------  -------------- ----------                              
        Ethernet 10.2.216.178 10.2.216.1     {10.2.204.154, 10.9.97.172, 10.9.97.179}

        Returns adapter by name


        .Example
        PS C:\> Get-RaxNetAdapter -Primary

        Name     IPAddresses  DefaultGateway DnsServers                              
        ----     -----------  -------------- ----------                              
        Ethernet 10.2.216.178 10.2.216.1     {10.2.204.154, 10.9.97.172, 10.9.97.179}

        Returns the adapter with the default gateway (if multiple adapters have default gateways, it returns the one with the highest metric in the system route table)


        .Example
        PS C:\> Get-RaxNetAdapter -Primary | fl *


        Name                         : Ethernet
        PSComputerName               : DustyDesktop
        CreationClassName            : Win32_NetworkAdapter
        ProductName                  : Intel(R) Ethernet Connection I217-LM
        ServiceName                  : e1dexpress
                    ...output abridged...
        FullDNSRegistrationEnabled   : True
        IPConnectionMetric           : 20
        IPEnabled                    : True
        IPSubnet                     : {255.255.255.0, 64}
        MTU                          : 
        DnsServers                   : {10.2.204.154, 10.9.97.172, 10.9.97.179}
        DefaultGateway               : 10.2.216.1
        IPAddresses                  : 10.2.216.178
        IPv6Addresses                : 

        Explore some of the properties returned


        .Example
        PS C:\> $Adapter = Get-RaxNetAdapter -Primary

        PS C:\> $Adapter.WmiConfiguration.__CLASS
        Win32_NetworkAdapterConfiguration

        PS C:\> $Adapter.WmiConfiguration.SetDNSServerSearchOrder('10.2.204.154')


        __GENUS          : 2
        __CLASS          : __PARAMETERS
        __SUPERCLASS     : 
        __DYNASTY        : __PARAMETERS
        __RELPATH        : 
        __PROPERTY_COUNT : 1
        __DERIVATION     : {}
        __SERVER         : 
        __NAMESPACE      : 
        __PATH           : 
        ReturnValue      : 91
        PSComputerName   : 

        The WmiConfiguration property returns the associated Win32_NetworkAdapterConfiguration class. This is queried each time you examine the property. You can invoke the methods of the WMI class. Likewise, the .WmiAdapter property returns the associated Win32_NetworkAdapter class.

        .Outputs
        PSCustomObjects representing network adapters
    #>
    [CmdletBinding(DefaultParameterSetName='Default')]
    [OutputType([System.Management.ManagementObject[]])]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='Primary')]
        [switch]$Primary,

        [Parameter(Mandatory=$true, ParameterSetName='Identity', Position=0)]
        [string]$Identity,

        [Parameter(Mandatory=$true, ParameterSetName='IncludeUnnamed')]
        [switch]$IncludeUnnamed
    )

    Get-WmiAdapter @PSBoundParameters | Add-AdapterMagic
}

function Test-DnsServer {
<#
    .Synopsis
    Tests DNS servers

    .Description
    Tests DNS servers for A records from an AD domain and the PDC locator SRV record.

    Returns psobject with valid servers, not-responding servers, and invalid servers (servers that did not return the expected records)

    .Parameter AdDomain
    Specify the DNS name of the AD domain to test. Default: the machine's domain (or workgroup name, which will usually not be valid)

    .Parameter DnsServers
    Specify the IP addresses of the DNS servers to test. Default: the DNS servers configured on the primary network adapter
#>
    param(
        [string]$AdDomain = ((Get-WmiObject Win32_ComputerSystem).Domain),
        [ipaddress[]]$DnsServers = (Get-WmiAdapter -Primary).DnsServers
    )

    $Output = New-Object psobject -Property @{
        ValidServers = @();
        InvalidServers = @();
        NonResponsiveServers = @();
    }

    foreach ($DnsServer in $DnsServers) {
        $DomainA = Invoke-Nslookup $AdDomain $DnsServer
        if (-not $DomainA.ConnectionSuccess) {
            $Output.NonResponsiveServers += $DnsServer; continue
        }
        if (-not $DomainA.Response) {
            $Output.InvalidServers += $DnsServer; continue
        }
        
        $Pdc = Invoke-Nslookup "_ldap._tcp.pdc._msdcs.$AdDomain" $DnsServer "SRV"
        if ($Pdc.Response) {
            $Output.ValidServers += $DnsServer
        } else {
            $Output.InvalidServers += $DnsServer
        }
    }
    
    return $Output
}
'@

 
[void](New-Module -Name Formatting -ScriptBlock ([scriptblock]::Create($FormattingPsm1)))
[void](New-Module -Name RaxNet -ScriptBlock ([scriptblock]::Create($RaxNetPsm1)))

#endregion Module Import



    [ipaddress[]]$DnsServerIPs = $DnsServers
    
    $WmiObj = Get-WmiObject Win32_ComputerSystem

    $Domain = $WmiObj.Domain
    
    $Output = Test-DnsServer -DnsServers $DnsServerIPs -AdDomain $Domain

    
    return $Output
}
