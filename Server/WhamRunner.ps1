param(
    [System.Net.WebHeaderCollection]$Headers
)


function Get-ComputerInfo {
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [int[]]$Devices
    )

    process {
        foreach ($Device in $Devices) {
            $ComputerName = switch ($device) {
                111333  {"Nano1"}
                222444  {"Nano2"}
                default {"No servers for you."}
            }

            Write-Output (New-Object psobject -Property @{ComputerName = $ComputerName})
        }
    }
}


$AuthToken = $Headers["AuthToken"]
$Devices = $Headers["Devices"] -split ','
$ScriptName = $Headers["ScriptName"]
$ScriptParameters = ConvertFrom-Json $Headers["ScriptParameters"]


#Stop illicit commands being run
ipmo $PSScriptRoot\..\Templates.psm1
if ($(Get-Command -Module Templates | select -ExpandProperty Name) -notcontains $ScriptName) {
    throw "Toys out of the pram"
}

$ComputerInfos = $Devices | Get-ComputerInfo

$ComputerInfos | %{
    Invoke-Command -ComputerName $_.ComputerName -ScriptBlock {gci C:\}

}

#return $Hashtable | ConvertTo-Json -Depth 10



