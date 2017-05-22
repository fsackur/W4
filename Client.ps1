

function Prompt {
    $realLASTEXITCODE = $LASTEXITCODE
    
    #Display currently-selected devices
    $DeviceBanner = if ($Global:WHAM_DEVICES -and $Global:WHAM_DEVICES.Count -gt 0) {
        [string]::Format("Devices: [{0}]", ($Global:WHAM_DEVICES -join ', '))
    } else {
        "Devices: [None selected]"
    }       
    Write-Host -NoNewline -ForegroundColor DarkYellow $DeviceBanner
    
    $global:LASTEXITCODE = $realLASTEXITCODE

    return "`nWHAM> "   
}


#http://patorjk.com/software/taag/#p=display&f=Electronic
$Banner = "
 ▄         ▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄       ▄▄ 
▐░▌       ▐░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░▌     ▐░░▌
▐░▌       ▐░▌▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌░▌   ▐░▐░▌
▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌▐░▌ ▐░▌▐░▌
▐░▌   ▄   ▐░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌ ▐░▐░▌ ▐░▌
▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌  ▐░▌  ▐░▌
▐░▌ ▐░▌░▌ ▐░▌▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌   ▀   ▐░▌
▐░▌▐░▌ ▐░▌▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
▐░▌░▌   ▐░▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
▐░░▌     ▐░░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌
 ▀▀       ▀▀  ▀         ▀  ▀         ▀  ▀         ▀ 
To set devices for a run, use Get-Device, Set-Device (overwrites) and Add-Device.
For a list of templates, enter: Get-Command
For general help, enter: Get-Help about_Wham
"

Clear-Host
Write-Host $Banner -ForegroundColor Gray


#region Manipulate the current list of devices
function Get-Device {
    param(
        [ValidateRange(0, 999999)]
        [int[]]$Device
    )
    $Global:WHAM_DEVICES = $Device

}

function Set-Device {
    param(
        [ValidateRange(0, 999999)]
        [int[]]$Device
    )
    $Global:WHAM_DEVICES = $Device | sort -Unique

}

function Add-Device {
    param(
        [ValidateRange(0, 999999)]
        [int[]]$Device
    )
    $Global:WHAM_DEVICES = (
        $Global:WHAM_DEVICES + $Device | sort -Unique

    )

}
#endregion Manipulate the current list of devices




Import-Module $PSScriptRoot\Templates.psm1 -Force




#############DEMO CODE##################
#From her onwards, it's test and demo code.
#This will be worked up into unit tests.


function ConvertFrom-Json2 {
    #This creates hashtables with minimum fuss; ConvertFom-Json creates PSCustomObject
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$InputObject
    )

    $Parser = New-Object Web.Script.Serialization.JavaScriptSerializer
    $Parser.MaxJsonLength = $InputObject.length
    Write-Output -NoEnumerate $Parser.DeserializeObject($InputObject)
}


$ApiHeaders = Get-Something -DoNothing -SomeNumber 12

$ActualParameters = ConvertFrom-Json2 $ApiHeaders.ScriptParameters

Get-Something @ActualParameters  #Should Not Throw
