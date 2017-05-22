

function Prompt {
    $realLASTEXITCODE = $LASTEXITCODE
    
    #Display currently-selected devices
    $DeviceBanner = if ($Global:WHAM_DEVICES -and $Global:WHAM_DEVICES.Count -gt 0) {
        [string]::Format("Devices: [{0}]", ($Global:WHAM_DEVICES -join ', '))
    } else {
        "Devices: [None selected]"
    }       
    Write-Host -ForegroundColor DarkYellow $DeviceBanner
    
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




function Get-Hostname {
    #THis is a mock of a script template that you might run
    [CmdletBinding()]
    param(
        [switch]$DoNothing,
        
        [int]$SomeNumber,

        [string[]]$CapitalCities
    )

    begin {
        $Stopwatch = [System.Diagnostics.Stopwatch]::startNew()
    }


    end {
        $ApiHeaders = @{
            AuthToken = 'deadbeefdeadbeef'
            Devices = $Global:WHAM_DEVICES
            ScriptName = $PSCmdlet.MyInvocation.MyCommand.Name
            ScriptParameters = (ConvertTo-Json $PSBoundParameters -Depth 10 -Compress) -replace '{"IsPresent":true}', 'true'
        }
    
        Write-Host -ForegroundColor Green `
"Invoking rest method:
https://wham.rax.io 
PUT
headers:
$($ApiHeaders | Out-String)"
        
        $Stopwatch.Stop()
        $Elapsed = $Stopwatch.Elapsed.ToString() -replace '00:' -replace '00\.', '0.'
        Write-Host -ForegroundColor Gray "Command executed in $Elapsed seconds"

        $ApiHeaders
    }

}

$Api = Get-Hostname -DoNothing -SomeNumber 12

$ActualParameters = ConvertFrom-Json2 $Api.ScriptParameters

Get-Hostname @ActualParameters
