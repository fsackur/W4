

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


function Invoke-WhamApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Command,

        [hashtable]$Parameters = @{}
    )

    $ApiHeaders = @{
        AuthToken = 'deadbeefdeadbeef'
        Devices = $Global:WHAM_DEVICES
        ScriptName = $Command
        ScriptParameters = (ConvertTo-Json $Parameters -Depth 10 -Compress) -replace '{"IsPresent":true}', 'true'
    }

    $Response = Invoke-RestMethod -Uri "$Url/Invoke" -Method GET -Headers $ApiHeaders
    
    <#
    Write-Host -ForegroundColor Green ((
        "Invoking rest method:",
        "`tUri     : https://wham.rax.io",
        "`tVerb    : GET",
        "`theaders :",
        ($ApiHeaders.GetEnumerator() | %{[string]::Format(
            "`t`t{0,-18}: {1}",
            $_.Key,
            $_.Value
            )} | Out-String
        )
    ) -join "`n")

    $ApiHeaders
    #>

    $Response
}




#############DEMO CODE##################
#From her onwards, it's test and demo code.
#This will be worked up into unit tests.

$Url = 'http://127.0.0.1:8081'

function Start-WhamServer {
    Start-Process powershell.exe -ArgumentList '-NoProfile', '-File', '.\Server\WhamServer.ps1', $Url
}

function Stop-WhamServer {
    $null = Invoke-WebRequest "$Url/end"
}




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


Get-Something -DoNothing -SomeNumber 12


