<#
    .Synopsis
    A sketch of an API client and server for running script from a library on a selection of remote computers


#>
#requires -Modules PowerShellGet

#Required modules
try {
    Import-Module Indented.StubCommand -ErrorAction Stop
} catch [System.IO.FileNotFoundException] {
    Install-Module Indented.StubCommand -Scope CurrentUser -Repository PSGallery -Force
} finally {
    Import-Module Indented.StubCommand -ErrorAction Stop
}



#region Import script library and inject API calls in the function body
$LibraryPath = 'C:\dev\W4\Templates'

#This replaces the function body in all functions in the library
$FunctionBody = {
    if (-not $Global:WHAM_DEVICES) {
        Write-Host -NoNewline -ForegroundColor Red "No devices selected. "
        Write-Host -ForegroundColor DarkYellow "Use Add-Device or Set-Device to select servers for script execution."
        return
    }
    #Execution metrics - client time
    $Stopwatch = [System.Diagnostics.Stopwatch]::startNew()

    Invoke-WhamApi `
        -Command $PSCmdlet.MyInvocation.MyCommand.Name `
        -Parameters $PSBoundParameters

    if ($Stopwatch) {
        $Stopwatch.Stop()
        $Elapsed = $Stopwatch.Elapsed.ToString() -replace '00:' -replace '00\.', '0.'
        Write-Host -ForegroundColor Gray "Command executed in $Elapsed seconds"
    }
}

Get-ChildItem $LibraryPath -Filter '*.psm1' | select -First 10 | foreach {
    Write-Verbose ("Stubbing " + $_.BaseName)
    New-StubModule -FromModule $_.FullName -FunctionBody $FunctionBody | Out-String | Invoke-Expression
}
#endregion Import script library and inject API calls in the function body




#Prompt shows currently-selected devices
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






function Invoke-WhamApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Command,

        [hashtable]$Parameters = @{}
    )

    $ApiHeaders = @{
        AuthToken = 'deadbeefdeadbeef'
        Devices = $Global:WHAM_DEVICES -join ','
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
#From here onwards, it's test and demo code.
#This will be worked up into unit tests.

$Url = 'http://127.0.0.1:8082'

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


$W = Get-Something -DoNothing -SomeNumber 12

$W
