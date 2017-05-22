<#
    .Synopsis
    The library of available script from the script repository
    
    .Description
    This module file contains scripts from the repository to be run on customer devices.

    The functions have been stubbed out. The parameter blocks are the same, but the function
    bodies have been replaced with code that invokes the API (using StubCommmand).

    Certain global variables are provided by the Wham client

    Todo: auto-generate using Jenkins on push to the script repository
    
    
    .Link
    https://github.com/indented-automation/Indented.StubCommand
#>



function Get-Something {
    <#
        .Synopsis
        Get a thing, possibly do some stuff

        .Description
        This help will be the cmdlet help from the real Get-SOmething command in the repository
    #>
    [CmdletBinding()]
    param(
        [switch]$DoNothing,
        
        [int]$SomeNumber,

        [string[]]$CapitalCities
    )



    begin {
        #Execution metrics - client time
        $Stopwatch = [System.Diagnostics.Stopwatch]::startNew()
    }


    end {
        
        $ApiHeaders = @{
            AuthToken = 'deadbeefdeadbeef'
            Devices = $Global:WHAM_DEVICES
            ScriptName = $PSCmdlet.MyInvocation.MyCommand.Name
            ScriptParameters = (ConvertTo-Json $PSBoundParameters -Depth 10 -Compress) -replace '{"IsPresent":true}', 'true'
        }

        #$Response = Invoke-RestMethod -Uri 'https://wham.rax.io' -Method GET -Headers $ApiHeaders
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
        

        $Stopwatch.Stop()
        $Elapsed = $Stopwatch.Elapsed.ToString() -replace '00:' -replace '00\.', '0.'
        Write-Host -ForegroundColor Gray "Command executed in $Elapsed seconds"

        $ApiHeaders
    }

}
