<#
    .Synopsis
    The library of available script from the script repository
    
    .Description
    This module file contains scripts from the repository to be run on customer devices.

    The functions have been stubbed out. The parameter blocks are the same, but the function
    bodies have been replaced with code that invokes the API (using StubCommmand).


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
        
        Invoke-WhamApi `
            -Command $PSCmdlet.MyInvocation.MyCommand.Name `
            -Parameters $PSBoundParameters       

        $Stopwatch.Stop()
        $Elapsed = $Stopwatch.Elapsed.ToString() -replace '00:' -replace '00\.', '0.'
        Write-Host -ForegroundColor Gray "Command executed in $Elapsed seconds"

    }

}
