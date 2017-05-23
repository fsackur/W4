<#
    This is the simplest possible implementation of the Wham API.

    Typical use:
    .\WhamServer.ps1 -Binding 'http://127.0.0.1:80'

    Then observe the output:
    Invoke-WebRequest "http://127.0.0.1:80" | select -ExpandProperty RawContent
    Invoke-WebRequest "http://127.0.0.1:80/end" | select -ExpandProperty RawContent

#>
[CmdletBinding()]
[OutputType([void])]
param (
    [Parameter(Position=0)]
    [ValidateScript({return (
            $_.IsWellFormedOriginalString() -and
            $_.IsAbsoluteUri -and
            $_.Scheme -eq "http"   #no SSL config to worry about
    )})]
    [uri]$Binding = 'http://127.0.0.1:8081'
)

$KillUrl = $Binding.AbsoluteUri + 'end'

$StartDate = [string](Get-Date)

$Host.UI.RawUI.WindowTitle = "Wham test server"


#intialise
$Listener = New-Object System.Net.HttpListener
$Listener.Prefixes.Add($Binding.AbsoluteUri)



try {
    $Listener.Start()
} catch [System.Net.HttpListenerException] {
    #Already running on this binding, so quit
    if ($_.Exception -like "*conflicts with an existing registration on the machine.*") {
        Write-Host "Binding $Binding is already in use"
        return
    }
}

Write-Host "Listening at $($Binding.AbsoluteUri). To kill:  Invoke-WebRequest $KillUrl   ..."


while ($Listener.IsListening) {

    $Context = $Listener.GetContext()
    $RequestUrl = $Context.Request.Url
    $Response = $Context.Response
    $RequestQuery = $RequestUrl.LocalPath


    Write-Host ''
    Write-Host "> $RequestUrl"


    #Prepare content based on query
    switch ($RequestQuery) {
        '/end' {
            $Response.Close()
            $Listener.Stop()
            return
        }


        '/Invoke' {
            #Get-Content returns array of string; this joins into single multi-line string
            $Content = & $PSScriptRoot\WhamRunner.ps1 -Context $Context 
            break
        }


        default {
            $Content = "WhamTester - serving up mock wham runs since $StartDate. Process ID: $PID`n`nTo terminate, send GET to: $KillUrl"
        }
    }


    #serve the content
    $Buffer = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $Response.AddHeader("ContentType", "text/plain")
    $Response.AddHeader("Accept-Ranges", "bytes")
    $Response.ContentLength64 = $Buffer.Length
    $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)


    #close
    $Response.Close()

    $ResponseStatus = $Response.StatusCode
    Write-Host "< $ResponseStatus"


}

try {
    $Listener.Stop()
} catch {

} finally {
    $Listener.Dispose()
}
