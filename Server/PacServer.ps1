<#
    This is a simple web server to serve a PAC file.

    Typical use:
    PacServer -PacFilePath 'C:\Proxy.Pac' -Binding 'http://127.0.0.1:8080'

    Then observe the output:
    Invoke-WebRequest "http://127.0.0.1:8080" | select -ExpandProperty RawContent
    Invoke-WebRequest "http://127.0.0.1:8080/Proxy.pac" | select -ExpandProperty RawContent
    Invoke-WebRequest "http://127.0.0.1:8080/end" | select -ExpandProperty RawContent

    Warning: if set, the PAC file is called often in WIndows. If you will have a long PAC file, you should optimise for performance.

#>
[CmdletBinding()]
[OutputType([void])]
param (
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, ValueFromRemainingArguments=$false, Position=0)]
    [ValidateScript({Test-Path $_})]
    [Alias("Path")]
    [string]$PacFilePath,

    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, ValueFromRemainingArguments=$false, Position=1)]
    [ValidateScript({return (
            $_.IsWellFormedOriginalString() -and
            $_.IsAbsoluteUri -and
            $_.Scheme -eq "http"   #no SSL config to worry about
    )})]
    [uri]$Binding
)


#Caution, scripters... sanitise URLs to stop use of \..\ to get out of the base dir
$BaseDir = Split-Path $PacFilePath -Parent
$PacFileName = Split-Path $PacFilePath -Leaf


$PacQueryStem = '/' + $PacFileName

$PacUrl = $Binding.AbsoluteUri + $PacFileName
$KillUrl = $Binding.AbsoluteUri + 'end'

$StartDate = [string](Get-Date)

$Host.UI.RawUI.WindowTitle = "Proxy PAC file server"



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

Write-Host "Listening at $($Binding.AbsoluteUri)..."



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


        $PacQueryStem {
            #Get-Content returns array of string; this joins into single multi-line string
            $Content = (Get-Content $PacFilePath) -join "`n"
            break
        }


        default {
            $Content = "Pacman - serving up proxy auto-configuration scripts since $StartDate. Process ID: $PID`nFor PAC script, send GET to: $PacUrl`nTo terminate, send GET to: $KillUrl"
        }
    }


    #serve the content
    $Buffer = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $Response.AddHeader("ContentType", "text/plain")
    #$Response.AddHeader("ContentType", "application/x-ns-proxy-autoconfig")
    $Response.AddHeader("Accept-Ranges", "bytes")
    $Response.ContentLength64 = $Buffer.Length
    $Response.OutputStream.Write($Buffer, 0, $Buffer.Length)


    #close
    $Response.Close()

    $ResponseStatus = $Response.StatusCode
    Write-Host "< $ResponseStatus"


}

$Listener.Stop()
$Listener.Dispose()
