<#
    Validates the javascript in a PAC file.

    The ScriptControl COM object is 32-bit, so this needs to be run in a 32-bit PS host.

    Invocation:
    Invoke-Expression "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -File C:\GithubPublic\Pacman\PacTester.ps1"

#>
[CmdletBinding(DefaultParameterSetName="Url")]
param(
    [Parameter(ParameterSetName="Url")]
    [string]$PacUrl = ("http://127.0.0.1:8080/Proxy.pac"),

    [Parameter(ParameterSetName="Filepath")]
    [string]$PacFilePath = (Join-Path $env:LOCALAPPDATA "Pacman\Proxy.pac"),

    [string[]]$TestHosts = @(
        "test.com",
        "127.0.0.1",
        "1.1.1.1",
        "1.1.1.3",
        "1.2.3.4",
        "31.222.128.22",
        "64.182.208.181",
        "95.138.147.101"
    )
)

if ([Environment]::Is64BitProcess) {
    throw "The tester requires 32-bit host. Run within 'Powershell (x86)' (C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe)"
}

[string]$PacToTest

if ($PacUrl) {
    $PacToTest = (
            (Invoke-WebRequest $PacUrl | select -ExpandProperty RawContent)  -split "`n" |
            ?{$_ -notmatch "^(HTTP/|ContentType:|Accept-Ranges:|Content-Length:|Date:|Server:)"}
        ) -join "`n"

} else {
    $PacToTest = (Get-Content $PacFilePath) -join "`n"
}


$ScriptCom = New-Object -ComObject ScriptControl
$ScriptCom.Language = "JScript"
$ScriptCom.AddCode($PacToTest)


foreach ($TestHost in $TestHosts) {
    $Url = "http://$TestHost/query"
    $result = $ScriptCom.CodeObject.FindProxyForURL($Url, $TestHost)
    Write-Host ($Url.PadRight(40, ' ') + $result)
}