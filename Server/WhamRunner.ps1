param(
    $Context
)

Write-Host "here"

#return $Context


$Headers = @{}
for ($i = 0; $i -lt $Context.Request.Headers.Count; $i++) {
    $Headers.Add($Context.Request.Headers.GetKey($i), $Context.Request.Headers.Get($i))
}
return $Headers | ConvertTo-Json -Depth 10