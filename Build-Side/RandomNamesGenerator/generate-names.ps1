


Remove-Item -Path ".\Random-Names.txt" -Force

$baseNames = Get-content ".\baseNames.txt"
$endingNames = Get-content ".\endingNames.txt"

foreach ($baseName in $baseNames)
{
    foreach ($endingName in $endingNames)
    {
        Add-Content -Path ".\Random-Names.txt" -Value "$baseName $endingName"
    }
}


while ($true)
{
    $randomGuid = ([guid]::NewGuid().Guid).ToUpper()
    $intelRandomName = "Intel Package Cache {$randomGuid}"
    Add-Content -Path ".\Random-Names.txt" -Value "$intelRandomName"

    $randomGuid = ([guid]::NewGuid().Guid).ToLower()
    $mozillaRandomName = "Mozilla-$randomGuid"
    Add-Content -Path ".\Random-Names.txt" -Value "$mozillaRandomName"
}

