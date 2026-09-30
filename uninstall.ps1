$ErrorActionPreference = "Stop"

$pythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($pythonCommand) {
    $python = $pythonCommand.Source
    $pythonArgs = @("-3")
} else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw "No se encontró Python. No se puede desinstalar el paquete con pip."
    }
    $python = $pythonCommand.Source
    $pythonArgs = @()
}

& $python @pythonArgs -m pip uninstall --yes open-osint-kit
if ($LASTEXITCODE -ne 0) {
    throw "pip no pudo desinstalar open-osint-kit."
}

$ownedScriptsPath = [Environment]::GetEnvironmentVariable("OPEN_OSINT_KIT_ADDED_PATH", "User")
if ($ownedScriptsPath) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathEntries = @($userPath -split ";" | Where-Object { $_ })
    $remainingEntries = @($pathEntries | Where-Object {
        $_.TrimEnd("\") -ine $ownedScriptsPath.TrimEnd("\")
    })
    [Environment]::SetEnvironmentVariable("Path", ($remainingEntries -join ";"), "User")
    [Environment]::SetEnvironmentVariable("OPEN_OSINT_KIT_ADDED_PATH", $null, "User")
    $env:Path = @($env:Path -split ";" | Where-Object {
        $_.TrimEnd("\") -ine $ownedScriptsPath.TrimEnd("\")
    }) -join ";"
    Write-Host "Se retiró del PATH la entrada añadida por Open OSINT Kit: $ownedScriptsPath"
} else {
    Write-Host "Se conservó el PATH de Python porque esta instalación no registró una ruta propia."
}

Write-Host "Open OSINT Kit fue desinstalado. Las dependencias compartidas, como phonenumbers, se conservaron."
