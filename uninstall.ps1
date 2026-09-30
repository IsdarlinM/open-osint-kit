$ErrorActionPreference = "Stop"

$pythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($pythonCommand) {
    $python = $pythonCommand.Source
    $pythonArgs = @("-3")
} else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw "Python was not found. The package cannot be uninstalled with pip."
    }
    $python = $pythonCommand.Source
    $pythonArgs = @()
}

& $python @pythonArgs -m pip uninstall --yes open-osint-kit
if ($LASTEXITCODE -ne 0) {
    throw "pip could not uninstall open-osint-kit."
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
    Write-Host "Removed the PATH entry added by Open OSINT Kit: $ownedScriptsPath"
} else {
    Write-Host "Kept the Python PATH entry because this installation did not register it as kit-owned."
}

Write-Host "Open OSINT Kit was uninstalled. Shared dependencies such as phonenumbers were kept."
