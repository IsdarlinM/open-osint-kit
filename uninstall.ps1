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

if (-not [Console]::IsInputRedirected) {
    $purgeAnswer = Read-Host "Also delete generated build artifacts and the stored Shodan key? [y/N]"
    if ($purgeAnswer -match "^(y|yes)$") {
        & $python @pythonArgs -c "import keyring; keyring.delete_password('open-osint-kit', 'shodan-api-key')" 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "The Shodan key could not be removed from the OS keyring; remove it manually if needed."
        }
        foreach ($artifact in @("build", "dist", "open_osint_kit.egg-info", "__pycache__")) {
            $artifactPath = Join-Path $PSScriptRoot $artifact
            if (Test-Path $artifactPath) {
                Remove-Item -Recurse -Force $artifactPath
                Write-Host "Removed generated artifact: $artifactPath"
            }
        }
    } else {
        Write-Host "Kept generated artifacts and the Shodan key."
    }
} else {
    Write-Host "Non-interactive session detected; kept generated artifacts and the Shodan key."
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
