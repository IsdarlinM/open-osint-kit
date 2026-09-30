$ErrorActionPreference = "Stop"

$pythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($pythonCommand) {
    $python = $pythonCommand.Source
    $pythonArgs = @("-3")
} else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw "Python 3.9+ was not found. Install it, then run this script again."
    }
    $python = $pythonCommand.Source
    $pythonArgs = @()
}

$isVirtualEnvironment = & $python @pythonArgs -c "import sys; print(int(sys.prefix != sys.base_prefix))"
if ($LASTEXITCODE -ne 0) {
    throw "Python could not be run."
}
if ($isVirtualEnvironment.Trim() -eq "1") {
    throw "Deactivate the virtual environment before installing the user command."
}

Write-Host "Installing Open OSINT Kit with verbose output..."
& $python @pythonArgs -m pip install --user --upgrade --force-reinstall --verbose $PSScriptRoot
if ($LASTEXITCODE -ne 0) {
    throw "Installation failed. Make sure pip is available, then try again."
}

$scriptsPath = (& $python @pythonArgs -c "import sysconfig; print(sysconfig.get_path('scripts', 'nt_user'))").Trim()
if (-not $scriptsPath) {
    throw "Could not determine the Python scripts directory."
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ";" | Where-Object { $_ })
if (-not ($pathEntries | Where-Object { $_.TrimEnd("\") -ieq $scriptsPath.TrimEnd("\") })) {
    $newUserPath = (@($pathEntries) + $scriptsPath) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
    [Environment]::SetEnvironmentVariable("OPEN_OSINT_KIT_ADDED_PATH", $scriptsPath, "User")
}
$env:Path = "$scriptsPath;$env:Path"

Write-Host "Installed. Run: osint-kit --help"
Write-Host "Open a new terminal for the updated PATH to apply to other sessions."
