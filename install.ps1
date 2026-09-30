$ErrorActionPreference = "Stop"

$pythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($pythonCommand) {
    $python = $pythonCommand.Source
    $pythonArgs = @("-3")
} else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw "No se encontró Python 3.9+. Instálalo y vuelve a ejecutar este script."
    }
    $python = $pythonCommand.Source
    $pythonArgs = @()
}

$isVirtualEnvironment = & $python @pythonArgs -c "import sys; print(int(sys.prefix != sys.base_prefix))"
if ($LASTEXITCODE -ne 0) {
    throw "No se pudo ejecutar Python."
}
if ($isVirtualEnvironment.Trim() -eq "1") {
    throw "Desactiva el entorno virtual antes de instalar el comando para tu usuario."
}

& $python @pythonArgs -m pip install --user --upgrade --force-reinstall $PSScriptRoot
if ($LASTEXITCODE -ne 0) {
    throw "La instalación falló. Comprueba que pip esté disponible y vuelve a intentarlo."
}

$scriptsPath = (& $python @pythonArgs -c "import sysconfig; print(sysconfig.get_path('scripts', 'nt_user'))").Trim()
if (-not $scriptsPath) {
    throw "No se pudo determinar la carpeta de comandos de Python."
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ";" | Where-Object { $_ })
if (-not ($pathEntries | Where-Object { $_.TrimEnd("\") -ieq $scriptsPath.TrimEnd("\") })) {
    $newUserPath = (@($pathEntries) + $scriptsPath) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
}
$env:Path = "$scriptsPath;$env:Path"

Write-Host "Instalado. Ejecuta: osint-kit --help"
Write-Host "La ruta de usuario se añadió al PATH; abre una terminal nueva para que otras ventanas la hereden."