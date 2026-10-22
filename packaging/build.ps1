[CmdletBinding()]
param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildRoot = Join-Path $Root "build\packaging"
$RuntimeRoot = Join-Path $BuildRoot "python-runtime"
$DownloadRoot = Join-Path $BuildRoot "downloads"
$DistRoot = Join-Path $Root "dist\windows"
$RuntimeZip = Join-Path $DownloadRoot "python-embed.zip"

Push-Location $Root
try {
    & $Python -c "import sys; assert sys.version_info >= (3, 13); assert sys.version_info < (3, 14); assert sys.maxsize > 2**32"
    if ($LASTEXITCODE -ne 0) {
        throw "Packaging requires 64-bit Python 3.13. Activate the intended build environment first."
    }
    & $Python -c "import PyInstaller"
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller is missing. Install build dependencies with: python -m pip install -r requirements-dev.txt"
    }
    & $Python -c "import PySide6"
    if ($LASTEXITCODE -ne 0) {
        throw "PySide6 is missing. Install the GUI extra with: python -m pip install -e '.[gui]'"
    }

    $PythonVersion = (& $Python -c "import platform; print(platform.python_version())").Trim()
    $PythonVersionParts = $PythonVersion.Split(".")
    $MajorMinor = "$($PythonVersionParts[0])$($PythonVersionParts[1])"
    $EmbedUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"

    New-Item -ItemType Directory -Force -Path $DownloadRoot | Out-Null
    if (Test-Path -LiteralPath $RuntimeRoot) {
        $ResolvedRuntime = (Resolve-Path -LiteralPath $RuntimeRoot).Path
        if (-not $ResolvedRuntime.StartsWith($BuildRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to replace a runtime directory outside the packaging build folder."
        }
        Remove-Item -LiteralPath $ResolvedRuntime -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $RuntimeRoot | Out-Null

    if (-not (Test-Path -LiteralPath $RuntimeZip)) {
        Write-Host "Downloading the matching Python $PythonVersion embeddable runtime..."
        & curl.exe --fail --location --silent --show-error $EmbedUrl --output $RuntimeZip
        if ($LASTEXITCODE -ne 0) {
            throw "Could not download the Python embeddable runtime from python.org."
        }
    }
    Expand-Archive -LiteralPath $RuntimeZip -DestinationPath $RuntimeRoot -Force

    $RuntimePth = Join-Path $RuntimeRoot "python$MajorMinor._pth"
    if (-not (Test-Path -LiteralPath $RuntimePth)) {
        throw "The embeddable Python archive did not contain the expected ._pth file."
    }
    $PthLines = @(Get-Content -LiteralPath $RuntimePth)
    if ($PthLines -notcontains "site-packages") {
        $PthLines += "site-packages"
    }
    if ($PthLines -notcontains "import site") {
        $PthLines += "import site"
    }
    Set-Content -LiteralPath $RuntimePth -Value $PthLines -Encoding ascii

    $RuntimePackages = Join-Path $RuntimeRoot "site-packages"
    New-Item -ItemType Directory -Force -Path $RuntimePackages | Out-Null
    Write-Host "Installing AEGIS runtime dependencies into the bundled Python..."
    & $Python -m pip install --disable-pip-version-check --no-compile --target $RuntimePackages -r (Join-Path $Root "requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        throw "Could not install the AEGIS runtime dependencies into the bundle."
    }
    & (Join-Path $RuntimeRoot "python.exe") -c "import bandit; import yaml; print('Bundled Bandit runtime ready:', bandit.__version__)"
    if ($LASTEXITCODE -ne 0) {
        throw "The staged Python runtime cannot import Bandit and its dependencies."
    }

    New-Item -ItemType Directory -Force -Path $DistRoot | Out-Null
    & $Python -m PyInstaller --noconfirm --clean --distpath $DistRoot --workpath (Join-Path $BuildRoot "pyinstaller-cli") (Join-Path $PSScriptRoot "aegis-cli.spec")
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed while building the CLI executable."
    }
    & $Python -m PyInstaller --noconfirm --clean --distpath $DistRoot --workpath (Join-Path $BuildRoot "pyinstaller-gui") (Join-Path $PSScriptRoot "aegis-gui.spec")
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed while building the GUI executable."
    }

    Write-Host ""
    Write-Host "Build complete:"
    Write-Host "  CLI: $DistRoot\aegis\aegis.exe"
    Write-Host "  GUI: $DistRoot\aegis-gui\aegis-gui.exe"
}
finally {
    Pop-Location
}
