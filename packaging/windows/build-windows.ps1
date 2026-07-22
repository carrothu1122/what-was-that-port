$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Dist = Join-Path $Root "dist\windows"
$Work = Join-Path $Root "build\pyinstaller-windows"

New-Item -ItemType Directory -Force -Path $Dist | Out-Null
New-Item -ItemType Directory -Force -Path $Work | Out-Null

python -m PyInstaller `
  --clean `
  --noconfirm `
  --distpath $Dist `
  --workpath $Work `
  (Join-Path $PSScriptRoot "what-was-that-port-worker.spec")

python -m PyInstaller `
  --clean `
  --noconfirm `
  --distpath $Dist `
  --workpath $Work `
  (Join-Path $PSScriptRoot "what-was-that-port-gui.spec")

Write-Host "Built Windows executables in $Dist"
