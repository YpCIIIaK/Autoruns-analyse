$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'release-assets'
$work = Join-Path $root 'build\pyinstaller'
$spec = Join-Path $work 'spec'

New-Item -ItemType Directory -Force -Path $dist, $work, $spec | Out-Null
python -m PyInstaller --noconfirm --clean --onefile `
  --name autoruns-lens-engine `
  --distpath $dist `
  --workpath $work `
  --specpath $spec `
  (Join-Path $root 'engine\cli.py')
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }

$engine = Join-Path $dist 'autoruns-lens-engine.exe'
if (-not (Test-Path -LiteralPath $engine)) {
  throw 'PyInstaller did not create autoruns-lens-engine.exe'
}
Write-Host "Engine sidecar: $engine"
