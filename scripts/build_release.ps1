$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

& (Join-Path $PSScriptRoot 'build_engine.ps1')
Push-Location $root
try {
  npx tauri build --config src-tauri/tauri.release.conf.json
  if ($LASTEXITCODE -ne 0) { throw "Tauri build failed with exit code $LASTEXITCODE" }
} finally {
  Pop-Location
}
