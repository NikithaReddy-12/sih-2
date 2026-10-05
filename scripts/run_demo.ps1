$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Backend = Join-Path $Root 'backend'

if (-not (Test-Path (Join-Path $Root 'dist\index.html'))) {
  Push-Location $Root
  npm run build
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  Pop-Location
}

$backend = Start-Process -FilePath 'python' -ArgumentList @('-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', '8000') -WorkingDirectory $Backend -PassThru -WindowStyle Hidden
try {
  Push-Location $Root
  npm run preview -- --host 127.0.0.1 --port 5173
} finally {
  if ($backend -and -not $backend.HasExited) {
    Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue
  }
  Pop-Location
}
