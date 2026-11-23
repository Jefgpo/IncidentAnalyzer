# IncidentAnalyzer - arranque en modo desarrollo (Windows / PowerShell)
#
#   .\run.ps1            prepara el entorno la primera vez y levanta backend + frontend
#   .\run.ps1 -Test      corre los tests del backend y del frontend
#
# Si PowerShell bloquea el script: Set-ExecutionPolicy -Scope Process Bypass
param([switch]$Test)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

function Need($cmd, $hint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Host "Falta '$cmd'. $hint" -ForegroundColor Red
        exit 1
    }
}

# Node a veces queda instalado pero fuera del PATH de la terminal ya abierta
if (-not (Get-Command node -ErrorAction SilentlyContinue) -and (Test-Path "$env:ProgramFiles\nodejs\node.exe")) {
    $env:Path = "$env:ProgramFiles\nodejs;$env:Path"
}
Need python "Instalá Python 3.11+ desde https://www.python.org/downloads/ (marcá 'Add python.exe to PATH')."
Need npm "Instalá Node.js 20+ desde https://nodejs.org/ (o: winget install OpenJS.NodeJS.LTS) y abrí una terminal nueva."

$py = "$root\backend\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Host "Creando entorno virtual de Python e instalando dependencias..." -ForegroundColor Cyan
    python -m venv "$root\backend\.venv"
    & $py -m pip install --quiet --upgrade pip
    & $py -m pip install --quiet -r "$root\backend\requirements-dev.txt"
}
if (-not (Test-Path "$root\frontend\node_modules")) {
    Write-Host "Instalando dependencias del frontend..." -ForegroundColor Cyan
    Push-Location "$root\frontend"; npm install --no-audit --no-fund; Pop-Location
}
if (-not (Test-Path "$root\.env")) {
    Copy-Item "$root\.env.example" "$root\.env"
    Write-Host "Se creó .env a partir de .env.example (las claves de IA y AbuseIPDB son opcionales)." -ForegroundColor Yellow
}

if ($Test) {
    Push-Location "$root\backend"; & $py -m pytest -q; $b = $LASTEXITCODE; Pop-Location
    Push-Location "$root\frontend"; npm test; $f = $LASTEXITCODE; npm run build; $f = $f + $LASTEXITCODE; Pop-Location
    exit ($b + $f)
}

Write-Host "Levantando backend (puerto 8000) y frontend (puerto 5173). Ctrl+C para detener." -ForegroundColor Green
$backend = Start-Process -PassThru -NoNewWindow -WorkingDirectory "$root\backend" -FilePath $py `
    -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"
try {
    Start-Sleep -Seconds 2
    Start-Process "http://localhost:5173"
    Push-Location "$root\frontend"; npm run dev
} finally {
    Pop-Location
    if ($backend -and -not $backend.HasExited) { Stop-Process -Id $backend.Id -Force }
}
