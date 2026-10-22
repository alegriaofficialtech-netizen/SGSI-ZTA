# Script Auto-Instalador y Lanzador de Demo para el Cliente
$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$backendDir = Join-Path $root "sgsi-zta-native-app\native-app\backend"
$frontendDir = Join-Path $root "sgsi-zta-native-app\native-app\frontend"
$dbPath = (Join-Path $backendDir "sgsi_demo.db").Replace("\", "/")
$venvDir = Join-Path $backendDir ".venv"
$nodeModules = Join-Path $frontendDir "node_modules"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "     SISTEMA SGSI + ZERO TRUST - INICIALIZADOR DEMO       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Validar requisitos del sistema
Write-Host "[1/5] Verificando requisitos en tu equipo..." -ForegroundColor Yellow

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "ERROR CRITICO: Python no esta instalado o no se agrego al PATH." -ForegroundColor Red
    Write-Host "Por favor descarga e instala Python desde https://www.python.org/" -ForegroundColor White
    Write-Host "IMPORTANTE: En la primera pantalla del instalador, marca la casilla 'Add python.exe to PATH'." -ForegroundColor Yellow
    pause
    exit 1
}

$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    Write-Host "ERROR CRITICO: Node.js no esta instalado." -ForegroundColor Red
    Write-Host "Por favor descarga e instala Node.js (version LTS) desde https://nodejs.org/" -ForegroundColor White
    pause
    exit 1
}

# 2. Configurar entorno Python si no existe
$pythonExe = Join-Path $venvDir "Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    Write-Host "[2/5] Creando entorno virtual e instalando librerias del backend..." -ForegroundColor Yellow
    Push-Location $backendDir
    python -m venv .venv
    & $pythonExe -m pip install --upgrade pip
    & $pythonExe -m pip install -r requirements.txt
    Pop-Location
} else {
    Write-Host "[2/5] Entorno virtual Python listo." -ForegroundColor Green
}

# 3. Base de datos sintética SQLite
$env:DATABASE_URL = "sqlite:///$dbPath"
$env:JWT_SECRET = "super_secret_jwt_key_local_demo_1234567890_min_length"
$env:MFA_ENCRYPTION_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
$env:DEMO_PASSWORD = "Demo!Aa9-12345678"
$env:COOKIE_SECURE = "false"
$env:ALLOWED_ORIGINS = '["http://127.0.0.1:8090","http://localhost:8090","http://127.0.0.1:5173","http://localhost:5173","https://demo.alegriatecn.com","http://demo.alegriatecn.com"]'
$env:ALLOWED_HOSTS = '["localhost","127.0.0.1","testserver","demo.alegriatecn.com","alegriatecn.com"]'

if (-not (Test-Path (Join-Path $backendDir "sgsi_demo.db"))) {
    Write-Host "[3/5] Inicializando base de datos demo local..." -ForegroundColor Yellow
    Push-Location $backendDir
    $alembicExe = Join-Path $venvDir "Scripts\alembic.exe"
    & $alembicExe upgrade head
    & $pythonExe -m app.seed
    Pop-Location
} else {
    Write-Host "[3/5] Base de datos demo local lista." -ForegroundColor Green
}

# 4. Configurar Frontend si faltan paquetes
if (-not (Test-Path $nodeModules)) {
    Write-Host "[4/5] Instalando dependencias del Frontend (npm install)..." -ForegroundColor Yellow
    Push-Location $frontendDir
    npm.cmd install
    Pop-Location
} else {
    Write-Host "[4/5] Paquetes del Frontend listos." -ForegroundColor Green
}

# 5. Lanzar servidores
Write-Host "[5/5] Levantando servidores..." -ForegroundColor Green
$backendProcess = Start-Process -FilePath $pythonExe `
    -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000" `
    -WorkingDirectory $backendDir `
    -PassThru

Start-Sleep -Seconds 2

$frontendProcess = Start-Process -FilePath "npm.cmd" `
    -ArgumentList "run", "dev" `
    -WorkingDirectory $frontendDir `
    -PassThru

Start-Sleep -Seconds 2
Start-Process "http://localhost:5173"

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "             DEMO CORRIENDO EXITOSAMENTE                  " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host " URL: http://localhost:5173" -ForegroundColor White
Write-Host " Usuario:  admision.demo  (o enfermeria.demo)" -ForegroundColor Yellow
Write-Host " Password: Demo!Aa9-12345678" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "Presiona cualquier tecla en esta ventana para cerrar la demo..." -ForegroundColor Red
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Stop-Process -Id $backendProcess.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $frontendProcess.Id -Force -ErrorAction SilentlyContinue
Write-Host "Servidores detenidos correctamente." -ForegroundColor Cyan
