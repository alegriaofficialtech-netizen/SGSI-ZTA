# Script para iniciar Demo y generar Link Publico de Cloudflare
$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$backendDir = Join-Path $root "sgsi-zta-native-app\native-app\backend"
$frontendDir = Join-Path $root "sgsi-zta-native-app\native-app\frontend"
$dbPath = (Join-Path $backendDir "sgsi_demo.db").Replace("\", "/")
$cloudflaredExe = "C:\Users\elcra\Desktop\cloudflared.exe"

Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       SGSI ZTA - GENERADOR DE LINK PUBLICO CLOUDFLARE    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Configurar variables de entorno
$env:DATABASE_URL = "sqlite:///$dbPath"
$env:JWT_SECRET = "super_secret_jwt_key_local_demo_1234567890_min_length"
$env:MFA_ENCRYPTION_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
$env:DEMO_PASSWORD = "Demo!Aa9-12345678"
$env:COOKIE_SECURE = "false"
$env:ALLOWED_HOSTS = '["*"]'

Write-Host "[1/3] Iniciando Backend en puerto 8000..." -ForegroundColor Yellow
$pythonExe = Join-Path $backendDir ".venv\Scripts\python.exe"
$backendProc = Start-Process -FilePath $pythonExe `
    -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000" `
    -WorkingDirectory $backendDir `
    -WindowStyle Hidden `
    -PassThru

Start-Sleep -Seconds 2

Write-Host "[2/3] Iniciando Frontend en puerto 5173..." -ForegroundColor Yellow
$frontendProc = Start-Process -FilePath "npm.cmd" `
    -ArgumentList "run", "dev" `
    -WorkingDirectory $frontendDir `
    -WindowStyle Hidden `
    -PassThru

Start-Sleep -Seconds 3

Write-Host "[3/3] Conectando con Cloudflare Tunnel..." -ForegroundColor Yellow
$tunnelLog = Join-Path $root "tunnel.log"
if (Test-Path $tunnelLog) { Remove-Item $tunnelLog -Force }

$tunnelProc = Start-Process -FilePath $cloudflaredExe `
    -ArgumentList "tunnel", "--url", "http://localhost:5173" `
    -RedirectStandardError $tunnelLog `
    -WindowStyle Hidden `
    -PassThru

# Esperar que Cloudflare asigne la URL
$url = ""
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    if (Test-Path $tunnelLog) {
        $match = Select-String -Path $tunnelLog -Pattern "https://[a-zA-Z0-9-]+\.trycloudflare\.com"
        if ($match) {
            $url = $match.Matches[0].Value
            break
        }
    }
}

Clear-Host
Write-Host "====================================================================" -ForegroundColor Green
Write-Host "            ¡TU LINK PUBLICO DE CLOUDFLARE ESTA ACTIVO!             " -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  LINK PARA ENVIARLE A TU CLIENTE:" -ForegroundColor White
Write-Host "  $url" -ForegroundColor Yellow -BackgroundColor Black
Write-Host ""
Write-Host "--------------------------------------------------------------------" -ForegroundColor Gray
Write-Host "  DATOS DE INGRESO PARA EL CLIENTE:" -ForegroundColor White
Write-Host "  - Usuario:  admision.demo  (o enfermeria.demo / auditor.demo)" -ForegroundColor Cyan
Write-Host "  - Clave:    Demo!Aa9-12345678" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------" -ForegroundColor Gray
Write-Host ""
Write-Host " [i] Mientras esta ventana negra permanezca abierta, el link funciona" -ForegroundColor Magenta
Write-Host "     desde cualquier computadora o celular en el mundo." -ForegroundColor Magenta
Write-Host ""
Write-Host " Presiona cualquier tecla para APAGAR la demo y cortar el link..." -ForegroundColor Red
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Write-Host "Deteniendo servicios y cerrando link..." -ForegroundColor Gray
Stop-Process -Id $backendProc.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $frontendProc.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $tunnelProc.Id -Force -ErrorAction SilentlyContinue
if (Test-Path $tunnelLog) { Remove-Item $tunnelLog -Force }
Write-Host "Listo. El enlace ya no esta disponible." -ForegroundColor Cyan
Start-Sleep -Seconds 2
