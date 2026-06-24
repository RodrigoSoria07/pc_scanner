<#
.SYNOPSIS
    Instalador remoto del comando 'scan' (pc_scanner).

.DESCRIPTION
    Pensado para correrse de un tiron en una PC nueva, sin clonar el repo a mano:

        irm https://raw.githubusercontent.com/RodrigoSoria07/pc_scanner/main/get.ps1 | iex

    Descarga scan.ps1 + install.ps1 a una carpeta estable del usuario
    (%LOCALAPPDATA%\pc_scanner) y corre el instalador, que registra el
    comando 'scan' en tu perfil de PowerShell.

.NOTES
    Solo lectura: no instala paquetes del sistema ni requiere admin.
#>

$ErrorActionPreference = 'Stop'

# TLS 1.2 por si la PC es vieja (Win10 antiguo trae TLS por defecto desactivado).
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$repo   = 'https://raw.githubusercontent.com/RodrigoSoria07/pc_scanner/main'
$target = Join-Path $env:LOCALAPPDATA 'pc_scanner'
$files  = @('scan.ps1', 'install.ps1', 'scan.cmd', 'clean.ps1')

Write-Host ""
Write-Host "  Instalando pc_scanner desde GitHub..." -ForegroundColor Cyan
Write-Host "  Destino: $target" -ForegroundColor DarkGray
Write-Host ""

New-Item -ItemType Directory -Path $target -Force | Out-Null

foreach ($f in $files) {
    $url = "$repo/$f"
    $out = Join-Path $target $f
    try {
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
        Unblock-File -Path $out -ErrorAction SilentlyContinue
        Write-Host "  [ OK ] $f" -ForegroundColor Green
    } catch {
        Write-Host "  [ !! ] No se pudo descargar $f" -ForegroundColor Red
        throw
    }
}

Write-Host ""

# Corremos el instalador descargado: registra el comando 'scan' en el perfil.
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $target 'install.ps1')
