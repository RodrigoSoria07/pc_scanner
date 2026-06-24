<#
.SYNOPSIS
    Actualiza pc_scanner a la ultima version publicada en GitHub.

.DESCRIPTION
    Re-descarga los scripts (scan.ps1, clean.ps1, install.ps1, scan.cmd,
    update.ps1) a la carpeta estable del usuario (%LOCALAPPDATA%\pc_scanner)
    y vuelve a registrar los comandos en tu perfil.

    Pensado para correrse con el comando 'update' (queda registrado por el
    instalador) sin tener que recordar el one-liner de instalacion:

        update

.NOTES
    Solo lectura: no instala paquetes del sistema ni requiere admin.
#>

$ErrorActionPreference = 'Stop'

# TLS 1.2 por si la PC es vieja (Win10 antiguo trae TLS por defecto desactivado).
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$repo   = 'https://raw.githubusercontent.com/RodrigoSoria07/pc_scanner/main'
$target = Join-Path $env:LOCALAPPDATA 'pc_scanner'
$files  = @('scan.ps1', 'clean.ps1', 'install.ps1', 'scan.cmd', 'update.ps1')

Write-Host ""
Write-Host "  Actualizando pc_scanner desde GitHub..." -ForegroundColor Cyan
Write-Host "  Destino: $target" -ForegroundColor DarkGray
Write-Host ""

New-Item -ItemType Directory -Path $target -Force | Out-Null

$ok = 0
foreach ($f in $files) {
    $url = "$repo/$f"
    $out = Join-Path $target $f
    try {
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
        Unblock-File -Path $out -ErrorAction SilentlyContinue
        Write-Host "  [ OK ] $f" -ForegroundColor Green
        $ok++
    } catch {
        Write-Host "  [ !! ] No se pudo descargar $f" -ForegroundColor Red
    }
}

if ($ok -eq 0) {
    Write-Host ""
    Write-Host "  No se pudo descargar ningun archivo. Revisa tu conexion." -ForegroundColor Red
    exit 1
}

Write-Host ""

# Re-registra los comandos en el perfil (idempotente) por si cambiaron.
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $target 'install.ps1')

Write-Host ""
Write-Host "  [ OK ] pc_scanner actualizado." -ForegroundColor Green
Write-Host "  Abri una NUEVA ventana de PowerShell para tomar los cambios." -ForegroundColor Cyan
Write-Host ""
