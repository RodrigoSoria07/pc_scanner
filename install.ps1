<#
.SYNOPSIS
    Registra el comando 'scan' en tu perfil de PowerShell.

.DESCRIPTION
    Despues de correr esto UNA vez, podes escribir simplemente:

        scan
        scan -Days 7
        scan -Full
        scan -NoAnim

    desde cualquier carpeta y en cualquier ventana nueva de PowerShell.
    Por debajo ejecuta scan.ps1 con la politica de ejecucion correcta.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1

.NOTES
    Para desinstalar, corre:  .\install.ps1 -Uninstall
#>

[CmdletBinding()]
param([switch]$Uninstall)

$ErrorActionPreference = 'Stop'

$script = Join-Path $PSScriptRoot 'scan.ps1'
if (-not (Test-Path $script)) {
    Write-Host "ERROR: no encuentro scan.ps1 junto a este instalador." -ForegroundColor Red
    exit 1
}

# Marcadores para poder actualizar/quitar el bloque sin tocar el resto del perfil.
$markerStart = '# >>> comando scan (virus-scanner) >>>'
$markerEnd   = '# <<< comando scan (virus-scanner) <<<'

$block = @"
$markerStart
function scan { powershell -NoProfile -ExecutionPolicy Bypass -File "$script" @args }
$markerEnd
"@

# Aseguramos que exista el archivo de perfil.
if (-not (Test-Path $PROFILE)) {
    New-Item -ItemType File -Path $PROFILE -Force | Out-Null
}

$content = Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue
if ($null -eq $content) { $content = '' }

# Quitamos cualquier bloque previo nuestro (idempotente).
$pattern = [regex]::Escape($markerStart) + '[\s\S]*?' + [regex]::Escape($markerEnd) + '\r?\n?'
$content = [regex]::Replace($content, $pattern, '')

if ($Uninstall) {
    Set-Content -Path $PROFILE -Value $content.TrimEnd() -Encoding UTF8
    Write-Host "Comando 'scan' desinstalado del perfil." -ForegroundColor Yellow
    Write-Host "Abri una nueva terminal para que tome el cambio." -ForegroundColor Gray
    exit 0
}

# Agregamos el bloque actualizado al final.
$content = $content.TrimEnd() + "`r`n`r`n" + $block + "`r`n"
Set-Content -Path $PROFILE -Value $content -Encoding UTF8

Write-Host ""
Write-Host "  [ OK ] Comando 'scan' instalado correctamente." -ForegroundColor Green
Write-Host ""
Write-Host "  Perfil: $PROFILE" -ForegroundColor Gray
Write-Host ""
Write-Host "  Abri una NUEVA ventana de PowerShell y escribi:" -ForegroundColor Cyan
Write-Host "      scan" -ForegroundColor White
Write-Host ""
Write-Host "  Otros usos:  scan -Days 7   |   scan -Full   |   scan -NoAnim" -ForegroundColor DarkGray
Write-Host ""
