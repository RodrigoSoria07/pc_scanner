<#
.SYNOPSIS
    Limpia archivos temporales y muestra rendimiento ANTES vs DESPUES.

.DESCRIPTION
    Toma una foto del estado del equipo (disco libre, CPU, RAM y tamano de las
    carpetas temporales), borra los temporales de usuario (%TEMP%) y del sistema
    (C:\Windows\Temp), y vuelve a medir para mostrarte la diferencia.

    Los archivos en uso por el sistema u otros programas se SALTEAN solos
    (no se fuerza el cierre de nada).

    Nota honesta: limpiar temporales libera ESPACIO EN DISCO. No reduce el uso
    de CPU. Los valores de CPU/RAM se muestran solo como referencia.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\clean.ps1
    powershell -ExecutionPolicy Bypass -File .\clean.ps1 -Force   # sin confirmar
#>

[CmdletBinding()]
param([switch]$Force, [switch]$Elevated)

$ErrorActionPreference = 'SilentlyContinue'

# --- Autoelevacion a administrador ----------------------------------------
# Borrar C:\Windows\Temp y los temporales protegidos requiere permisos de
# administrador. Si no los tenemos, relanzamos el script pidiendo elevacion
# (UAC). El switch -Elevated evita un bucle infinito si el usuario rechaza.
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $Elevated) {
    Write-Host ""
    Write-Host "  Pidiendo permisos de administrador (UAC) para una limpieza completa..." -ForegroundColor Cyan
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Elevated')
    if ($Force) { $argList += '-Force' }
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList -ErrorAction Stop
        # La ventana elevada hace el trabajo; esta instancia termina aca.
        return
    } catch {
        Write-Host "  Elevacion cancelada. Continuo SIN admin (se saltearan el temp del sistema y archivos protegidos)." -ForegroundColor Yellow
        Write-Host ""
    }
}

# --- Helpers --------------------------------------------------------------

function Format-Size([double]$bytes) {
    if ($bytes -ge 1GB) { return ('{0:N2} GB' -f ($bytes / 1GB)) }
    if ($bytes -ge 1MB) { return ('{0:N2} MB' -f ($bytes / 1MB)) }
    if ($bytes -ge 1KB) { return ('{0:N2} KB' -f ($bytes / 1KB)) }
    return "$bytes B"
}

function Get-FolderSize([string]$path) {
    if (-not (Test-Path $path)) { return 0 }
    $sum = (Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) { return 0 }
    return [double]$sum
}

function Get-Snapshot {
    $os   = Get-CimInstance Win32_OperatingSystem
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $cpu  = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average

    $ramTotal = [double]$os.TotalVisibleMemorySize * 1KB
    $ramFree  = [double]$os.FreePhysicalMemory     * 1KB
    $ramUsedPct = if ($ramTotal -gt 0) { [math]::Round((($ramTotal - $ramFree) / $ramTotal) * 100) } else { 0 }

    [pscustomobject]@{
        DiskFree   = [double]$disk.FreeSpace
        DiskSize   = [double]$disk.Size
        CpuPct     = [int]$cpu
        RamUsedPct = $ramUsedPct
        RamFree    = $ramFree
    }
}

# --- Objetivos ------------------------------------------------------------

$targets = @(
    [pscustomobject]@{ Name = 'Temp de usuario (%TEMP%)'; Path = $env:TEMP },
    [pscustomobject]@{ Name = 'Temp del sistema';         Path = (Join-Path $env:windir 'Temp') }
)

# --- ANTES ----------------------------------------------------------------

Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkCyan
Write-Host "  LIMPIEZA DE TEMPORALES  -  RENDIMIENTO ANTES vs DESPUES" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor DarkCyan
Write-Host ""

$before = Get-Snapshot

$tempBefore = 0
Write-Host "  Carpetas a limpiar:" -ForegroundColor White
foreach ($t in $targets) {
    $s = Get-FolderSize $t.Path
    $tempBefore += $s
    Write-Host ("    - {0,-26} {1,12}   {2}" -f $t.Name, (Format-Size $s), $t.Path) -ForegroundColor Gray
}

Write-Host ""
Write-Host "  Estado ANTES:" -ForegroundColor White
Write-Host ("    Disco C: libre : {0}  de  {1}" -f (Format-Size $before.DiskFree), (Format-Size $before.DiskSize)) -ForegroundColor Gray
Write-Host ("    Temporales     : {0}" -f (Format-Size $tempBefore)) -ForegroundColor Gray
Write-Host ("    CPU            : {0}%   (referencia)" -f $before.CpuPct) -ForegroundColor DarkGray
Write-Host ("    RAM usada      : {0}%   (referencia)" -f $before.RamUsedPct) -ForegroundColor DarkGray
Write-Host ""

# --- Confirmacion ---------------------------------------------------------

if (-not $Force) {
    $ans = Read-Host "  Borrar estos temporales? (s/N)"
    if ($ans -notmatch '^[sSyY]') {
        Write-Host "  Cancelado. No se borro nada." -ForegroundColor Yellow
        exit 0
    }
}

# --- Limpieza -------------------------------------------------------------

Write-Host ""
Write-Host "  Limpiando..." -ForegroundColor Cyan
$skipped = 0
foreach ($t in $targets) {
    if (-not (Test-Path $t.Path)) { continue }
    Get-ChildItem -LiteralPath $t.Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop
        } catch {
            $skipped++   # en uso / sin permisos -> se saltea
        }
    }
}

Start-Sleep -Milliseconds 500

# --- DESPUES --------------------------------------------------------------

$after = Get-Snapshot
$tempAfter = 0
foreach ($t in $targets) { $tempAfter += (Get-FolderSize $t.Path) }

$tempFreed = $tempBefore - $tempAfter   # lo que realmente se libero de las carpetas temp

Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkCyan
Write-Host "  RESULTADO" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host ("  {0,-16} {1,16}   {2,16}" -f '', 'ANTES', 'DESPUES') -ForegroundColor White
Write-Host ("  {0,-16} {1,16}   {2,16}" -f 'Disco C: libre', (Format-Size $before.DiskFree), (Format-Size $after.DiskFree)) -ForegroundColor Green
Write-Host ("  {0,-16} {1,16}   {2,16}" -f 'Temporales',     (Format-Size $tempBefore),      (Format-Size $tempAfter)) -ForegroundColor Green
Write-Host ("  {0,-16} {1,15}%   {2,15}%" -f 'CPU (ref)',    $before.CpuPct,                 $after.CpuPct) -ForegroundColor DarkGray
Write-Host ("  {0,-16} {1,15}%   {2,15}%" -f 'RAM usada (ref)', $before.RamUsedPct,          $after.RamUsedPct) -ForegroundColor DarkGray
Write-Host ""
Write-Host ("  >> Espacio liberado: {0}" -f (Format-Size ([math]::Max($tempFreed, 0)))) -ForegroundColor Green
if ($skipped -gt 0) {
    Write-Host ("  >> {0} elemento(s) en uso se saltearon (normal: estaban abiertos)." -f $skipped) -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  Nota: limpiar temporales libera DISCO, no baja la CPU." -ForegroundColor DarkGray
Write-Host ""

# La ventana elevada es independiente y se cerraria sola: pausamos para que
# se pueda leer el resultado.
if ($Elevated) {
    Read-Host "  Presiona Enter para cerrar esta ventana de administrador" | Out-Null
}
