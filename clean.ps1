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
    powershell -ExecutionPolicy Bypass -File .\clean.ps1 -Force    # sin confirmar
    powershell -ExecutionPolicy Bypass -File .\clean.ps1 -DryRun   # solo muestra que borraria

.PARAMETER DryRun
    Modo simulacion: lista lo que se borraria y cuanto espacio se liberaria,
    pero NO borra nada. Util para revisar antes de ejecutar de verdad.

.PARAMETER LogPath
    Ruta del log de auditoria. Por defecto:
    %LOCALAPPDATA%\pc_scanner\logs\clean_<fecha>.log
#>

[CmdletBinding()]
param([switch]$Force, [switch]$Elevated, [switch]$DryRun, [string]$LogPath)

$ErrorActionPreference = 'SilentlyContinue'

# --- Log de auditoria ------------------------------------------------------
# Registramos TODO lo que se borra (o se borraria, en -DryRun) para tener
# trazabilidad: que se elimino, cuanto se libero y que se salteo.
if (-not $LogPath) {
    $logDir = Join-Path $env:LOCALAPPDATA 'pc_scanner\logs'
    try { if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } } catch {}
    $LogPath = Join-Path $logDir ("clean_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

function Write-Log {
    param([string]$Message)
    try {
        $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
}

Write-Log ("=== clean.ps1 iniciado === modo={0} usuario={1} equipo={2}" -f `
    $(if ($DryRun) { 'DRY-RUN' } else { 'BORRADO' }), $env:USERNAME, $env:COMPUTERNAME)

# --- Autoelevacion a administrador ----------------------------------------
# Borrar C:\Windows\Temp y los temporales protegidos requiere permisos de
# administrador. Si no los tenemos, relanzamos el script pidiendo elevacion
# (UAC). El switch -Elevated evita un bucle infinito si el usuario rechaza.
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# En -DryRun no elevamos: es solo lectura, no tiene sentido pedir UAC.
if (-not $isAdmin -and -not $Elevated -and -not $DryRun) {
    Write-Host ""
    Write-Host "  Pidiendo permisos de administrador (UAC) para una limpieza completa..." -ForegroundColor Cyan
    # Las rutas van entre comillas: el perfil del usuario puede tener espacios
    # (ej. "Rodrigo Soria"), y Start-Process une los argumentos por espacios.
    # Sin comillas, la ventana elevada recibe la ruta cortada y se cierra al instante.
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Elevated')
    if ($Force)  { $argList += '-Force' }
    if ($LogPath) { $argList += @('-LogPath', "`"$LogPath`"") }
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

foreach ($t in $targets) { Write-Log ("ANTES  {0,-26} {1}" -f $t.Name, (Format-Size (Get-FolderSize $t.Path))) }

# --- Modo simulacion (-DryRun): muestra y registra, NO borra --------------

if ($DryRun) {
    Write-Host ""
    Write-Host "  *** MODO SIMULACION (-DryRun): no se borrara nada ***" -ForegroundColor Magenta
    Write-Host ""
    $wouldCount = 0
    $wouldBytes = 0
    foreach ($t in $targets) {
        if (-not (Test-Path $t.Path)) { continue }
        Get-ChildItem -LiteralPath $t.Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $sz = if ($_.PSIsContainer) { Get-FolderSize $_.FullName } else { [double]$_.Length }
            $wouldCount++
            $wouldBytes += $sz
            Write-Log ("[DRY] se borraria: {0}  ({1})" -f $_.FullName, (Format-Size $sz))
        }
    }
    Write-Host ("  Se borrarian {0} elemento(s), liberando ~{1}." -f $wouldCount, (Format-Size $wouldBytes)) -ForegroundColor Yellow
    Write-Host ("  Detalle completo en el log: {0}" -f $LogPath) -ForegroundColor DarkGray
    Write-Host ""
    Write-Log ("=== DRY-RUN: {0} elementos, ~{1} -> nada borrado ===" -f $wouldCount, (Format-Size $wouldBytes))
    if ($Elevated) { Read-Host "  Presiona Enter para cerrar" | Out-Null }
    exit 0
}

# --- Confirmacion ---------------------------------------------------------

if (-not $Force) {
    $ans = Read-Host "  Borrar estos temporales? (s/N)  [tip: -DryRun para simular primero]"
    if ($ans -notmatch '^[sSyY]') {
        Write-Host "  Cancelado. No se borro nada." -ForegroundColor Yellow
        Write-Log "Cancelado por el usuario. Nada borrado."
        exit 0
    }
}

# --- Limpieza -------------------------------------------------------------

Write-Host ""
Write-Host "  Limpiando..." -ForegroundColor Cyan
$skipped = 0
$deleted = 0
foreach ($t in $targets) {
    if (-not (Test-Path $t.Path)) { continue }
    Get-ChildItem -LiteralPath $t.Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $full = $_.FullName
        try {
            Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
            $deleted++
            Write-Log ("BORRADO  {0}" -f $full)
        } catch {
            $skipped++   # en uso / sin permisos -> se saltea
            Write-Log ("SALTADO  {0}  ({1})" -f $full, $_.Exception.Message)
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
Write-Host ("  Log de auditoria: {0}" -f $LogPath) -ForegroundColor DarkGray
Write-Host ""

Write-Log ("=== Resultado: {0} borrados, {1} saltados, liberado {2} ===" -f `
    $deleted, $skipped, (Format-Size ([math]::Max($tempFreed, 0))))

# La ventana elevada es independiente y se cerraria sola: pausamos para que
# se pueda leer el resultado.
if ($Elevated) {
    Read-Host "  Presiona Enter para cerrar esta ventana de administrador" | Out-Null
}
