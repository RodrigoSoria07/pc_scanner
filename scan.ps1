<#
.SYNOPSIS
    Scanner heuristico de malware para Windows (solo lectura, defensivo).

.DESCRIPTION
    Revisa los lugares donde tipicamente se esconde el malware y marca lo
    sospechoso con su ruta exacta y un nivel de riesgo. NO es un antivirus:
    no usa firmas ni elimina nada. Es una herramienta de TRIAJE para detectar
    cosas raras en tu propio equipo.

    Lo que revisa:
      - Carpetas de inicio (Startup) del usuario y del sistema.
      - Claves del registro Run / RunOnce (HKCU + HKLM, incluido Wow6432Node).
      - Tareas programadas con acciones sospechosas.
      - Servicios cuyo binario esta en ubicaciones de usuario o sin firmar.
      - Procesos en ejecucion corriendo desde carpetas temporales/usuario.
      - Ejecutables recientes en zonas de riesgo (Temp, AppData, Downloads...).

.PARAMETER Days
    Antiguedad (en dias) para considerar un ejecutable como "reciente".
    Por defecto 14.

.PARAMETER Full
    Escaneo profundo: recorre todo el perfil de usuario buscando ejecutables
    recientes (mas lento).

.EXAMPLE
    .\scan.ps1
    Escaneo estandar.

.EXAMPLE
    .\scan.ps1 -Days 30 -Full
    Escaneo profundo de los ultimos 30 dias.

.NOTES
    Autor : Rodrigo Soria
    Licencia: MIT
    Solo lectura. Para mejores resultados ejecutar como Administrador.
#>

[CmdletBinding()]
param(
    [int]$Days = 14,
    [switch]$Full,
    [switch]$NoAnim
)

# ---------------------------------------------------------------------------
# Estado global
# ---------------------------------------------------------------------------
$script:Findings = New-Object System.Collections.Generic.List[object]

# Activamos animaciones solo si hay una consola interactiva (no redirigida a
# archivo) y el usuario no paso -NoAnim.
$script:Animate = $false
try {
    $script:Animate = (-not $NoAnim) -and (-not [Console]::IsOutputRedirected)
} catch { $script:Animate = $false }

# Extensiones consideradas "ejecutables" o de script.
$script:ExecExt = @('.exe', '.dll', '.scr', '.com', '.pif', '.bat', '.cmd',
                    '.vbs', '.vbe', '.js', '.jse', '.ps1', '.wsf', '.hta',
                    '.jar', '.msi', '.lnk')

# Carpetas donde el malware suele alojarse (escribibles por el usuario).
$script:HotDirs = @(
    $env:TEMP,
    "$env:LOCALAPPDATA\Temp",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "$env:USERPROFILE\Downloads",
    "$env:PUBLIC",
    "C:\ProgramData"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

# Patrones de ruta que consideramos "de usuario" (mas riesgosos para binarios
# que se autoejecutan: inicio, registro, tareas, servicios).
$script:UserPathPatterns = @(
    '\\AppData\\', '\\Temp\\', '\\Downloads\\', '\\Public\\',
    '\\ProgramData\\', '\\Users\\Public\\'
)

# Ubicaciones "de confianza" del sistema (binarios firmados aqui no son hallazgo).
$script:TrustedPathPatterns = @(
    '\\Program Files\\', '\\Program Files (x86)\\',
    '\\Windows\\System32\\', '\\Windows\\SysWOW64\\',
    '\\WindowsApps\\', '\\DriverStore\\', '\\WINDOWS\\'
)

# Carpetas ruidosas que NO interesan al escanear archivos recientes
# (dependencias, caches de editores, historiales). Reducen falsos positivos.
$script:ExcludePatterns = @(
    '\\node_modules\\',
    '\\.git\\',
    '\\Code\\User\\History\\',
    '\\__PSScriptPolicyTest',
    '\\.vscode\\', '\\.cache\\',
    '\\pip\\cache\\', '\\npm-cache\\', '\\Yarn\\Cache\\',
    '\\NuGet\\', '\\.nuget\\',
    '\\Microsoft\\Office\\Recent\\',
    '\\go\\pkg\\', '\\.cargo\\', '\\.gradle\\'
)

function Test-IsTrustedPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    foreach ($p in $script:TrustedPathPatterns) {
        if ($Path -like "*$p*") { return $true }
    }
    return $false
}

function Test-IsExcludedPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    foreach ($p in $script:ExcludePatterns) {
        if ($Path -like "*$p*") { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Helpers de salida
# ---------------------------------------------------------------------------
function Write-Title {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkGreen
    if ($script:Animate) {
        Write-Typing "  $Text" -Color Green -Delay 5
    } else {
        Write-Host "  $Text" -ForegroundColor Green
    }
    Write-Host ("=" * 70) -ForegroundColor DarkGreen
}

function Write-Section {
    param([string]$Text)
    Write-Host ""
    if ($script:Animate) {
        Write-Typing ">> $Text" -Color Green -Delay 4
    } else {
        Write-Host ">> $Text" -ForegroundColor White
    }
}

# ---------------------------------------------------------------------------
# Animaciones estilo "consola hacker" (cosmeticas, opcionales)
# ---------------------------------------------------------------------------

# Efecto maquina de escribir: imprime el texto caracter por caracter.
function Write-Typing {
    param(
        [string]$Text,
        [System.ConsoleColor]$Color = [System.ConsoleColor]::Green,
        [int]$Delay = 10,
        [switch]$NoNewline
    )
    if (-not $script:Animate) {
        Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline
        return
    }
    foreach ($ch in $Text.ToCharArray()) {
        Write-Host $ch -ForegroundColor $Color -NoNewline
        if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
    }
    if (-not $NoNewline) { Write-Host "" }
}

# Lluvia de caracteres estilo Matrix durante unos segundos, luego limpia.
function Show-MatrixRain {
    param([int]$Frames = 50)
    if (-not $script:Animate) { return }

    $w = 0; $h = 0
    try { $w = [Console]::WindowWidth; $h = [Console]::WindowHeight } catch { return }
    if ($w -lt 10 -or $h -lt 6) { return }
    $w = [Math]::Min($w, 220) - 1   # evitamos la ultima columna (provoca scroll)

    $chars = ([char[]](48..57 + 65..90)) + '@#$%&*<>/\|=+-'.ToCharArray()
    $green = [System.ConsoleColor]::Green
    $head  = [System.ConsoleColor]::White
    $dim   = [System.ConsoleColor]::DarkGreen

    # Posicion inicial (aleatoria) de cada "gota" por columna.
    $drops = New-Object 'int[]' $w
    for ($i = 0; $i -lt $w; $i++) { $drops[$i] = Get-Random -Minimum (-$h) -Maximum $h }

    $prevVisible = $true
    try {
        try { $prevVisible = [Console]::CursorVisible } catch {}
        [Console]::CursorVisible = $false
        [Console]::Clear()

        for ($f = 0; $f -lt $Frames; $f++) {
            for ($x = 0; $x -lt $w; $x++) {
                $y = $drops[$x]

                # Cabeza brillante.
                if ($y -ge 0 -and $y -lt $h) {
                    [Console]::SetCursorPosition($x, $y)
                    [Console]::ForegroundColor = $head
                    [Console]::Write($chars[(Get-Random -Maximum $chars.Length)])
                }
                # Cuerpo verde, una fila arriba.
                $by = $y - 1
                if ($by -ge 0 -and $by -lt $h) {
                    [Console]::SetCursorPosition($x, $by)
                    [Console]::ForegroundColor = $green
                    [Console]::Write($chars[(Get-Random -Maximum $chars.Length)])
                }
                # Estela tenue.
                $dy = $y - 4
                if ($dy -ge 0 -and $dy -lt $h) {
                    [Console]::SetCursorPosition($x, $dy)
                    [Console]::ForegroundColor = $dim
                    [Console]::Write($chars[(Get-Random -Maximum $chars.Length)])
                }
                # Borrado de la cola.
                $ey = $y - 9
                if ($ey -ge 0 -and $ey -lt $h) {
                    [Console]::SetCursorPosition($x, $ey)
                    [Console]::Write(' ')
                }

                $drops[$x]++
                if (($drops[$x] - 9) -gt $h) { $drops[$x] = Get-Random -Minimum (-6) -Maximum 0 }
            }
            Start-Sleep -Milliseconds 25
        }
    } catch {
        # Si la consola no soporta posicionamiento, abortamos sin romper nada.
    } finally {
        try {
            [Console]::ResetColor()
            [Console]::Clear()
            [Console]::SetCursorPosition(0, 0)
            [Console]::CursorVisible = $prevVisible
        } catch {}
    }
}

# Banner ASCII del scanner.
function Show-Banner {
    $banner = @(
        '  __     ___                 ____                                ',
        '  \ \   / (_)_ __ _   _ ___  / ___|  ___ __ _ _ __  _ __   ___ _ __ ',
        "   \ \ / /| | '__| | | / __| \___ \ / __/ _`` | '_ \| '_ \ / _ \ '__|",
        '    \ V / | | |  | |_| \__ \  ___) | (_| (_| | | | | | | |  __/ |   ',
        '     \_/  |_|_|   \__,_|___/ |____/ \___\__,_|_| |_|_| |_|\___|_|   '
    )
    Write-Host ""
    foreach ($line in $banner) {
        Write-Host $line -ForegroundColor Green
        if ($script:Animate) { Start-Sleep -Milliseconds 45 }
    }
    Write-Typing "        [ heuristic malware triage // read-only ]" -Color DarkGreen -Delay 6
    Write-Host ""
}

# Secuencia de arranque tipo terminal: lineas "[ OK ]" con efecto tipeo.
function Write-BootSequence {
    $steps = @(
        'Inicializando motor de escaneo',
        'Cargando reglas heuristicas',
        'Mapeando puntos de persistencia',
        'Conectando con el subsistema del kernel',
        'Estableciendo enlace seguro'
    )
    foreach ($s in $steps) {
        Write-Host "  [" -ForegroundColor DarkGreen -NoNewline
        Write-Host "*" -ForegroundColor Green -NoNewline
        Write-Host "] " -ForegroundColor DarkGreen -NoNewline
        Write-Typing $s -Color Green -Delay 6 -NoNewline
        if ($script:Animate) {
            # Puntos suspensivos animados.
            for ($i = 0; $i -lt 3; $i++) {
                Write-Host "." -ForegroundColor Green -NoNewline
                Start-Sleep -Milliseconds 90
            }
        } else {
            Write-Host "..." -ForegroundColor Green -NoNewline
        }
        Write-Host "  [ OK ]" -ForegroundColor Green
    }
    Write-Host ""
}

function Add-Finding {
    param(
        [string]$Category,
        [ValidateSet('Alto', 'Medio', 'Bajo', 'Info')]
        [string]$Risk,
        [string]$Item,
        [string]$Path,
        [string]$Reason
    )
    $script:Findings.Add([PSCustomObject]@{
        Categoria = $Category
        Riesgo    = $Risk
        Item      = $Item
        Ruta      = $Path
        Motivo    = $Reason
    })

    $color = switch ($Risk) {
        'Alto'  { 'Red' }
        'Medio' { 'Yellow' }
        'Bajo'  { 'DarkYellow' }
        default { 'Gray' }
    }
    Write-Host ("  [{0,-5}] " -f $Risk) -ForegroundColor $color -NoNewline
    Write-Host $Item -ForegroundColor $color
    if ($Path)   { Write-Host "          Ruta : $Path"   -ForegroundColor Gray }
    if ($Reason) { Write-Host "          Motivo: $Reason" -ForegroundColor DarkGray }
}

# ---------------------------------------------------------------------------
# Helpers de analisis
# ---------------------------------------------------------------------------

# Devuelve la ruta del ejecutable a partir de una linea de comando del registro
# o de un servicio (maneja comillas y argumentos).
function Resolve-ExePath {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $cmd = $CommandLine.Trim()
    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        if ($end -gt 0) { return $cmd.Substring(1, $end - 1) }
    }
    # Sin comillas: tomamos hasta el primer espacio que cierre un .ext conocida.
    if ($cmd -match '^(.*?\.(?:exe|com|bat|cmd|scr|pif|dll|vbs|js|ps1))(\s|$)') {
        return $Matches[1]
    }
    return ($cmd -split '\s+')[0]
}

# Estado de firma Authenticode de un archivo.
function Get-SignatureState {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return [PSCustomObject]@{ Status = 'NoExiste'; Signer = $null }
        }
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
        return [PSCustomObject]@{ Status = $sig.Status.ToString(); Signer = $signer }
    } catch {
        return [PSCustomObject]@{ Status = 'Desconocido'; Signer = $null }
    }
}

function Test-IsUserPath {
    param([string]$Path)
    if (-not $Path) { return $false }
    foreach ($p in $script:UserPathPatterns) {
        if ($Path -like "*$p*") { return $true }
    }
    return $false
}

# Detecta doble extension enganosa (ej: factura.pdf.exe).
function Test-DoubleExtension {
    param([string]$Name)
    return ($Name -match '\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|zip|rar)\.(exe|scr|com|pif|bat|cmd|vbs|js|jar|hta)$')
}

# Nombres de procesos del sistema que NO deberian correr fuera de System32.
$script:SystemNames = @('svchost.exe', 'lsass.exe', 'csrss.exe', 'services.exe',
                        'winlogon.exe', 'explorer.exe', 'smss.exe', 'wininit.exe',
                        'spoolsv.exe', 'taskhostw.exe')

# ---------------------------------------------------------------------------
# Modulos de escaneo
# ---------------------------------------------------------------------------

function Show-SystemInfo {
    Write-Title "INFORMACION DEL SISTEMA"
    try {
        $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs  = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $up  = (Get-Date) - $os.LastBootUpTime
        Write-Typing ("  Equipo      : {0}" -f $cs.Name)              -Color Green -Delay 6
        Write-Typing ("  Usuario     : {0}" -f $env:USERNAME)        -Color Green -Delay 6
        Write-Typing ("  SO          : {0} ({1})" -f $os.Caption, $os.Version) -Color Green -Delay 6
        Write-Typing ("  Arquitectura: {0}" -f $os.OSArchitecture)   -Color Green -Delay 6
        Write-Typing ("  Uptime      : {0}d {1}h {2}m" -f $up.Days, $up.Hours, $up.Minutes) -Color Green -Delay 6
    } catch {
        Write-Host "  (No se pudo obtener informacion del sistema)" -ForegroundColor DarkGray
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host ("  Admin      : {0}" -f $(if ($isAdmin) { 'Si' } else { 'No (algunos chequeos seran limitados)' })) `
        -ForegroundColor $(if ($isAdmin) { 'Green' } else { 'Yellow' })
}

function Scan-StartupFolders {
    Write-Section "Carpetas de inicio (Startup)"
    $folders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    $found = $false
    foreach ($f in $folders) {
        if (-not (Test-Path $f)) { continue }
        Get-ChildItem -LiteralPath $f -File -ErrorAction SilentlyContinue | ForEach-Object {
            $found = $true
            $ext = $_.Extension.ToLower()
            $isScriptlike = $ext -in @('.exe', '.scr', '.com', '.pif', '.bat', '.cmd', '.vbs', '.js', '.hta', '.ps1')
            $risk = if ($isScriptlike) { 'Medio' } else { 'Info' }
            $reason = if ($isScriptlike) {
                "Ejecutable/script que corre al iniciar sesion (verifica que lo reconoces)."
            } else {
                "Acceso directo que corre al iniciar sesion."
            }
            Add-Finding -Category 'Inicio' -Risk $risk -Item $_.Name -Path $_.FullName -Reason $reason
        }
    }
    if (-not $found) { Write-Host "  (Sin elementos en carpetas de inicio)" -ForegroundColor DarkGray }
}

function Scan-RegistryRun {
    Write-Section "Registro: claves Run / RunOnce"
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $found = $false
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $found = $true
            $cmd  = [string]$p.Value
            $exe  = Resolve-ExePath $cmd
            $risk = 'Info'
            $reasons = @()

            if (Test-IsUserPath $exe) {
                $risk = 'Alto'
                $reasons += 'binario en carpeta de usuario/temporal'
            }
            if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
                $sig = Get-SignatureState $exe
                if ($sig.Status -eq 'NotSigned') {
                    if ($risk -eq 'Info') { $risk = 'Medio' }
                    $reasons += 'sin firma digital'
                } elseif ($sig.Status -notin @('Valid', 'NoExiste', 'Desconocido')) {
                    $risk = 'Alto'
                    $reasons += "firma invalida ($($sig.Status))"
                }
            } elseif ($exe -and -not (Test-IsTrustedPath $exe)) {
                if ($risk -eq 'Info') { $risk = 'Bajo' }
                $reasons += 'el archivo referenciado no existe'
            }
            if ($reasons.Count -eq 0) { $reasons += 'autoarranque firmado en ubicacion confiable' }
            Add-Finding -Category 'Registro Run' -Risk $risk -Item "$($p.Name) = $cmd" -Path $exe `
                -Reason ($reasons -join '; ')
        }
    }
    if (-not $found) { Write-Host "  (Sin entradas Run/RunOnce)" -ForegroundColor DarkGray }
}

function Scan-ScheduledTasks {
    Write-Section "Tareas programadas sospechosas"
    $found = $false
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
    } catch {
        Write-Host "  (No se pudieron leer las tareas programadas)" -ForegroundColor DarkGray
        return
    }
    foreach ($t in $tasks) {
        foreach ($a in @($t.Actions)) {
            $exe = $a.Execute
            if (-not $exe) { continue }
            $argStr = [string]$a.Arguments
            # Expandimos variables de entorno para evaluar la ruta real.
            $exeExpanded = [Environment]::ExpandEnvironmentVariables($exe)
            $argExpanded = [Environment]::ExpandEnvironmentVariables($argStr)
            $risk = $null
            $reasons = @()

            # Senales FUERTES de descarga/ejecucion remota (cualquier ejecutable).
            if ($argExpanded -match 'FromBase64String|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|\biwr\b|\biex\b|Invoke-Expression') {
                $risk = 'Alto'; $reasons += 'descarga remota / ejecucion dinamica en los argumentos'
            }
            # Comando codificado: solo cuenta si quien ejecuta es PowerShell
            # (evita falsos positivos con "-e" de binarios legitimos del sistema).
            if (($exeExpanded -match 'powershell|pwsh') -and
                ($argExpanded -match '(^|\s)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}')) {
                $risk = 'Alto'; $reasons += 'PowerShell con comando codificado en Base64'
            }
            # Binario o script invocado desde carpeta de usuario/temporal.
            if (Test-IsUserPath $exeExpanded) {
                $risk = 'Alto'; $reasons += 'ejecuta binario en carpeta de usuario/temporal'
            }
            if (($exeExpanded -match 'powershell|cmd\.exe|wscript|cscript|mshta|rundll32') -and (Test-IsUserPath $argExpanded)) {
                if (-not $risk) { $risk = 'Medio' }
                $reasons += 'interprete invocando contenido de carpeta de usuario'
            }
            # Ventana oculta SOLO suma si ya hay otra senal; por si sola es comun en tareas legitimas.
            if ($risk -and $argExpanded -match '-w(indowstyle)?\s+hidden') {
                $reasons += 'ventana oculta'
            }
            if ($risk) {
                $found = $true
                $full = ("{0}\{1}" -f $t.TaskPath.TrimEnd('\'), $t.TaskName)
                Add-Finding -Category 'Tarea programada' -Risk $risk -Item $full `
                    -Path ("{0} {1}" -f $exe, $argStr).Trim() -Reason ($reasons -join '; ')
            }
        }
    }
    if (-not $found) { Write-Host "  (Sin tareas sospechosas)" -ForegroundColor DarkGray }
}

function Scan-Services {
    Write-Section "Servicios con binario sospechoso"
    $found = $false
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction Stop
    } catch {
        Write-Host "  (No se pudieron leer los servicios)" -ForegroundColor DarkGray
        return
    }
    foreach ($s in $svcs) {
        $exe = Resolve-ExePath $s.PathName
        if (-not $exe) { continue }
        $risk = $null
        $reasons = @()
        if (Test-IsUserPath $exe) {
            $risk = 'Alto'; $reasons += 'binario del servicio en carpeta de usuario/temporal'
        }
        if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
            $sig = Get-SignatureState $exe
            if ($sig.Status -notin @('Valid', 'NoExiste') -and (Test-IsUserPath $exe)) {
                $risk = 'Alto'; $reasons += "sin firma valida ($($sig.Status))"
            }
        }
        if ($risk) {
            $found = $true
            Add-Finding -Category 'Servicio' -Risk $risk -Item "$($s.Name) ($($s.State))" `
                -Path $s.PathName -Reason ($reasons -join '; ')
        }
    }
    if (-not $found) { Write-Host "  (Sin servicios sospechosos)" -ForegroundColor DarkGray }
}

function Scan-Processes {
    Write-Section "Procesos en ejecucion sospechosos"
    $found = $false
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path }
    foreach ($p in $procs) {
        $path = $p.Path
        $risk = $null
        $reasons = @()

        if (Test-IsUserPath $path) {
            $risk = 'Alto'; $reasons += 'corre desde carpeta de usuario/temporal'
        }
        # Proceso con nombre de sistema corriendo fuera de System32/Windows.
        $exeName = "$($p.Name).exe".ToLower()
        if ($exeName -in $script:SystemNames -and $path -notmatch '\\System32\\|\\SysWOW64\\|\\Windows\\') {
            $risk = 'Alto'; $reasons += 'nombre de proceso de sistema fuera de System32'
        }
        if ($risk) {
            $sig = Get-SignatureState $path
            if ($sig.Status -notin @('Valid')) { $reasons += "firma: $($sig.Status)" }
            $found = $true
            Add-Finding -Category 'Proceso' -Risk $risk -Item ("{0} (PID {1})" -f $p.Name, $p.Id) `
                -Path $path -Reason ($reasons -join '; ')
        }
    }
    if (-not $found) { Write-Host "  (Sin procesos sospechosos)" -ForegroundColor DarkGray }
}

function Scan-RecentExecutables {
    Write-Section "Ejecutables recientes en zonas de riesgo (ultimos $Days dias)"
    $cutoff = (Get-Date).AddDays(-$Days)
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $hits = 0
    $cap  = 60   # tope de hallazgos para no inundar la consola

    $dirs = if ($Full) {
        @($env:USERPROFILE) + $script:HotDirs | Select-Object -Unique
    } else {
        $script:HotDirs
    }

    foreach ($d in $dirs) {
        if (-not (Test-Path $d)) { continue }
        try {
            $files = Get-ChildItem -LiteralPath $d -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.LastWriteTime -ge $cutoff -and
                    ($script:ExecExt -contains $_.Extension.ToLower())
                }
        } catch { continue }

        foreach ($f in $files) {
            if ($hits -ge $cap) { break }
            if (-not $seen.Add($f.FullName.ToLower())) { continue }
            if (Test-IsExcludedPath $f.FullName) { continue }

            # Solo reportamos si hay una SENAL REAL de sospecha. Un ejecutable
            # reciente por si solo (ej: una dependencia recien instalada) no lo es.
            $risk = $null
            $reasons = @()

            if (Test-DoubleExtension $f.Name) {
                $risk = 'Alto'; $reasons += 'DOBLE EXTENSION enganosa (ej: documento.pdf.exe)'
            }
            if (($f.Attributes -band [IO.FileAttributes]::Hidden) -and ($f.Attributes -band [IO.FileAttributes]::System)) {
                if (-not $risk) { $risk = 'Medio' }
                $reasons += 'archivo oculto + sistema en carpeta de usuario'
            }
            # Binario sin firmar SOLO es senal si esta en una "zona de descarga"
            # (Temp, Downloads, Public). En carpetas de instalacion de apps las
            # DLLs sin firma son comunes y legitimas: las ignoramos para no inundar.
            $dropZone = $f.DirectoryName -match '\\Temp(\\|$)|\\Downloads(\\|$)|\\Users\\Public(\\|$)'
            if ($dropZone -and $f.Extension.ToLower() -in @('.exe', '.dll', '.scr', '.com', '.pif')) {
                $sig = Get-SignatureState $f.FullName
                if ($sig.Status -notin @('Valid', 'NoExiste', 'Desconocido')) {
                    $isExe = $f.Extension.ToLower() -in @('.exe', '.scr', '.com', '.pif')
                    if ($isExe) { $risk = 'Alto' } elseif (-not $risk) { $risk = 'Medio' }
                    $reasons += "binario sin firma en zona de descarga ($($sig.Status))"
                }
            }

            if ($risk) {
                $hits++
                $reasons += "modificado el $($f.LastWriteTime.ToString('yyyy-MM-dd'))"
                Add-Finding -Category 'Archivo reciente' -Risk $risk -Item $f.Name -Path $f.FullName `
                    -Reason ($reasons -join '; ')
            }
        }
        if ($hits -ge $cap) {
            Write-Host "  (... se alcanzo el tope de $cap hallazgos; usa -Days menor para acotar)" -ForegroundColor DarkGray
            break
        }
    }
    if ($hits -eq 0) {
        Write-Host "  (Sin ejecutables recientes sospechosos)" -ForegroundColor DarkGray
    }
}

function Show-Summary {
    Write-Title "RESUMEN"
    $alto  = @($script:Findings.Where({ $_.Riesgo -eq 'Alto'  })).Count
    $medio = @($script:Findings.Where({ $_.Riesgo -eq 'Medio' })).Count
    $bajo  = @($script:Findings.Where({ $_.Riesgo -eq 'Bajo'  })).Count
    $info  = @($script:Findings.Where({ $_.Riesgo -eq 'Info'  })).Count

    Write-Host ("  Riesgo ALTO   : {0}" -f $alto)  -ForegroundColor Red
    Write-Host ("  Riesgo MEDIO  : {0}" -f $medio) -ForegroundColor Yellow
    Write-Host ("  Riesgo BAJO   : {0}" -f $bajo)  -ForegroundColor DarkYellow
    Write-Host ("  Informativos  : {0}  (autoarranques conocidos, no sospechosos)" -f $info) -ForegroundColor Gray

    Write-Host ""
    if ($alto -gt 0) {
        Write-Host "  >> Hay hallazgos de riesgo ALTO. Revisa las rutas marcadas en rojo." -ForegroundColor Red
        Write-Host "     Si no reconoces un elemento, busca su nombre/hash en internet" -ForegroundColor Red
        Write-Host "     o subelo a https://www.virustotal.com antes de eliminarlo." -ForegroundColor Red
    } elseif ($medio -gt 0) {
        Write-Host "  >> Sin hallazgos de riesgo alto, pero hay elementos a revisar." -ForegroundColor Yellow
    } else {
        Write-Host "  >> No se encontraron elementos sospechosos con esta heuristica." -ForegroundColor Green
        Write-Host "     (Esto NO garantiza que el equipo este limpio: es solo un triaje.)" -ForegroundColor DarkGray
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Ejecucion
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Continue'

Show-MatrixRain
Show-Banner
Write-Host ("  SCANNER HEURISTICO DE MALWARE  -  {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm')) -ForegroundColor DarkGreen
Write-Host "  Herramienta defensiva de SOLO LECTURA. No elimina ni modifica nada." -ForegroundColor DarkGray
Write-Host ""
Write-BootSequence

Show-SystemInfo

Write-Title "ESCANEO"
Scan-StartupFolders
Scan-RegistryRun
Scan-ScheduledTasks
Scan-Services
Scan-Processes
Scan-RecentExecutables

Show-Summary

# Codigo de salida: 2 si hay riesgo alto, 1 si medio, 0 si limpio.
if (@($script:Findings.Where({ $_.Riesgo -eq 'Alto'  })).Count -gt 0)      { exit 2 }
elseif (@($script:Findings.Where({ $_.Riesgo -eq 'Medio' })).Count -gt 0)  { exit 1 }
else { exit 0 }
