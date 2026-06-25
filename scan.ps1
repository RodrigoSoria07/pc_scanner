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
      - Conexiones de red de procesos sospechosos (malware "llamando a casa").
      - Ejecutables recientes en zonas de riesgo (Temp, AppData, Downloads...).

    Ademas muestra una seccion de OPTIMIZACION (no de seguridad): lista los
    programas que arrancan con Windows y marca cuales son optimizables para
    acelerar el arranque.

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
    [switch]$NoAnim,

    # --- VirusTotal (opcional) ---
    [switch]$VirusTotal,            # consulta el hash de los binarios sospechosos en VirusTotal
    [string]$VTApiKey,             # API key (si se omite usa $env:VT_API_KEY)
    [int]$VTMax = 20,             # tope de consultas VT (free tier: 4/min, 500/dia)

    # --- Reportes (opcional) ---
    [switch]$Report,               # genera reporte HTML + JSON
    [switch]$Json,                # genera solo JSON
    [switch]$Pdf,                 # ademas genera PDF (requiere Microsoft Edge)
    [string]$OutDir,             # carpeta de salida (default Documents\pc_scanner)
    [switch]$OpenReport            # abre el HTML al terminar
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
    param([int]$Frames = 40)
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
            Start-Sleep -Milliseconds 12
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
        [string]$Reason,
        [string]$FileForHash   # ruta limpia del binario (cuando Ruta lleva argumentos)
    )
    $script:Findings.Add([PSCustomObject]@{
        Categoria   = $Category
        Riesgo      = $Risk
        Item        = $Item
        Ruta        = $Path
        Motivo      = $Reason
        FileForHash = $FileForHash
        Hash        = $null
        VT          = $null
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
                    -Path ("{0} {1}" -f $exe, $argStr).Trim() -Reason ($reasons -join '; ') `
                    -FileForHash $exeExpanded
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
                -Path $s.PathName -Reason ($reasons -join '; ') -FileForHash $exe
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

function Scan-NetworkConnections {
    Write-Section "Conexiones de red sospechosas"
    try {
        $conns = Get-NetTCPConnection -ErrorAction Stop |
            Where-Object { $_.State -in @('Established', 'Listen') }
    } catch {
        Write-Host "  (No se pudieron leer las conexiones de red)" -ForegroundColor DarkGray
        return
    }

    # Cache PID -> proceso para resolver rutas sin re-consultar.
    $procCache = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procCache[[int]$_.Id] = $_ }

    $loopback = @('127.0.0.1', '::1', '0.0.0.0', '::', '')
    $estab = 0; $listen = 0
    $found = $false
    $seen = New-Object System.Collections.Generic.HashSet[string]

    foreach ($c in $conns) {
        if ($c.State -eq 'Established') { $estab++ } else { $listen++ }

        $proc = $procCache[[int]$c.OwningProcess]
        $path = if ($proc) { $proc.Path } else { $null }
        $pname = if ($proc) { $proc.ProcessName } else { "PID $($c.OwningProcess)" }
        if (-not $path) { continue }   # sin ruta no podemos evaluar (suele ser del sistema)

        $risk = $null
        $reasons = @()

        if (Test-IsUserPath $path) {
            $risk = 'Alto'
            if ($c.State -eq 'Listen') {
                $reasons += "proceso en carpeta de usuario ESCUCHANDO en puerto $($c.LocalPort)"
            } else {
                $reasons += "proceso en carpeta de usuario con conexion saliente"
            }
        } elseif ($c.State -eq 'Established' -and $c.RemoteAddress -notin $loopback -and -not (Test-IsTrustedPath $path)) {
            $sig = Get-SignatureState $path
            if ($sig.Status -eq 'NotSigned') {
                $risk = 'Medio'; $reasons += 'proceso sin firma con conexion saliente'
            }
        }

        if ($risk) {
            $dest = if ($c.State -eq 'Listen') { "escucha :$($c.LocalPort)" } else { "$($c.RemoteAddress):$($c.RemotePort)" }
            $key = "$pname|$dest"
            if (-not $seen.Add($key)) { continue }
            $found = $true
            Add-Finding -Category 'Red' -Risk $risk -Item "$pname  ->  $dest" -Path $path `
                -Reason ($reasons -join '; ')
        }
    }

    Write-Host ("  ({0} conexiones establecidas, {1} en escucha)" -f $estab, $listen) -ForegroundColor DarkGray
    if (-not $found) { Write-Host "  (Sin conexiones sospechosas)" -ForegroundColor DarkGray }
}

function Scan-StartupOptimization {
    Write-Title "PROGRAMAS DE ARRANQUE (OPTIMIZACION)"
    Write-Host "  Que arranca con Windows. No es seguridad: son sugerencias para acelerar el arranque." -ForegroundColor DarkGray
    Write-Host ""

    try {
        $items = Get-CimInstance Win32_StartupCommand -ErrorAction Stop
    } catch {
        Write-Host "  (No se pudo leer la lista de programas de arranque)" -ForegroundColor DarkGray
        return
    }
    if (-not $items) {
        Write-Host "  (Sin programas de arranque registrados)" -ForegroundColor DarkGray
        return
    }

    # Esencial: seguridad, drivers, audio/video, fabricante. No conviene tocar.
    $essentialKw = 'securityhealth|defender|antivirus|mcafee|norton|kaspersky|bitdefender|eset|avast|avg|realtek|rtkaud|nvidia|nvcontainer|intel|igfx|amd|radeon|synaptics|elan|audiodg|sttray|dell|lenovo|hp '
    # Optimizable: updaters, launchers y apps que no necesitan arrancar con el SO.
    $optimizableKw = 'update|updater|helper|launcher|steam|spotify|discord|epic|adobe|acrobat|reader|itunes|quicktime|skype|zoom|webex|googleupdate|google update|java|jusched|onedrive|dropbox|google drive|slack|teams|notion|cron|toolbox|origin|ubisoft|battle\.net|riot|overwolf|docker|spotifyweb|whatsapp|telegram|grammarly|ccleaner'

    $optCount = 0
    foreach ($it in $items) {
        $name = if ($it.Name) { $it.Name } else { $it.Caption }
        $cmd  = [string]$it.Command
        $loc  = [string]$it.Location
        $hay  = "$name $cmd"

        if ($hay -imatch $essentialKw) {
            $tag = 'ESENCIAL  '; $color = 'Green'
        } elseif ($hay -imatch $optimizableKw) {
            $tag = 'OPTIMIZABLE'; $color = 'Yellow'; $optCount++
        } else {
            $tag = 'REVISAR   '; $color = 'Gray'
        }

        Write-Host ("  [{0}] " -f $tag) -ForegroundColor $color -NoNewline
        Write-Host $name -ForegroundColor $color
        if ($loc) { Write-Host "                Origen: $loc" -ForegroundColor DarkGray }
    }

    Write-Host ""
    if ($optCount -gt 0) {
        Write-Host ("  >> {0} programa(s) marcados como OPTIMIZABLES." -f $optCount) -ForegroundColor Yellow
        Write-Host "     Para desactivarlos y acelerar el arranque:" -ForegroundColor Gray
        Write-Host "     Administrador de tareas (Ctrl+Shift+Esc) -> pestana 'Inicio' -> clic derecho -> Deshabilitar" -ForegroundColor Gray
        Write-Host "     (Desactivar el inicio automatico NO desinstala la app; podes abrirla cuando quieras.)" -ForegroundColor DarkGray
    } else {
        Write-Host "  >> No se detectaron programas claramente optimizables." -ForegroundColor Green
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

    # Sugerencia: limpieza de temporales (opcional, la decide el usuario).
    $tmpBytes = 0
    foreach ($p in @($env:TEMP, (Join-Path $env:windir 'Temp'))) {
        if (Test-Path $p) {
            $s = (Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue |
                  Measure-Object -Property Length -Sum).Sum
            if ($s) { $tmpBytes += [double]$s }
        }
    }
    if ($tmpBytes -ge 1MB) {
        if     ($tmpBytes -ge 1GB) { $tmpStr = ('{0:N2} GB' -f ($tmpBytes / 1GB)) }
        else                       { $tmpStr = ('{0:N0} MB' -f ($tmpBytes / 1MB)) }
        Write-Host ("  Tip: tenes {0} en archivos temporales. Para liberar espacio:" -f $tmpStr) -ForegroundColor Cyan
        # scan corre con -NoProfile, asi que Get-Command no ve la funcion 'clean'
        # del perfil. Detectamos leyendo el archivo de perfil directamente.
        $cleanRegistered = $false
        if ($PROFILE -and (Test-Path $PROFILE)) {
            if (Select-String -Path $PROFILE -Pattern 'function\s+clean' -Quiet -ErrorAction SilentlyContinue) {
                $cleanRegistered = $true
            }
        }
        $cleanScript = Join-Path $PSScriptRoot 'clean.ps1'
        if ($cleanRegistered) {
            Write-Host "       clean        (borra %TEMP% y Windows\Temp; pide confirmacion)" -ForegroundColor White
        } elseif (Test-Path $cleanScript) {
            # Sin instalar: damos la ruta absoluta para que funcione desde cualquier carpeta.
            Write-Host ("       powershell -ExecutionPolicy Bypass -File `"{0}`"" -f $cleanScript) -ForegroundColor White
        }
        Write-Host ""
    }
}

# ---------------------------------------------------------------------------
# VirusTotal (opcional): reputacion real de los binarios sospechosos
# ---------------------------------------------------------------------------

# Cache en memoria: hash -> resultado VT (evita reconsultar el mismo binario).
$script:VTCache = @{}

# Devuelve una ruta de archivo existente y hasheable a partir de un hallazgo.
function Resolve-HashableFile {
    param($Finding)
    $cand = $Finding.FileForHash
    if ($cand -and (Test-Path -LiteralPath $cand -PathType Leaf)) { return $cand }
    if ($Finding.Ruta -and (Test-Path -LiteralPath $Finding.Ruta -PathType Leaf)) { return $Finding.Ruta }
    return $null
}

function Get-FileSha256 {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
    } catch { return $null }
}

function Get-VTApiKey {
    param([string]$Explicit)
    if ($Explicit)               { return $Explicit }
    if ($env:VT_API_KEY)         { return $env:VT_API_KEY }
    if ($env:VIRUSTOTAL_API_KEY) { return $env:VIRUSTOTAL_API_KEY }
    return $null
}

# Consulta el reporte de un hash en VirusTotal v3. NO sube el archivo (privacidad):
# solo consulta por hash. Si VT no lo conoce, devuelve Error='desconocido'.
function Get-VTFileReport {
    param([string]$Sha256, [string]$ApiKey)
    if ($script:VTCache.ContainsKey($Sha256)) { return $script:VTCache[$Sha256] }

    $result = [PSCustomObject]@{
        Found     = $false
        Malicious = 0
        Suspicious= 0
        Total     = 0
        Permalink = "https://www.virustotal.com/gui/file/$Sha256"
        Error     = $null
    }
    try {
        $resp = Invoke-RestMethod -Method Get -Uri "https://www.virustotal.com/api/v3/files/$Sha256" `
            -Headers @{ 'x-apikey' = $ApiKey } -TimeoutSec 30 -ErrorAction Stop
        $stats = $resp.data.attributes.last_analysis_stats
        $result.Found      = $true
        $result.Malicious  = [int]$stats.malicious
        $result.Suspicious = [int]$stats.suspicious
        $result.Total      = [int]$stats.malicious + [int]$stats.suspicious + `
                             [int]$stats.undetected + [int]$stats.harmless + [int]$stats.timeout
    } catch {
        $code = $null
        try { $code = [int]$_.Exception.Response.StatusCode } catch {}
        switch ($code) {
            404     { $result.Error = 'desconocido' }
            429     { $result.Error = 'rate-limit' }
            401     { $result.Error = 'api-key-invalida' }
            default { $result.Error = $_.Exception.Message }
        }
    }
    $script:VTCache[$Sha256] = $result
    return $result
}

# Recorre los hallazgos con archivo real (priorizando Alto/Medio), consulta VT
# y enriquece cada hallazgo. Confirma a 'Alto' los que VT marca como maliciosos.
function Invoke-VTEnrichment {
    param([string]$ApiKey, [int]$Max)
    Write-Section "VirusTotal: reputacion de binarios sospechosos"
    if (-not $ApiKey) {
        Write-Host "  (Sin API key. Define `$env:VT_API_KEY o pasa -VTApiKey." -ForegroundColor DarkGray
        Write-Host "   Conseguila gratis en https://www.virustotal.com/gui/join-us)" -ForegroundColor DarkGray
        return
    }

    $order = @{ 'Alto' = 0; 'Medio' = 1; 'Bajo' = 2; 'Info' = 3 }
    $cands = @($script:Findings | Where-Object { Resolve-HashableFile $_ } |
        Sort-Object @{ Expression = { $order[$_.Riesgo] } })

    if ($cands.Count -eq 0) {
        Write-Host "  (No hay archivos analizables entre los hallazgos)" -ForegroundColor DarkGray
        return
    }

    $queried = 0
    $needDelay = $false
    foreach ($f in $cands) {
        if ($queried -ge $Max) {
            Write-Host ("  (... tope de {0} consultas alcanzado; usa -VTMax para subirlo)" -f $Max) -ForegroundColor DarkGray
            break
        }
        $file = Resolve-HashableFile $f
        $hash = Get-FileSha256 $file
        if (-not $hash) { continue }
        $f.Hash = $hash

        # Respetamos el limite del free tier (4/min) salvo que ya este en cache.
        if (-not $script:VTCache.ContainsKey($hash)) {
            if ($needDelay) { Start-Sleep -Seconds 15 }
            $needDelay = $true
            $queried++
        }
        $vt = Get-VTFileReport -Sha256 $hash -ApiKey $ApiKey
        $f.VT = $vt

        if ($vt.Found -and $vt.Malicious -gt 0) {
            Write-Host ("  [VT] {0}/{1} motores: MALICIOSO  ->  {2}" -f $vt.Malicious, $vt.Total, $f.Item) -ForegroundColor Red
            Write-Host ("        {0}" -f $vt.Permalink) -ForegroundColor DarkGray
            if ($f.Riesgo -ne 'Alto') { $f.Riesgo = 'Alto' }   # confirmado por VT
            $f.Motivo = ("{0}; VirusTotal: {1}/{2} detecciones" -f $f.Motivo, $vt.Malicious, $vt.Total)
        } elseif ($vt.Found) {
            Write-Host ("  [VT] 0/{0}: limpio en VirusTotal  ->  {1}" -f $vt.Total, $f.Item) -ForegroundColor Green
        } elseif ($vt.Error -eq 'desconocido') {
            Write-Host ("  [VT] sin datos (nunca analizado)  ->  {0}" -f $f.Item) -ForegroundColor DarkGray
        } elseif ($vt.Error -eq 'rate-limit') {
            Write-Host "  [VT] limite de consultas alcanzado; intenta mas tarde." -ForegroundColor Yellow
            break
        } elseif ($vt.Error -eq 'api-key-invalida') {
            Write-Host "  [VT] API key invalida. Revisa -VTApiKey / `$env:VT_API_KEY." -ForegroundColor Red
            break
        } else {
            Write-Host ("  [VT] error consultando: {0}" -f $vt.Error) -ForegroundColor DarkGray
        }
    }
}

# ---------------------------------------------------------------------------
# Reportes: JSON estructurado + HTML autocontenido (+ PDF opcional)
# ---------------------------------------------------------------------------

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

# Construye el modelo de datos del reporte (sirve para JSON y HTML).
function Get-ReportModel {
    $alto  = @($script:Findings.Where({ $_.Riesgo -eq 'Alto'  })).Count
    $medio = @($script:Findings.Where({ $_.Riesgo -eq 'Medio' })).Count
    $bajo  = @($script:Findings.Where({ $_.Riesgo -eq 'Bajo'  })).Count
    $info  = @($script:Findings.Where({ $_.Riesgo -eq 'Info'  })).Count

    $osCaption = ''
    try { $osCaption = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}

    [PSCustomObject]@{
        generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        tool        = 'pc_scanner'
        host        = $env:COMPUTERNAME
        user        = $env:USERNAME
        os          = $osCaption
        scanDays    = $Days
        fullScan    = [bool]$Full
        virusTotal  = [bool]$VirusTotal
        summary     = [PSCustomObject]@{ alto = $alto; medio = $medio; bajo = $bajo; info = $info; total = $script:Findings.Count }
        findings    = @($script:Findings | ForEach-Object {
            [PSCustomObject]@{
                categoria = $_.Categoria
                riesgo    = $_.Riesgo
                item      = $_.Item
                ruta      = $_.Ruta
                motivo    = $_.Motivo
                hash      = $_.Hash
                virustotal= if ($_.VT) {
                    [PSCustomObject]@{
                        encontrado = $_.VT.Found
                        maliciosos = $_.VT.Malicious
                        total      = $_.VT.Total
                        link       = $_.VT.Permalink
                    }
                } else { $null }
            }
        })
    }
}

function Export-JsonReport {
    param([string]$Path)
    (Get-ReportModel) | ConvertTo-Json -Depth 6 | Out-File -FilePath $Path -Encoding UTF8
}

function Export-HtmlReport {
    param([string]$Path)
    $m = Get-ReportModel

    $rows = foreach ($f in $m.findings) {
        $rk = $f.riesgo.ToLower()
        $vtCell = '<span class="muted">-</span>'
        if ($f.virustotal) {
            if ($f.virustotal.encontrado -and $f.virustotal.maliciosos -gt 0) {
                $vtCell = ('<a class="vt-bad" href="{0}" target="_blank">{1}/{2} MALICIOSO</a>' -f `
                    (ConvertTo-HtmlSafe $f.virustotal.link), $f.virustotal.maliciosos, $f.virustotal.total)
            } elseif ($f.virustotal.encontrado) {
                $vtCell = ('<a class="vt-ok" href="{0}" target="_blank">0/{1} limpio</a>' -f `
                    (ConvertTo-HtmlSafe $f.virustotal.link), $f.virustotal.total)
            } else {
                $vtCell = '<span class="muted">sin datos</span>'
            }
        }
        @"
<tr class="risk-$rk">
  <td><span class="badge badge-$rk">$(ConvertTo-HtmlSafe $f.riesgo)</span></td>
  <td>$(ConvertTo-HtmlSafe $f.categoria)</td>
  <td class="item">$(ConvertTo-HtmlSafe $f.item)</td>
  <td class="path">$(ConvertTo-HtmlSafe $f.ruta)</td>
  <td class="reason">$(ConvertTo-HtmlSafe $f.motivo)</td>
  <td class="vt">$vtCell</td>
</tr>
"@
    }

    $html = @"
<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pc_scanner - Reporte $(ConvertTo-HtmlSafe $m.host)</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; background:#0a0f0a; color:#cfe8cf; font:14px/1.5 'Segoe UI',system-ui,sans-serif; }
  .wrap { max-width:1100px; margin:0 auto; padding:24px; }
  h1 { color:#5fe85f; font-family:Consolas,monospace; letter-spacing:1px; margin:0 0 4px; }
  .sub { color:#6f9f6f; margin-bottom:24px; }
  .meta { display:flex; flex-wrap:wrap; gap:8px 24px; background:#0f1a0f; border:1px solid #1d3a1d; border-radius:8px; padding:16px; margin-bottom:20px; }
  .meta div { min-width:160px; }
  .meta b { color:#9fd49f; display:block; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }
  .card { flex:1; min-width:120px; border-radius:8px; padding:14px 16px; border:1px solid; }
  .card .n { font-size:28px; font-weight:700; }
  .card.alto  { background:#2a0d0d; border-color:#5a1d1d; color:#ff8a8a; }
  .card.medio { background:#2a230d; border-color:#5a4d1d; color:#ffd86a; }
  .card.bajo  { background:#26220d; border-color:#4d451d; color:#e0c97a; }
  .card.info  { background:#12210f; border-color:#264a26; color:#9fd49f; }
  .tablewrap { overflow-x:auto; border:1px solid #1d3a1d; border-radius:8px; }
  table { border-collapse:collapse; width:100%; min-width:760px; }
  th,td { text-align:left; padding:10px 12px; border-bottom:1px solid #162916; vertical-align:top; }
  th { background:#0f1a0f; color:#9fd49f; font-size:11px; text-transform:uppercase; letter-spacing:.5px; position:sticky; top:0; }
  tr.risk-alto { background:rgba(90,29,29,.18); }
  .badge { padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
  .badge-alto  { background:#5a1d1d; color:#ffb3b3; }
  .badge-medio { background:#5a4d1d; color:#ffe39a; }
  .badge-bajo  { background:#4d451d; color:#e8d79a; }
  .badge-info  { background:#264a26; color:#bfe8bf; }
  .path,.item { font-family:Consolas,monospace; font-size:12px; word-break:break-all; }
  .reason { color:#9fb89f; font-size:12px; }
  .muted { color:#5f7f5f; }
  .vt-bad { color:#ff8a8a; font-weight:700; text-decoration:none; }
  .vt-ok  { color:#7fe87f; text-decoration:none; }
  footer { margin-top:24px; color:#5f7f5f; font-size:12px; }
  a { color:#7fbfff; }
</style></head><body><div class="wrap">
  <h1>// pc_scanner</h1>
  <div class="sub">Triaje heuristico de malware &mdash; reporte generado el $(ConvertTo-HtmlSafe $m.generatedAt)</div>
  <div class="meta">
    <div><b>Equipo</b>$(ConvertTo-HtmlSafe $m.host)</div>
    <div><b>Usuario</b>$(ConvertTo-HtmlSafe $m.user)</div>
    <div><b>Sistema</b>$(ConvertTo-HtmlSafe $m.os)</div>
    <div><b>Ventana</b>ultimos $($m.scanDays) dias$(if($m.fullScan){' (profundo)'})</div>
    <div><b>VirusTotal</b>$(if($m.virusTotal){'activado'}else{'no'})</div>
  </div>
  <div class="cards">
    <div class="card alto"><div class="n">$($m.summary.alto)</div>Riesgo ALTO</div>
    <div class="card medio"><div class="n">$($m.summary.medio)</div>Riesgo MEDIO</div>
    <div class="card bajo"><div class="n">$($m.summary.bajo)</div>Riesgo BAJO</div>
    <div class="card info"><div class="n">$($m.summary.info)</div>Informativos</div>
  </div>
  <div class="tablewrap"><table>
    <thead><tr><th>Riesgo</th><th>Categoria</th><th>Item</th><th>Ruta</th><th>Motivo</th><th>VirusTotal</th></tr></thead>
    <tbody>
$($rows -join "`n")
    </tbody>
  </table></div>
  <footer>
    pc_scanner es una herramienta de triaje heuristico de SOLO LECTURA, no un antivirus.
    Un resultado limpio no garantiza que el equipo este libre de amenazas.
    Verifica siempre las rutas marcadas antes de eliminar nada.
  </footer>
</div></body></html>
"@
    $html | Out-File -FilePath $Path -Encoding UTF8
}

# Mejor esfuerzo: convierte el HTML a PDF usando Microsoft Edge headless.
function Export-Pdf {
    param([string]$HtmlPath, [string]$PdfPath)
    $edge = $null
    foreach ($c in @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")) {
        if (Test-Path $c) { $edge = $c; break }
    }
    if (-not $edge) {
        $cmd = Get-Command msedge.exe -ErrorAction SilentlyContinue
        if ($cmd) { $edge = $cmd.Source }
    }
    if (-not $edge) {
        Write-Host "  (PDF omitido: no se encontro Microsoft Edge)" -ForegroundColor DarkGray
        return $false
    }
    try {
        $uri = ([System.Uri]$HtmlPath).AbsoluteUri
        & $edge --headless --disable-gpu "--print-to-pdf=$PdfPath" --no-pdf-header-footer $uri 2>$null
        Start-Sleep -Milliseconds 800
        return (Test-Path $PdfPath)
    } catch {
        Write-Host ("  (PDF omitido: {0})" -f $_.Exception.Message) -ForegroundColor DarkGray
        return $false
    }
}

# Orquesta la generacion de todos los reportes solicitados.
function Export-Reports {
    param([switch]$Html, [switch]$JsonOut, [switch]$MakePdf, [string]$Dir, [switch]$Open)
    Write-Title "REPORTES"

    if (-not $Dir) { $Dir = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'pc_scanner' }
    try {
        if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    } catch {
        Write-Host ("  No se pudo crear la carpeta de reportes: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        return
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $base  = Join-Path $Dir ("scan_{0}" -f $stamp)
    $htmlPath = "$base.html"

    if ($JsonOut) {
        try { Export-JsonReport -Path "$base.json"; Write-Host ("  JSON : {0}.json" -f $base) -ForegroundColor Green }
        catch { Write-Host ("  Error generando JSON: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
    }
    if ($Html) {
        try { Export-HtmlReport -Path $htmlPath; Write-Host ("  HTML : {0}" -f $htmlPath) -ForegroundColor Green }
        catch { Write-Host ("  Error generando HTML: {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
    }
    if ($MakePdf) {
        if (-not (Test-Path $htmlPath)) {
            try { Export-HtmlReport -Path $htmlPath } catch {}   # PDF necesita el HTML
        }
        if (Export-Pdf -HtmlPath $htmlPath -PdfPath "$base.pdf") {
            Write-Host ("  PDF  : {0}.pdf" -f $base) -ForegroundColor Green
        }
    }
    if ($Open -and (Test-Path $htmlPath)) {
        try { Start-Process $htmlPath } catch {}
    }
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
Scan-NetworkConnections
Scan-RecentExecutables

if ($VirusTotal) {
    Invoke-VTEnrichment -ApiKey (Get-VTApiKey $VTApiKey) -Max $VTMax
}

Scan-StartupOptimization

Show-Summary

if ($Report -or $Json -or $Pdf) {
    Export-Reports -Html:($Report -or $Pdf) -JsonOut:($Report -or $Json) -MakePdf:$Pdf `
        -Dir $OutDir -Open:$OpenReport
}

# Codigo de salida: 2 si hay riesgo alto, 1 si medio, 0 si limpio.
if (@($script:Findings.Where({ $_.Riesgo -eq 'Alto'  })).Count -gt 0)      { exit 2 }
elseif (@($script:Findings.Where({ $_.Riesgo -eq 'Medio' })).Count -gt 0)  { exit 1 }
else { exit 0 }
