# 🛡️ Scan — Scanner heurístico de malware para Windows

Herramienta de **triaje defensivo** que revisa tu propio equipo en busca de elementos
sospechosos y te muestra **dónde están alojados** (ruta exacta) y con qué **nivel de riesgo**.

> ⚠️ **No es un antivirus.** No usa bases de firmas ni elimina nada. Es de **solo lectura**
> y sirve para detectar rápidamente cosas raras (persistencia de malware, ejecutables
> tirados en carpetas temporales, tareas/servicios sospechosos). Para limpieza usá tu
> antivirus o [VirusTotal](https://www.virustotal.com).

---

## ✨ ¿Qué revisa?

| Módulo | Qué busca |
| --- | --- |
| **Carpetas de inicio** | Programas/scripts que arrancan al iniciar sesión |
| **Registro Run / RunOnce** | Autoarranques en HKCU y HKLM (incluido Wow6432Node) |
| **Tareas programadas** | Tareas con comandos ofuscados, descargas remotas o binarios en carpetas de usuario |
| **Servicios** | Servicios cuyo binario está en ubicaciones de usuario o sin firmar |
| **Procesos** | Procesos corriendo desde Temp/AppData o suplantando nombres del sistema |
| **Conexiones de red** | Procesos sospechosos conectados a internet o escuchando puertos (malware "llamando a casa") |
| **Archivos recientes** | Ejecutables nuevos en zonas de riesgo, doble extensión, ocultos+sistema, sin firma en zonas de descarga |

Además incluye una sección de **optimización del arranque** (no es seguridad): lista los programas
que arrancan con Windows y marca cuáles son `OPTIMIZABLE` (updaters, launchers que podés desactivar
para acelerar el arranque) vs. `ESENCIAL` (seguridad, drivers).

### Niveles de riesgo

- 🔴 **Alto** — patrón clásico de malware (binario en Temp, doble extensión, PowerShell codificado…).
- 🟡 **Medio** — vale la pena revisarlo.
- 🟠 **Bajo** — anomalía menor (ej: autoarranque que apunta a un archivo inexistente).
- ⚪ **Info** — autoarranques conocidos y firmados; se listan para que los reconozcas, **no** son sospechosos.

---

## ⚡ Instalación rápida en una PC nueva (un solo comando)

Abrí **PowerShell** y pegá esto. Descarga todo desde GitHub y deja el comando `scan` listo:

```powershell
irm https://raw.githubusercontent.com/RodrigoSoria07/pc_scanner/main/get.ps1 | iex
```

Después **abrí una ventana nueva de PowerShell** y ya podés usar `scan` desde cualquier carpeta.

> No requiere admin ni instala paquetes del sistema. Solo copia los scripts a
> `%LOCALAPPDATA%\pc_scanner` y registra el comando en tu perfil.

---

## 🚀 Instalación (comando `scan`)

Si clonaste el repo, corré el instalador **una sola vez**. Registra el comando `scan` en tu perfil de PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Después, abrí una **nueva** ventana de PowerShell y ya podés usarlo desde cualquier carpeta:

```powershell
scan                # escaneo estándar
scan -Days 7        # acota archivos recientes a 7 días
scan -Full          # escaneo profundo de todo el perfil (más lento)
scan -NoAnim        # sin animaciones
scan -Report        # genera reporte HTML + JSON
scan -VirusTotal    # consulta el hash de lo sospechoso en VirusTotal
```

### 🌐 Reputación con VirusTotal (`-VirusTotal`)

Con `-VirusTotal`, el scanner calcula el **SHA-256** de cada binario sospechoso y consulta
su reputación en [VirusTotal](https://www.virustotal.com) (cuántos motores antivirus lo
marcan como malicioso). Pasa de *"esto es raro"* a *"12/70 motores lo detectan como malware"*.
Si VirusTotal lo confirma malicioso, el hallazgo se **eleva automáticamente a riesgo Alto**.

> 🔒 Solo consulta por hash, **no sube tus archivos** (privacidad). Necesitás una API key
> gratuita: registrate en https://www.virustotal.com/gui/join-us y guardala así:
>
> ```powershell
> setx VT_API_KEY "tu_api_key_aqui"     # una sola vez; abrí una terminal nueva después
> scan -VirusTotal
> # o sin guardarla:  scan -VirusTotal -VTApiKey "tu_api_key"
> ```
>
> El plan gratuito permite 4 consultas/minuto, así que el scanner las **espacia solo**.
> Con `-VTMax <n>` cambiás el tope de consultas por escaneo (default 20).

### 📄 Reportes HTML / JSON / PDF (`-Report`)

```powershell
scan -Report                 # HTML + JSON en Documentos\pc_scanner
scan -Json                   # solo JSON (ideal para integraciones)
scan -Report -Pdf            # además genera PDF (usa Microsoft Edge)
scan -Report -OpenReport     # abre el HTML al terminar
scan -Report -OutDir "D:\informes"   # carpeta de salida personalizada
scan -VirusTotal -Report     # combina ambos: reporte con columna de VirusTotal
```

Genera un **reporte HTML autocontenido** (tabla de hallazgos con colores por riesgo,
resumen y enlaces a VirusTotal) y un **JSON estructurado** para integrarlo en otros
sistemas. El PDF se genera a partir del HTML usando Microsoft Edge en modo headless.
Por defecto se guardan en `Documentos\pc_scanner\scan_<fecha>.{html,json,pdf}`.

### 🧹 Limpiar temporales (comando `clean`)

Aparte del scanner, se instala el comando `clean`, que **borra los temporales**
de usuario (`%TEMP%`) y del sistema (`C:\Windows\Temp`) y te muestra el
**rendimiento antes vs después** (disco libre, tamaño de temporales, CPU y RAM):

```powershell
clean           # pide confirmación antes de borrar
clean -Force    # borra sin preguntar
clean -DryRun   # SIMULACIÓN: muestra qué borraría, sin borrar nada
```

Los archivos en uso se saltean solos (no se fuerza el cierre de nada).

> 🧪 **Modo simulación (`-DryRun`):** lista exactamente qué se borraría y cuánto espacio
> liberaría, **sin tocar nada** (y sin pedir UAC). Ideal para revisar antes de ejecutar
> de verdad, sobre todo si limpiás la PC de otra persona.
>
> 📋 **Log de auditoría:** cada ejecución (real o simulada) registra qué se borró, qué se
> saltó y cuánto se liberó en `%LOCALAPPDATA%\pc_scanner\logs\clean_<fecha>.log`. Cambialo
> con `-LogPath <ruta>`.

> 🔒 `clean` **pide permisos de administrador (UAC)** automáticamente, así puede
> borrar también `C:\Windows\Temp`. Si rechazás el UAC, igual limpia tu `%TEMP%`.

> ℹ️ Limpiar temporales libera **espacio en disco**, no reduce la CPU. Los
> valores de CPU/RAM se muestran solo como referencia.

### 🔄 Actualizar (comando `update`)

Para traer la última versión publicada en GitHub sin recordar el one-liner:

```powershell
update
```

Re-descarga todos los scripts a `%LOCALAPPDATA%\pc_scanner` y vuelve a registrar
los comandos. Después **abrí una ventana nueva** de PowerShell para tomar los cambios.

Para quitar el comando del perfil:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
```

> 🟢 **Modo "consola hacker":** al arrancar muestra una lluvia estilo Matrix, un banner
> ASCII y una secuencia de arranque animada, y los datos del sistema aparecen con efecto
> máquina de escribir. Las animaciones se **desactivan solas** si mandás la salida a un
> archivo, o podés apagarlas con `-NoAnim`.

> 💡 **Tip:** ejecutá PowerShell **como Administrador** para que algunos chequeos
> (servicios, tareas de otros usuarios) sean completos.

### Sin instalar (uso directo)

Si preferís no tocar tu perfil, podés correrlo directamente desde la carpeta del proyecto:

```powershell
powershell -ExecutionPolicy Bypass -File .\scan.ps1
```

O desde CMD / con la carpeta en el `PATH`, usando el wrapper incluido:

```cmd
scan.cmd -Days 7
```

### Parámetros

| Parámetro | Descripción | Default |
| --- | --- | --- |
| `-Days <n>` | Antigüedad en días para considerar un ejecutable "reciente" | `14` |
| `-Full` | Escaneo profundo de todo el perfil de usuario | (apagado) |
| `-NoAnim` | Desactiva las animaciones (intro Matrix, efecto tipeo) | (apagado) |
| `-VirusTotal` | Consulta el hash de los binarios sospechosos en VirusTotal | (apagado) |
| `-VTApiKey <key>` | API key de VirusTotal (o usá `$env:VT_API_KEY`) | — |
| `-VTMax <n>` | Tope de consultas a VirusTotal por escaneo | `20` |
| `-Report` | Genera reporte HTML + JSON | (apagado) |
| `-Json` | Genera solo el reporte JSON | (apagado) |
| `-Pdf` | Genera también PDF (requiere Microsoft Edge) | (apagado) |
| `-OutDir <ruta>` | Carpeta de salida de los reportes | `Documentos\pc_scanner` |
| `-OpenReport` | Abre el HTML al terminar | (apagado) |

### Códigos de salida

Útiles si lo integrás en otro script o tarea:

| Código | Significado |
| --- | --- |
| `0` | Sin hallazgos de riesgo |
| `1` | Hay hallazgos de riesgo **medio** |
| `2` | Hay hallazgos de riesgo **alto** |

---

## 📋 Ejemplo de salida

```
>> Tareas programadas sospechosas
  [Alto ] \Microsoft\Windows\Foo\Bar
          Ruta : powershell.exe -enc SQBFAFgA...
          Motivo: PowerShell con comando codificado en Base64

>> Ejecutables recientes en zonas de riesgo (ultimos 7 dias)
  [Alto ] factura.pdf.exe
          Ruta : C:\Users\...\Downloads\factura.pdf.exe
          Motivo: DOBLE EXTENSION enganosa; binario sin firma en zona de descarga (NotSigned)
```

---

## 🛠️ Solución de problemas

**`scan` no se reconoce como comando** o el perfil tira *"la ejecución de scripts está deshabilitada"*:
es la política de ejecución de Windows (viene `Restricted` por defecto). El instalador ya la ajusta,
pero si lo necesitás a mano (no requiere admin):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Después **abrí una terminal nueva** y volvé a probar `scan`. Si tu perfil está dentro de OneDrive y
sigue sin cargar, desbloquealo: `Unblock-File $PROFILE`.

## ⚠️ Limitaciones

- Es un **detector heurístico**, no un antivirus: puede tener falsos positivos y **no** detecta todo el malware.
- La reputación online es **opcional** (`-VirusTotal`) y requiere API key; sin ella, el scan sigue siendo 100% local.
- No modifica, mueve ni elimina nada. Vos decidís qué hacer con cada hallazgo.

## 🤝 Contribuir

Issues y PRs bienvenidos. Ideas a futuro: detección de persistencia avanzada
(DLL/COM hijacking, suscripciones WMI), validación de cadena de certificados,
escaneo en paralelo, versión para Linux/macOS en Bash.

## 📄 Licencia

[MIT](LICENSE) © Rodrigo Soria
