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
```

### 🧹 Limpiar temporales (comando `clean`)

Aparte del scanner, se instala el comando `clean`, que **borra los temporales**
de usuario (`%TEMP%`) y del sistema (`C:\Windows\Temp`) y te muestra el
**rendimiento antes vs después** (disco libre, tamaño de temporales, CPU y RAM):

```powershell
clean           # pide confirmación antes de borrar
clean -Force    # borra sin preguntar
```

Los archivos en uso se saltean solos (no se fuerza el cierre de nada).

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
- No analiza el contenido de los archivos ni calcula reputación online (eso lo hace VirusTotal).
- No modifica, mueve ni elimina nada. Vos decidís qué hacer con cada hallazgo.

## 🤝 Contribuir

Issues y PRs bienvenidos. Ideas a futuro: integración con VirusTotal (hash lookup),
exportar reporte a HTML/JSON, auto-elevación opcional de `scan`, versión para Linux/macOS en Bash.

## 📄 Licencia

[MIT](LICENSE) © Rodrigo Soria
