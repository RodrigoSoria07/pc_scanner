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
| **Archivos recientes** | Ejecutables nuevos en zonas calientes, doble extensión, ocultos+sistema, sin firma en zonas de descarga |

### Niveles de riesgo

- 🔴 **Alto** — patrón clásico de malware (binario en Temp, doble extensión, PowerShell codificado…).
- 🟡 **Medio** — vale la pena revisarlo.
- 🟠 **Bajo** — anomalía menor (ej: autoarranque que apunta a un archivo inexistente).
- ⚪ **Info** — autoarranques conocidos y firmados; se listan para que los reconozcas, **no** son sospechosos.

---

## 🚀 Uso

```powershell
# Escaneo estándar (últimos 14 días para archivos recientes)
.\scan.ps1

# Acotar la ventana de archivos recientes a 7 días
.\scan.ps1 -Days 7

# Escaneo profundo: recorre todo el perfil de usuario (más lento)
.\scan.ps1 -Days 30 -Full
```

Si Windows bloquea la ejecución de scripts, corré con bypass puntual (no cambia tu política global):

```powershell
powershell -ExecutionPolicy Bypass -File .\scan.ps1
```

> 💡 **Tip:** ejecutá PowerShell **como Administrador** para que algunos chequeos
> (servicios, tareas de otros usuarios) sean completos.

### Parámetros

| Parámetro | Descripción | Default |
| --- | --- | --- |
| `-Days <n>` | Antigüedad en días para considerar un ejecutable "reciente" | `14` |
| `-Full` | Escaneo profundo de todo el perfil de usuario | (apagado) |

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

>> Ejecutables recientes en zonas calientes (ultimos 7 dias)
  [Alto ] factura.pdf.exe
          Ruta : C:\Users\...\Downloads\factura.pdf.exe
          Motivo: DOBLE EXTENSION enganosa; binario sin firma en zona de descarga (NotSigned)
```

---

## ⚠️ Limitaciones

- Es un **detector heurístico**, no un antivirus: puede tener falsos positivos y **no** detecta todo el malware.
- No analiza el contenido de los archivos ni calcula reputación online (eso lo hace VirusTotal).
- No modifica, mueve ni elimina nada. Vos decidís qué hacer con cada hallazgo.

## 🤝 Contribuir

Issues y PRs bienvenidos. Ideas a futuro: integración con VirusTotal (hash lookup),
exportar reporte a HTML/JSON, versión para Linux/macOS en Bash.

## 📄 Licencia

[MIT](LICENSE) © Rodrigo Soria
