# 🛡️ Scan — Heuristic malware triage scanner for Windows

A **defensive triage tool** that inspects your own machine for suspicious items and shows you
**where they live** (exact path) and at what **risk level**.

> ⚠️ **It is not an antivirus.** It uses no signature databases and removes nothing. It is
> **read-only** and meant to quickly surface odd things (malware persistence, executables
> dropped in temp folders, suspicious tasks/services). For cleanup, use your antivirus or
> [VirusTotal](https://www.virustotal.com).

---

## ✨ What it checks

| Module | What it looks for |
| --- | --- |
| **Startup folders** | Programs/scripts that launch at sign-in |
| **Run / RunOnce registry** | Autostarts in HKCU and HKLM (including Wow6432Node) |
| **Scheduled tasks** | Tasks with obfuscated commands, remote downloads, or binaries in user folders |
| **Services** | Services whose binary lives in user locations or is unsigned |
| **Processes** | Processes running from Temp/AppData or impersonating system names |
| **Network connections** | Suspicious processes connected to the internet or listening on ports (malware "calling home") |
| **Recent files** | New executables in risky areas, double extensions, hidden+system, unsigned in download zones |

It also includes a **startup optimization** section (not security): it lists programs that start
with Windows and marks which are `OPTIMIZABLE` (updaters, launchers you can disable to speed up
boot) vs. `ESSENTIAL` (security, drivers).

### Risk levels

- 🔴 **High** — classic malware pattern (binary in Temp, double extension, encoded PowerShell…).
- 🟡 **Medium** — worth reviewing.
- 🟠 **Low** — minor anomaly (e.g., an autostart pointing to a missing file).
- ⚪ **Info** — known, signed autostarts; listed so you recognize them — **not** suspicious.

---

## ⚡ Quick install on a fresh PC (single command)

Open **PowerShell** and paste this. It downloads everything from GitHub and leaves the `scan`
command ready:

```powershell
irm https://raw.githubusercontent.com/RodrigoSoria07/pc_scanner/main/get.ps1 | iex
```

Then **open a new PowerShell window** and you can run `scan` from any folder.

> No admin required and no system packages installed. It just copies the scripts to
> `%LOCALAPPDATA%\pc_scanner` and registers the command in your profile.

---

## 🚀 Install (the `scan` command)

If you cloned the repo, run the installer **once**. It registers the `scan` command in your
PowerShell profile:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Then open a **new** PowerShell window and use it from anywhere:

```powershell
scan                # standard scan
scan -Days 7        # limit "recent files" to the last 7 days
scan -Full          # deep scan of the whole user profile (slower)
scan -NoAnim        # no animations
scan -Report        # generate HTML + JSON report
scan -VirusTotal    # check suspicious hashes against VirusTotal
```

### 🌐 Reputation via VirusTotal (`-VirusTotal`)

With `-VirusTotal`, the scanner computes the **SHA-256** of each suspicious binary and checks its
reputation on [VirusTotal](https://www.virustotal.com) (how many antivirus engines flag it as
malicious). It goes from *"this looks odd"* to *"12/70 engines detect this as malware."* If
VirusTotal confirms it malicious, the finding is **automatically escalated to High risk**.

> 🔒 It only queries by hash — it **does not upload your files** (privacy). You need a free API key:
> sign up at https://www.virustotal.com/gui/join-us and store it like this:
>
> ```powershell
> setx VT_API_KEY "your_api_key_here"     # once; open a new terminal afterward
> scan -VirusTotal
> # or without storing it:  scan -VirusTotal -VTApiKey "your_api_key"
> ```
>
> The free tier allows 4 queries/minute, so the scanner **paces them automatically**.
> Use `-VTMax <n>` to change the per-scan query cap (default 20).

### 📄 HTML / JSON / PDF reports (`-Report`)

```powershell
scan -Report                 # HTML + JSON in Documents\pc_scanner
scan -Json                   # JSON only (ideal for integrations)
scan -Report -Pdf            # also generate a PDF (uses Microsoft Edge)
scan -Report -OpenReport     # open the HTML when done
scan -Report -OutDir "D:\reports"   # custom output folder
scan -VirusTotal -Report     # combine both: report with a VirusTotal column
```

It generates a **self-contained HTML report** (findings table color-coded by risk, summary, and
VirusTotal links) plus a **structured JSON** for integration into other systems. The PDF is
generated from the HTML using Microsoft Edge in headless mode. By default they are saved to
`Documents\pc_scanner\scan_<date>.{html,json,pdf}`.

### 🧹 Clean temp files (the `clean` command)

Besides the scanner, a `clean` command is installed that **deletes user temp files** (`%TEMP%`)
and system temp files (`C:\Windows\Temp`) and shows you **before vs. after performance** (free
disk, temp size, CPU and RAM):

```powershell
clean           # asks for confirmation before deleting
clean -Force    # deletes without asking
clean -DryRun   # SIMULATION: shows what it would delete, without deleting anything
```

Files in use are skipped automatically (nothing is force-closed).

> 🧪 **Dry-run mode (`-DryRun`):** lists exactly what would be deleted and how much space it would
> free, **without touching anything** (and without prompting for UAC). Great for reviewing before
> a real run, especially when cleaning someone else's PC.
>
> 📋 **Audit log:** every run (real or simulated) records what was deleted, what was skipped, and
> how much was freed in `%LOCALAPPDATA%\pc_scanner\logs\clean_<date>.log`. Change it with
> `-LogPath <path>`.

> 🔒 `clean` **requests administrator permission (UAC)** automatically so it can also clean
> `C:\Windows\Temp`. If you decline UAC, it still cleans your `%TEMP%`.

> ℹ️ Cleaning temp files frees **disk space**, it does not reduce CPU. The CPU/RAM values are
> shown only as a reference.

### 🔄 Update (the `update` command)

To pull the latest version published on GitHub without remembering the one-liner:

```powershell
update
```

It re-downloads all scripts to `%LOCALAPPDATA%\pc_scanner` and re-registers the commands.
Afterward, **open a new PowerShell window** to pick up the changes.

To remove the command from your profile:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
```

> 🟢 **"Hacker console" mode:** on startup it shows a Matrix-style rain, an ASCII banner, and an
> animated boot sequence, with system data appearing in a typewriter effect. Animations
> **disable themselves** when output is redirected to a file, or you can turn them off with `-NoAnim`.

> 💡 **Tip:** run PowerShell **as Administrator** so some checks (services, other users' tasks)
> are complete.

### Without installing (direct use)

If you'd rather not touch your profile, run it directly from the project folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\scan.ps1
```

Or from CMD / with the folder on your `PATH`, using the included wrapper:

```cmd
scan.cmd -Days 7
```

### Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `-Days <n>` | Age in days to consider an executable "recent" | `14` |
| `-Full` | Deep scan of the entire user profile | (off) |
| `-NoAnim` | Disable animations (Matrix intro, typing effect) | (off) |
| `-VirusTotal` | Check suspicious binary hashes against VirusTotal | (off) |
| `-VTApiKey <key>` | VirusTotal API key (or use `$env:VT_API_KEY`) | — |
| `-VTMax <n>` | Cap on VirusTotal queries per scan | `20` |
| `-Report` | Generate HTML + JSON report | (off) |
| `-Json` | Generate JSON report only | (off) |
| `-Pdf` | Also generate PDF (requires Microsoft Edge) | (off) |
| `-OutDir <path>` | Output folder for reports | `Documents\pc_scanner` |
| `-OpenReport` | Open the HTML when done | (off) |

### Exit codes

Useful if you integrate it into another script or task:

| Code | Meaning |
| --- | --- |
| `0` | No risk findings |
| `1` | **Medium** risk findings present |
| `2` | **High** risk findings present |

---

## 📋 Sample output

```
>> Suspicious scheduled tasks
  [High ] \Microsoft\Windows\Foo\Bar
          Path  : powershell.exe -enc SQBFAFgA...
          Reason: PowerShell with Base64-encoded command

>> Recent executables in risky areas (last 7 days)
  [High ] invoice.pdf.exe
          Path  : C:\Users\...\Downloads\invoice.pdf.exe
          Reason: Misleading DOUBLE EXTENSION; unsigned binary in download zone (NotSigned)
```

---

## 🛠️ Troubleshooting

**`scan` is not recognized** or the profile says *"running scripts is disabled"*: that's the
Windows execution policy (it ships `Restricted` by default). The installer already adjusts it,
but if you need to do it by hand (no admin required):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then **open a new terminal** and try `scan` again. If your profile lives inside OneDrive and it
still won't load, unblock it: `Unblock-File $PROFILE`.

## ⚠️ Limitations

- It is a **heuristic detector**, not an antivirus: it can have false positives and does **not**
  detect all malware.
- Online reputation is **optional** (`-VirusTotal`) and requires an API key; without it, the scan
  stays 100% local.
- It does not modify, move, or delete anything. You decide what to do with each finding.

## 🤝 Contributing

Issues and PRs welcome. Future ideas: advanced persistence detection (DLL/COM hijacking, WMI
subscriptions), certificate-chain validation, parallel scanning, a Linux/macOS version in Bash.

## 📄 License

[MIT](LICENSE) © Rodrigo Soria
