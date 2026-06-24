@echo off
REM Wrapper para ejecutar el scanner como 'scan' desde CMD o teniendo la carpeta en el PATH.
REM %~dp0 = carpeta de este archivo, asi siempre encuentra scan.ps1 sin importar desde donde se llame.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scan.ps1" %*
