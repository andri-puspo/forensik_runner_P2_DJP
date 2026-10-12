@echo off
rem Memasang ikon Forensik Runner (folder + pintasan). Tambahkan opsi: PASANG_IKON.bat desktop  -> juga membuat pintasan di Desktop
cd /d "%~dp0"
if /i "%~1"=="desktop" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0PASANG_IKON.ps1" -Desktop
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0PASANG_IKON.ps1"
)
pause
