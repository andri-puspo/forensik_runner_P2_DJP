@echo off
rem Forensik Runner - peluncur. Otomatis meminta hak Administrator (UAC) bila belum; bila ditolak, tetap berjalan tanpa Administrator.
cd /d "%~dp0"
if not "%~1"=="" goto :mulai
fltmc >nul 2>&1 && goto :mulai
echo Meminta hak Administrator ^(klik "Yes" pada jendela UAC^)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 exit /b 0
echo UAC ditolak atau gagal - melanjutkan TANPA hak Administrator ^(sebagian data forensik dapat kosong^).
:mulai
cd /d "%~dp0"
if not exist "Forensik Runner.lnk" powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0PASANG_IKON.ps1" >nul 2>nul
where py >nul 2>nul && (set PY=py -3) || (set PY=python)
%PY% -c "import reportlab" >nul 2>nul || (
  echo Memasang reportlab ^(sekali saja, perlu internet^)...
  %PY% -m pip install reportlab
)
%PY% forensik_app.py %*
if errorlevel 1 pause
