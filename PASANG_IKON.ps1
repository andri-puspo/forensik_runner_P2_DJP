# Pasang ikon Forensik Runner: ikon folder (desktop.ini) + pintasan "Forensik Runner.lnk" -> JALANKAN.bat
param([switch]$Desktop)
$ErrorActionPreference = "Stop"
try {
  $dir = Split-Path -Parent $MyInvocation.MyCommand.Path
  $ico = Join-Path $dir "assets\forensik_runner.ico"
  if (-not (Test-Path $ico)) { throw "assets\forensik_runner.ico tidak ditemukan" }
  # 1. ikon folder
  $ini = Join-Path $dir "desktop.ini"
  if (Test-Path $ini) { attrib -h -s $ini | Out-Null }
  $txt = "[.ShellClassInfo]`r`nIconResource=assets\forensik_runner.ico,0`r`nIconFile=assets\forensik_runner.ico`r`nIconIndex=0`r`nInfoTip=Forensik Runner - APH4NC-Dit.P2-DJP-KEMENKEU`r`n"
  [System.IO.File]::WriteAllText($ini, $txt, [System.Text.Encoding]::Default)
  attrib +h +s $ini | Out-Null
  attrib +s $dir | Out-Null
  # 2. pintasan peluncur
  $ws = New-Object -ComObject WScript.Shell
  $targets = @((Join-Path $dir "Forensik Runner.lnk"))
  if ($Desktop) { $targets += (Join-Path ([Environment]::GetFolderPath("Desktop")) "Forensik Runner.lnk") }
  foreach ($t in $targets) {
    $l = $ws.CreateShortcut($t)
    $l.TargetPath = Join-Path $dir "JALANKAN.bat"
    $l.WorkingDirectory = $dir
    $l.IconLocation = "$ico,0"
    $l.Description = "Forensik Runner - APH4NC-Dit.P2-DJP-KEMENKEU"
    $l.Save()
  }
  Write-Host "Ikon terpasang. Tekan F5 di Explorer bila ikon folder belum berubah."
} catch { Write-Host ("Ikon tidak dapat dipasang: " + $_.Exception.Message); exit 1 }
