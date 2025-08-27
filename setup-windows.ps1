<#  GOUZEPE – Setup Windows (corrigé)
    - élévation admin auto
    - vérifie Node/npm
    - crée/complète api/.env (EFOOTBALL / Admin123 si absent)
    - npm install dans ./api si node_modules absent
    - installe NSSM si absent (fonction approuvée: Install-Nssm)
    - crée/MAJ services:
        • gouzepe-api  (node api\server.js)  port 3000
        • gouzepe-web  (node web-server.js)  port 8080
    - crée logs + rotation
    - ouvre le pare-feu (profil Privé) pour 3000 & 8080
    - affiche les URLs réseau
#>

# ───────────────────────────────────────────────
# Auto-élévation admin
# ───────────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Élévation en administrateur..." -ForegroundColor Yellow
  $psi = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
  $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"";
  $psi.Verb = "runas";
  [System.Diagnostics.Process]::Start($psi) | Out-Null
  exit
}

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ───────────────────────────────────────────────
# Variables chemins
# ───────────────────────────────────────────────
$root   = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$Api    = Join-Path $root 'api'
$WebDir = Join-Path $root 'web'
$EnvFile= Join-Path $Api  '.env'
$Logs   = Join-Path $root 'logs'
$LogApi = Join-Path $Logs 'api'
$LogWeb = Join-Path $Logs 'web'

New-Item -ItemType Directory -Force -Path $Api,$WebDir,$Logs,$LogApi,$LogWeb | Out-Null

# ───────────────────────────────────────────────
# Node / npm
# ───────────────────────────────────────────────
$node = (Get-Command node -ErrorAction Stop).Source
$npm  = (Get-Command npm  -ErrorAction Stop).Source
Write-Host "Node  : $node"
Write-Host "npm   : $npm"

# ───────────────────────────────────────────────
# .env (DB EFOOTBALL, pass Admin123, JWT 24h)
# ───────────────────────────────────────────────
if (-not (Test-Path $EnvFile)) {
  @"
DATABASE_URL=postgresql://postgres:Admin123@localhost:5432/EFOOTBALL
PORT=3000
JWT_SECRET=$(New-Guid)
"@ | Out-File -Encoding UTF8 -FilePath $EnvFile
  Write-Host "Créé $EnvFile"
} else {
  # assure PORT & JWT_SECRET
  $envTxt = Get-Content -Raw $EnvFile
  if ($envTxt -notmatch "(?m)^PORT=")        { Add-Content $EnvFile "`nPORT=3000" }
  if ($envTxt -notmatch "(?m)^JWT_SECRET=")  { Add-Content $EnvFile "`nJWT_SECRET=$(New-Guid)" }
  Write-Host ".env vérifié."
}

# ───────────────────────────────────────────────
# npm install (api) – contourne la policy (npm.ps1 bloqué) via cmd
# ───────────────────────────────────────────────
if (-not (Test-Path (Join-Path $Api 'node_modules'))) {
  Write-Host "Installation des dépendances API..." -ForegroundColor Cyan
  Push-Location $Api
  & cmd /c "npm install"
  Pop-Location
}

# ───────────────────────────────────────────────
# NSSM (Install-Nssm = verbe approuvé)
# ───────────────────────────────────────────────
function Install-Nssm {
  param([string]$TargetDir = (Join-Path $env:ProgramData 'nssm'))

  $nssmExe = Get-Command nssm -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue
  if ($nssmExe) { return $nssmExe }

  New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
  $zip = Join-Path $TargetDir 'nssm.zip'
  $url = 'https://nssm.cc/release/nssm-2.24.zip'
  Write-Host "Téléchargement NSSM..." -ForegroundColor Cyan
  try {
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
  } catch {
    # miroir GitHub si le site est indisponible
    $url2 = 'https://github.com/kohsuke/nssm/releases/download/nssm-2.24/nssm-2.24.zip'
    Invoke-WebRequest -Uri $url2 -OutFile $zip -UseBasicParsing
  }

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $TargetDir, $true)
  Remove-Item $zip -Force

  $arch = if ([Environment]::Is64BitOperatingSystem) { 'win64' } else { 'win32' }
  $exe  = Join-Path $TargetDir ("nssm-2.24\{0}\nssm.exe" -f $arch)
  if (-not (Test-Path $exe)) { throw "NSSM non trouvé après extraction." }

  # ajoute au PATH courant
  $env:PATH = "$([System.IO.Path]::GetDirectoryName($exe));$env:PATH"
  return $exe
}

$nssm = Install-Nssm
Write-Host "NSSM  : $nssm"

# wrapper pour appeler nssm sans erreur "Jeton inattendu 'install'"
function Invoke-Nssm {
  param([Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][string]$Service,
        [string[]]$Args)
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $nssm
  $psi.Arguments = @($Command, $Service) + ($Args | ForEach-Object { "`"$_`"" }) -join ' '
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  $p.WaitForExit()
  if ($p.ExitCode -ne 0) {
    Write-Host ($p.StandardError.ReadToEnd()) -ForegroundColor Red
    throw "nssm $Command $Service a échoué ($($p.ExitCode))"
  }
  return $p.StandardOutput.ReadToEnd()
}

# ───────────────────────────────────────────────
# Services
# ───────────────────────────────────────────────
$nodeExe = $node
$apiJs   = Join-Path $Api 'server.js'
$webJs   = Join-Path $root 'web-server.js'

if (-not (Test-Path $apiJs)) { throw "Fichier introuvable: $apiJs" }
if (-not (Test-Path $webJs)) { throw "Fichier introuvable: $webJs" }

function Register-GouzepeService {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$WorkingDir,
    [Parameter(Mandatory)][string]$ScriptPath,
    [Parameter(Mandatory)][string]$StdOut,
    [Parameter(Mandatory)][string]$StdErr
  )

  $exists = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($exists) {
    Write-Host "Service $Name existe → mise à jour…" -ForegroundColor Yellow
    Invoke-Nssm -Command 'set' -Service $Name -Args @('Application', $nodeExe)
    Invoke-Nssm -Command 'set' -Service $Name -Args @('AppParameters', "`"$ScriptPath`"")
    Invoke-Nssm -Command 'set' -Service $Name -Args @('AppDirectory', $WorkingDir)
  } else {
    Write-Host "Création du service $Name…" -ForegroundColor Cyan
    Invoke-Nssm -Command 'install' -Service $Name -Args @($nodeExe, "`"$ScriptPath`"")
    Invoke-Nssm -Command 'set'     -Service $Name -Args @('AppDirectory', $WorkingDir)
  }

  # journaux & rotation
  Invoke-Nssm -Command 'set' -Service $Name -Args @('AppStdout', $StdOut)
  Invoke-Nssm -Command 'set' -Service $Name -Args @('AppStderr', $StdErr)
  Invoke-Nssm -Command 'set' -Service $Name -Args @('AppRotateFiles', '1')
  Invoke-Nssm -Command 'set' -Service $Name -Args @('AppRotateOnline', '1')
  Invoke-Nssm -Command 'set' -Service $Name -Args @('AppRotateBytes', '10485760') # 10 MB
  Invoke-Nssm -Command 'set' -Service $Name -Args @('Start', 'SERVICE_AUTO_START')
  Invoke-Nssm -Command 'set' -Service $Name -Args @('AppStopMethodConsole', '5000')

  # redémarre proprement
  try { & $nssm stop  $Name | Out-Null } catch {}
  try { & $nssm start $Name | Out-Null } catch {}
}

Register-GouzepeService -Name 'gouzepe-api' -WorkingDir $Api  -ScriptPath $apiJs -StdOut (Join-Path $LogApi 'api.out.log') -StdErr (Join-Path $LogApi 'api.err.log')
Register-GouzepeService -Name 'gouzepe-web' -WorkingDir $root -ScriptPath $webJs -StdOut (Join-Path $LogWeb 'web.out.log') -StdErr (Join-Path $LogWeb 'web.err.log')

# ───────────────────────────────────────────────
# Pare-feu (profil privé)
# ───────────────────────────────────────────────
function Add-PortRule {
  param([int]$Port,[string]$Name)
  $exists = netsh advfirewall firewall show rule name="$Name" | Select-String -Quiet "$Name"
  if (-not $exists) {
    netsh advfirewall firewall add rule name="$Name" dir=in action=allow protocol=TCP localport=$Port profile=private | Out-Null
  }
}
Add-PortRule -Port 3000 -Name "gouzepe-api-3000"
Add-PortRule -Port 8080 -Name "gouzepe-web-8080"

# ───────────────────────────────────────────────
# Copie des pages vers ./web (si absent)
# ───────────────────────────────────────────────
$pages = @('login.html','accueil.html','Classement-general.html','Admin-Joueurs.html','Admin-Utilisateurs.html')
foreach($pg in $pages){
  $src = Join-Path $root $pg
  $dst = Join-Path $WebDir $pg
  if ((Test-Path $src) -and (-not (Test-Path $dst))) {
    Copy-Item -Path $src -Destination $dst -Force
  }
}

# ───────────────────────────────────────────────
# IP locale & URLs
# ───────────────────────────────────────────────
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -notmatch '^169\.254\.' -and $_.IPAddress -ne '127.0.0.1' } |
  Select-Object -ExpandProperty IPAddress -First 1)

Write-Host "`nTout est prêt ✅" -ForegroundColor Green
Write-Host "API :   http://$ip:3000/health"
Write-Host "WEB :   http://$ip:8080/ (redirige vers login.html)"
Write-Host "Pages :"
Write-Host "  - Accueil               http://$ip:8080/accueil.html"
Write-Host "  - Classement général    http://$ip:8080/Classement-general.html"
Write-Host "  - Admin joueurs         http://$ip:8080/Admin-Joueurs.html"
Write-Host "  - Admin utilisateurs    http://$ip:8080/Admin-Utilisateurs.html"
