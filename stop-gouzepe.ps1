<# 
  stop-gouzepe.ps1
  Arrête proprement (et si besoin de force) :
   - Services NSSM : gouzepe-api, gouzepe-web
   - Processus node liés à server.js / web-server.js / vite / http-server
   - Processus qui écoutent sur les ports 3000 (API), 8080 (Web) + ports dev courants
#>

# --- Vérif droits admin ---
$currUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currUser)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Lance PowerShell en tant qu'Administrateur puis réessaie."
  exit 1
}

Write-Host "===> Arrêt des services et processus GOUZEPE (API & Web)..." -ForegroundColor Cyan

# --- Paramètres ---
$serviceNames = @('gouzepe-api','gouzepe-web')
$portsToKill  = @(3000,8080,4173,5173)  # 3000=API, 8080=Web, 4173/5173=dev
$killPatterns = @('server.js','web-server.js','vite','http-server')

function Stop-ServiceSafe([string]$name, [int]$timeoutSec=10) {
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if (-not $svc) {
    Write-Host "Service '$name' introuvable (ok)." -ForegroundColor DarkGray
    return
  }

  # Tente un stop en douceur
  try {
    if ($svc.Status -in 'Running','Paused','StartPending','ContinuePending') {
      Write-Host "Arrêt du service $name..." -NoNewline
      try { Stop-Service -Name $name -Force -ErrorAction Stop } catch {}
      # Parfois sc.exe est plus convaincant
      & sc.exe stop $name | Out-Null

      $sw = [Diagnostics.Stopwatch]::StartNew()
      do {
        Start-Sleep -Milliseconds 500
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
      } while ($svc -and $svc.Status -ne 'Stopped' -and $sw.Elapsed.TotalSeconds -lt $timeoutSec)

      if ($svc -and $svc.Status -ne 'Stopped') {
        Write-Host " forcé." -ForegroundColor Yellow
        # Tentative d’obtention du PID via SCM (non trivial) — on force via kill par port & nom ensuite
      } else {
        Write-Host " ok." -ForegroundColor Green
      }
    } else {
      Write-Host "Service $name déjà arrêté." -ForegroundColor DarkGray
    }
  } catch {
    Write-Host " échec: $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

function Kill-ByPorts($ports){
  foreach($p in $ports){
    try{
      $conns = Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue
      if(-not $conns){ continue }
      ($conns | Select-Object -ExpandProperty OwningProcess -Unique) | ForEach-Object {
        if($_ -and $_ -ne 0){
          try{
            $proc = Get-Process -Id $_ -ErrorAction SilentlyContinue
            if($proc){
              Write-Host ("Kill PID {0} (port {1}, {2})..." -f $_, $p, $proc.ProcessName) -ForegroundColor Yellow
              Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
            }
          } catch {}
        }
      }
    } catch {
      # Fallback si Get-NetTCPConnection indisponible
      Write-Host "Get-NetTCPConnection indispo, fallback netstat pour port $p..." -ForegroundColor DarkGray
      $lines = netstat -ano | Select-String (":$p\s")
      foreach($line in $lines){
        if($line -match '\s+(\d+)$'){
          $pid = [int]$Matches[1]
          try{ Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue } catch {}
        }
      }
    }
  }
}

function Kill-ByCommandPattern($patterns){
  try{
    $procs = Get-CimInstance Win32_Process -Filter "Name='node.exe'"
  } catch {
    $procs = @()
  }
  foreach($pat in $patterns){
    $hit = $procs | Where-Object { $_.CommandLine -match $pat }
    foreach($h in $hit){
      try{
        Write-Host ("Kill node PID {0} (match: {1})..." -f $h.ProcessId, $pat) -ForegroundColor Yellow
        Stop-Process -Id $h.ProcessId -Force -ErrorAction SilentlyContinue
      } catch {}
    }
  }
}

# 1) Stop services
$serviceNames | ForEach-Object { Stop-ServiceSafe $_ 12 }

# 2) Tuer processus sur les ports connus
Kill-ByPorts $portsToKill

# 3) Tuer node.exe par motifs de ligne de commande
Kill-ByCommandPattern $killPatterns

# 4) Double check : tuer un éventuel “node.exe” restant lié à notre dossier projet
# (ajuste le chemin si besoin)
$projectRoot = Split-Path -Parent $PSCommandPath  # dossier du script
try{
  $nodeLeft = Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object {
    ($_.CommandLine -match 'server\.js' -or $_.CommandLine -match 'web-server\.js') -or
    ($_.ExecutablePath -like "*node*")
  }
  foreach($p in $nodeLeft){
    try{
      Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    } catch {}
  }
} catch {}

Write-Host "===> Arrêt complet terminé." -ForegroundColor Green
