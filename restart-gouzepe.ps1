# restart-gouzepe.ps1
$ErrorActionPreference = 'SilentlyContinue'

# 1) Stop (si tu as le script d'arrêt dans le même dossier)
$stop = Join-Path (Split-Path -Parent $PSCommandPath) 'stop-gouzepe.ps1'
if (Test-Path $stop) { & $stop }

# 2) Start services NSSM
$services = @('gouzepe-api','gouzepe-web')
foreach($s in $services){
  Write-Host "Start $s..." -ForegroundColor Cyan
  sc.exe start $s | Out-Null
  Start-Sleep -Seconds 1
}

# 3) Attente ouverture des ports
function Wait-Port($port, $timeoutSec=20){
  $sw=[Diagnostics.Stopwatch]::StartNew()
  do{
    try{
      $ok = (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction Stop) -ne $null
      if($ok){ return $true }
    }catch{}
    Start-Sleep -Milliseconds 500
  }while($sw.Elapsed.TotalSeconds -lt $timeoutSec)
  return $false
}

$apiOk = Wait-Port 3000 25
$webOk = Wait-Port 8080 25
if($apiOk){ Write-Host "API écoute sur 3000" -ForegroundColor Green } else { Write-Host "API KO" -ForegroundColor Yellow }
if($webOk){ Write-Host "Web écoute sur 8080" -ForegroundColor Green } else { Write-Host "Web KO" -ForegroundColor Yellow }

# 4) Ping /health et ouvrir la page login
try{
  $health = Invoke-RestMethod -Uri "http://localhost:3000/health" -TimeoutSec 5
  Write-Host "Health: $($health.ok) @ $($health.now)" -ForegroundColor DarkGray
}catch{}
Start-Process "http://localhost:8080/login.html"
