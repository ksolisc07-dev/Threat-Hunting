<#
.SYNOPSIS
  Instala (o desinstala) el agente de Threat Hunting en Windows como tarea
  programada que arranca con el sistema y corre como SYSTEM.

.EXAMPLE
  # PowerShell como Administrador, desde la carpeta del repositorio:
  powershell -ExecutionPolicy Bypass -File .\agent\install_windows.ps1 -Server http://192.168.1.50:8000 -EnrollKey "mi-clave"

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\agent\install_windows.ps1 -Uninstall
#>
param(
    [string]$Server,
    [string]$EnrollKey,
    [int]$Interval = 60,
    [string]$InstallDir = "$env:ProgramData\ThreatHuntingAgent",
    [string]$Python = "",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$TaskName = "ThreatHuntingAgent"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Ejecuta este script en una consola de PowerShell abierta como Administrador."
}

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    Write-Host "Agente desinstalado." -ForegroundColor Green
    return
}

if (-not $Server -or -not $EnrollKey) { throw "Indica -Server y -EnrollKey." }

# --- Python --------------------------------------------------------------
if (-not $Python) {
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike "*WindowsApps*") { $Python = $cmd.Source }
    else {
        $cmd = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($cmd) { $Python = (& $cmd.Source -3 -c "import sys; print(sys.executable)").Trim() }
    }
}
if (-not $Python -or -not (Test-Path $Python)) {
    throw "No se encontró Python 3. Instálalo desde python.org marcando 'Install for all users' y 'Add python.exe to PATH', o pasa -Python C:\ruta\python.exe"
}
if ($Python -like "$env:USERPROFILE*") {
    Write-Warning "Python está instalado solo para tu usuario ($Python). La cuenta SYSTEM podría no tener acceso: se recomienda 'Install for all users'."
}
Write-Host "Usando Python: $Python"

& $Python -m pip install --upgrade psutil
if ($LASTEXITCODE -ne 0) { throw "No se pudo instalar psutil." }

# --- Ficheros ------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Force (Join-Path $PSScriptRoot "th_agent.py") $InstallDir
# Solo Administradores y SYSTEM pueden leer el token del agente
icacls $InstallDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

$agent = Join-Path $InstallDir "th_agent.py"
$state = Join-Path $InstallDir "agent_state.json"
$logf  = Join-Path $InstallDir "agent.log"
$arguments = "`"$agent`" --server `"$Server`" --enroll-key `"$EnrollKey`" --interval $Interval --state-file `"$state`" --log-file `"$logf`""

# --- Tarea programada ----------------------------------------------------
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
$action    = New-ScheduledTaskAction -Execute $Python -Argument $arguments -WorkingDirectory $InstallDir
$trigger   = New-ScheduledTaskTrigger -AtStartup
$taskUser  = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
               -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
               -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $taskUser -Settings $settings `
    -Description "Agente de Threat Hunting" | Out-Null
Start-ScheduledTask -TaskName $TaskName

Start-Sleep -Seconds 8
Write-Host ""
Write-Host "Agente instalado en $InstallDir y en ejecución como SYSTEM." -ForegroundColor Green
Write-Host "Log: $logf"
if (Test-Path $logf) { Get-Content $logf -Tail 5 }
