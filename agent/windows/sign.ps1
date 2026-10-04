# Firma ejecutables con signtool (SHA-256 + sello de tiempo). Uso interno del workflow.
param(
    [Parameter(Mandatory)][string]$PfxPath,
    [Parameter(Mandatory)][string]$Password,
    [Parameter(Mandatory)][string[]]$Files
)
$ErrorActionPreference = "Stop"
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe |
    Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe no encontrado (Windows SDK)" }

foreach ($f in $Files) {
    $ok = $false
    foreach ($ts in "http://timestamp.digicert.com", "http://timestamp.sectigo.com") {
        & $signtool.FullName sign /f $PfxPath /p $Password /fd sha256 /tr $ts /td sha256 /d "Threat Hunting Agent" $f
        if ($LASTEXITCODE -eq 0) { $ok = $true; break }
        Write-Warning "Fallo con el servidor de sello de tiempo $ts; probando otro"
    }
    if (-not $ok) { throw "No se pudo firmar $f" }
    $sig = Get-AuthenticodeSignature $f
    if (-not $sig.SignerCertificate) { throw "$f no quedó firmado" }
    Write-Host "Firmado: $f -> $($sig.SignerCertificate.Subject) [estado en este equipo: $($sig.Status)]"
}
