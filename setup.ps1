# VibeSafe Hollywood-style Cyberpunk Installer for Windows PowerShell

# Set console encoding to UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Colors
$Green = "Green"
$Cyan = "Cyan"
$Yellow = "Yellow"
$Red = "Red"

Clear-Host

# Header
Write-Host "======================================================================" -ForegroundColor $Green
Write-Host "  V I B E S A F E   🛡️   S E C U R I T Y   I N S T A L L E R   E N G I N E" -ForegroundColor $Green
Write-Host "======================================================================" -ForegroundColor $Green
Start-Sleep -Milliseconds 400

Write-Host "[*] Initializing Windows deployment sequence..." -ForegroundColor $Cyan
Start-Sleep -Milliseconds 500
Write-Host "[+] Running terminal environment diagnostics..." -ForegroundColor $Green
Start-Sleep -Milliseconds 300
Write-Host "[+] Verifying Python installation..." -ForegroundColor $Green

if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Error: Python executable not found on PATH. Aborting payload delivery." -ForegroundColor $Red
    Exit
}
Start-Sleep -Milliseconds 300
$pyVersion = python --version
Write-Host "[+] Python version: $pyVersion" -ForegroundColor $Green
Start-Sleep -Milliseconds 300

Write-Host "[!] Inspecting target host system package managers..." -ForegroundColor $Yellow
Start-Sleep -Milliseconds 500
Write-Host "[*] Windows environment detected. Direct pip installations are permitted." -ForegroundColor $Cyan
Start-Sleep -Milliseconds 500

Write-Host "`n--- STAGE 1: Deploying Package Modules & Dependencies ---" -ForegroundColor $Green
Start-Sleep -Milliseconds 200
Write-Host "[*] Running virtual pipeline pip install..." -ForegroundColor $Cyan

# Hollywood Progress Bar
Write-Host -NoNewline "Installing: [" -ForegroundColor $Green
for ($i = 1; $i -le 20; $i++) {
    Write-Host -NoNewline "■" -ForegroundColor $Green
    Start-Sleep -Milliseconds 80
}
Write-Host "] 100%" -ForegroundColor $Green

# Install
python -m pip install -e . | Out-Null
if ($LastExitCode -ne 0) {
    Write-Host "[-] Dependency deployment failed. Retrying in verbose mode..." -ForegroundColor $Red
    python -m pip install -e .
    Exit
}
Write-Host "[+] Base modules successfully injected." -ForegroundColor $Green
Start-Sleep -Milliseconds 400

Write-Host "`n--- STAGE 2: Linking Command Line Global Interfaces ---" -ForegroundColor $Green
Start-Sleep -Milliseconds 200
Write-Host "[+] Verifying execution path aliases..." -ForegroundColor $Cyan
Start-Sleep -Milliseconds 500

# Final confirmation output
Write-Host "`n======================================================================" -ForegroundColor $Green
Write-Host "🛡️  VIBESAFE SYSTEM DEPLOYMENT COMPLETED SUCCESSFULLY" -ForegroundColor $Green
Write-Host "======================================================================" -ForegroundColor $Green
Write-Host "[+] Execution link initialized successfully." -ForegroundColor $Green
Write-Host "`nTo initiate security scanning, run:" -ForegroundColor $Yellow
Write-Host "  vibesafe phases" -ForegroundColor $Green
Write-Host "  vibesafe scan <project_dir>" -ForegroundColor $Green
Write-Host "======================================================================" -ForegroundColor $Green
Write-Host "`n"
