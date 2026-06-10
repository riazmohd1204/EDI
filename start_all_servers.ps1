# Start Both FastAPI Backend and React Frontend
# Get the workspace path dynamically (parent of this script)
$workspace = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== Starting EDI Assistant Servers ===" -ForegroundColor Cyan
Write-Host ""

# Kill any processes on ports 3000 and 8000
Write-Host "Clearing ports 3000 and 8000..." -ForegroundColor Yellow
Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

# Start FastAPI Backend
Write-Host "Starting FastAPI Backend on port 8000..." -ForegroundColor Green
$backendPath = Join-Path $workspace "fastapi-backend"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; Write-Host 'FastAPI Backend - http://localhost:8000' -ForegroundColor Cyan; Write-Host 'API Docs - http://localhost:8000/docs' -ForegroundColor Cyan; py -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

Start-Sleep -Seconds 3

# Start React Frontend
Write-Host "Starting React Frontend on port 3000..." -ForegroundColor Green
$frontendPath = Join-Path $workspace "FigmaReactFrontend"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$frontendPath'; Write-Host 'React Frontend - http://localhost:3000' -ForegroundColor Cyan; npm run dev"

Start-Sleep -Seconds 5

Write-Host ""
Write-Host "=== Server Status ===" -ForegroundColor Cyan
Write-Host "Backend:  http://localhost:8000" -ForegroundColor Yellow
Write-Host "Docs:     http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "Frontend: http://localhost:3000" -ForegroundColor Yellow
Write-Host ""
Write-Host "Both servers started in separate windows." -ForegroundColor Green
Write-Host "Check the PowerShell windows for any errors." -ForegroundColor Yellow

