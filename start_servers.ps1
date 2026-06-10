# Simple script to start servers with visible output
$ErrorActionPreference = "Continue"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Starting Servers" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$workspace = "c:\Users\mtupakula\OneDrive - Levi Strauss & Co\Desktop\leviEPIX-EDI-Agent"
$backendPath = Join-Path $workspace "fastapi-backend"
$frontendPath = Join-Path $workspace "FigmaReactFrontend"

# Start Backend
Write-Host "Starting FastAPI Backend..." -ForegroundColor Yellow
if (Test-Path $backendPath) {
    $backendCmd = "cd '$backendPath'; Write-Host 'FastAPI Backend Server' -ForegroundColor Green; Write-Host 'Backend URL: http://localhost:8000' -ForegroundColor Yellow; py -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $backendCmd
    Write-Host "  Backend window should have opened" -ForegroundColor Green
} else {
    Write-Host "  ERROR: Backend path not found: $backendPath" -ForegroundColor Red
}

Start-Sleep -Seconds 3

# Start Frontend
Write-Host "Starting React Frontend..." -ForegroundColor Yellow
if (Test-Path $frontendPath) {
    $frontendCmd = "cd '$frontendPath'; Write-Host 'React Frontend Server' -ForegroundColor Green; Write-Host 'Frontend URL: http://localhost:3000' -ForegroundColor Yellow; npm run dev"
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $frontendCmd
    Write-Host "  Frontend window should have opened" -ForegroundColor Green
} else {
    Write-Host "  ERROR: Frontend path not found: $frontendPath" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Servers Starting" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Backend:  http://localhost:8000" -ForegroundColor Yellow
Write-Host "Frontend: http://localhost:3000" -ForegroundColor Yellow
Write-Host ""
Write-Host "Check the PowerShell windows that opened for server logs." -ForegroundColor Cyan

