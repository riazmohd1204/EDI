# Complete Kill, Rebuild Database, and Restart Script
# This script kills all processes, rebuilds the database, and restarts both frontend and backend

$ErrorActionPreference = "Continue"
$workspace = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Complete System Restart" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Kill all processes on ports 3000 and 8000
Write-Host "Step 1: Killing processes on ports 3000 and 8000..." -ForegroundColor Yellow

# Kill port 3000 (Frontend)
$port3000 = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
if ($port3000) {
    $port3000 | ForEach-Object {
        $pid = $_.OwningProcess
        Write-Host "  Killing process PID $pid on port 3000" -ForegroundColor White
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  ✓ Port 3000 cleared" -ForegroundColor Green
} else {
    Write-Host "  ✓ Port 3000 is free" -ForegroundColor Green
}

# Kill port 8000 (Backend)
$port8000 = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
if ($port8000) {
    $port8000 | ForEach-Object {
        $pid = $_.OwningProcess
        Write-Host "  Killing process PID $pid on port 8000" -ForegroundColor White
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  ✓ Port 8000 cleared" -ForegroundColor Green
} else {
    Write-Host "  ✓ Port 8000 is free" -ForegroundColor Green
}

# Also kill any Python processes that might be running uvicorn
Write-Host ""
Write-Host "Step 2: Checking for Python/uvicorn processes..." -ForegroundColor Yellow
$pythonProcs = Get-Process | Where-Object { 
    $_.ProcessName -like "*python*" -or $_.ProcessName -like "*py*" 
} -ErrorAction SilentlyContinue

if ($pythonProcs) {
    $pythonProcs | ForEach-Object {
        $procName = $_.ProcessName
        $procId = $_.Id
        Write-Host "  Stopping Python process PID $procId ($procName)" -ForegroundColor White
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  ✓ Python processes stopped" -ForegroundColor Green
} else {
    Write-Host "  ✓ No Python processes found" -ForegroundColor Green
}

# Also kill any Node processes that might be running the frontend
Write-Host ""
Write-Host "Step 3: Checking for Node/npm processes..." -ForegroundColor Yellow
$nodeProcs = Get-Process | Where-Object { 
    $_.ProcessName -like "*node*" 
} -ErrorAction SilentlyContinue

if ($nodeProcs) {
    $nodeProcs | ForEach-Object {
        $procName = $_.ProcessName
        $procId = $_.Id
        Write-Host "  Stopping Node process PID $procId ($procName)" -ForegroundColor White
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  ✓ Node processes stopped" -ForegroundColor Green
} else {
    Write-Host "  ✓ No Node processes found" -ForegroundColor Green
}

# Wait for ports to be released
Write-Host ""
Write-Host "Waiting 3 seconds for ports to release..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Step 4: Rebuild the database
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Rebuilding Database" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$backendPath = Join-Path $workspace "fastapi-backend"
Set-Location $backendPath

Write-Host "Running database build script..." -ForegroundColor Yellow
Write-Host ""

try {
    $buildResult = py build_database.py
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "⚠️  Database build may have encountered issues (exit code: $LASTEXITCODE)" -ForegroundColor Yellow
        Write-Host "   Continuing anyway..." -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Host "✓ Database rebuild complete" -ForegroundColor Green
    }
} catch {
    Write-Host ""
    Write-Host "⚠️  Error during database build: $_" -ForegroundColor Red
    Write-Host "   Continuing with restart..." -ForegroundColor Yellow
}

Write-Host ""
Start-Sleep -Seconds 2

# Step 5: Start Backend
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Starting Backend Server" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Starting FastAPI Backend on port 8000..." -ForegroundColor Yellow
Write-Host "  Backend URL: http://localhost:8000" -ForegroundColor Cyan
Write-Host "  API Docs:    http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host ""

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; Write-Host '=== FastAPI Backend Server ===' -ForegroundColor Cyan; Write-Host 'Backend: http://localhost:8000' -ForegroundColor Green; Write-Host 'API Docs: http://localhost:8000/docs' -ForegroundColor Green; Write-Host ''; Write-Host 'Press Ctrl+C to stop' -ForegroundColor Yellow; Write-Host ''; py -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

Start-Sleep -Seconds 3

# Step 6: Start Frontend
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Starting Frontend Server" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$frontendPath = Join-Path $workspace "FigmaReactFrontend"
Write-Host "Starting React Frontend on port 3000..." -ForegroundColor Yellow
Write-Host "  Frontend URL: http://localhost:3000" -ForegroundColor Cyan
Write-Host ""

Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$frontendPath'; Write-Host '=== React Frontend Server ===' -ForegroundColor Cyan; Write-Host 'Frontend: http://localhost:3000' -ForegroundColor Green; Write-Host ''; Write-Host 'Press Ctrl+C to stop' -ForegroundColor Yellow; Write-Host ''; npm run dev"

Start-Sleep -Seconds 5

# Final status
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ✅ Restart Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Server Status:" -ForegroundColor Yellow
Write-Host "  Backend:  http://localhost:8000" -ForegroundColor White
Write-Host "  Docs:     http://localhost:8000/docs" -ForegroundColor White
Write-Host "  Frontend: http://localhost:3000" -ForegroundColor White
Write-Host ""
Write-Host "Both servers are running in separate PowerShell windows." -ForegroundColor Green
Write-Host "Check those windows for any errors or logs." -ForegroundColor Yellow
Write-Host ""

