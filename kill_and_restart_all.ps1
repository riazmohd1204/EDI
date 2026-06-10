# Kill All Processes and Restart Frontend and Backend
# This script kills processes on ports 3000, 5173, and 8000, then restarts both servers

$workspace = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Killing All Server Processes" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Kill processes on port 8000 (Backend)
Write-Host "Killing processes on port 8000 (Backend)..." -ForegroundColor Yellow
$backendProcs = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
if ($backendProcs) {
    foreach ($processId in $backendProcs) {
        try {
            Stop-Process -Id $processId -Force -ErrorAction Stop
            Write-Host "  ✓ Killed process PID: $processId" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Could not kill PID: $processId" -ForegroundColor Red
        }
    }
} else {
    Write-Host "  No processes found on port 8000" -ForegroundColor Gray
}

# Kill processes on port 3000 (Frontend - React default)
Write-Host "Killing processes on port 3000 (Frontend)..." -ForegroundColor Yellow
$frontendProcs3000 = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
if ($frontendProcs3000) {
    foreach ($processId in $frontendProcs3000) {
        try {
            Stop-Process -Id $processId -Force -ErrorAction Stop
            Write-Host "  ✓ Killed process PID: $processId" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Could not kill PID: $processId" -ForegroundColor Red
        }
    }
} else {
    Write-Host "  No processes found on port 3000" -ForegroundColor Gray
}

# Kill processes on port 5173 (Frontend - Vite default)
Write-Host "Killing processes on port 5173 (Frontend - Vite)..." -ForegroundColor Yellow
$frontendProcs5173 = Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
if ($frontendProcs5173) {
    foreach ($processId in $frontendProcs5173) {
        try {
            Stop-Process -Id $processId -Force -ErrorAction Stop
            Write-Host "  ✓ Killed process PID: $processId" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Could not kill PID: $processId" -ForegroundColor Red
        }
    }
} else {
    Write-Host "  No processes found on port 5173" -ForegroundColor Gray
}

# Also kill any Python processes that might be running uvicorn
Write-Host "Killing any remaining Python/uvicorn processes..." -ForegroundColor Yellow
$pythonProcs = Get-Process python* -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*uvicorn*" -or $_.CommandLine -like "*app.main*"
}
if ($pythonProcs) {
    foreach ($proc in $pythonProcs) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-Host "  ✓ Killed Python process PID: $($proc.Id)" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Could not kill PID: $($proc.Id)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "  No Python/uvicorn processes found" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Waiting 3 seconds for ports to release..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Starting Servers" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Start FastAPI Backend
Write-Host "Starting FastAPI Backend on port 8000..." -ForegroundColor Green
$backendPath = Join-Path $workspace "fastapi-backend"
if (Test-Path $backendPath) {
    $backendScript = @"
cd '$backendPath'
Write-Host '========================================' -ForegroundColor Cyan
Write-Host 'FastAPI Backend Server' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Cyan
Write-Host 'Backend URL: http://localhost:8000' -ForegroundColor Yellow
Write-Host 'API Docs:    http://localhost:8000/docs' -ForegroundColor Yellow
Write-Host 'Status:      http://localhost:8000/api/system/status' -ForegroundColor Yellow
Write-Host ''
py -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
"@
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $backendScript -WindowStyle Normal
    Write-Host "  ✓ Backend starting in new PowerShell window" -ForegroundColor Green
} else {
    Write-Host "  ✗ Backend path not found: $backendPath" -ForegroundColor Red
}

Start-Sleep -Seconds 3

# Start React Frontend
Write-Host "Starting React Frontend..." -ForegroundColor Green
$frontendPath = Join-Path $workspace "FigmaReactFrontend"
if (Test-Path $frontendPath) {
    $frontendScript = @"
cd '$frontendPath'
Write-Host '========================================' -ForegroundColor Cyan
Write-Host 'React Frontend Server' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Cyan
Write-Host 'Frontend URL: http://localhost:3000' -ForegroundColor Yellow
Write-Host ''
npm run dev
"@
    Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", $frontendScript -WindowStyle Normal
    Write-Host "  ✓ Frontend starting in new PowerShell window" -ForegroundColor Green
} else {
    Write-Host "  ✗ Frontend path not found: $frontendPath" -ForegroundColor Red
}

Start-Sleep -Seconds 5

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Server Status" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Backend:  http://localhost:8000" -ForegroundColor Yellow
Write-Host "Docs:     http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "Status:   http://localhost:8000/api/system/status" -ForegroundColor Yellow
Write-Host "Frontend: http://localhost:3000 (or check the frontend window)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Both servers started in separate PowerShell windows." -ForegroundColor Green
Write-Host "Check those windows for startup logs and any errors." -ForegroundColor Yellow
Write-Host ""
Write-Host "To test HANA document loading, wait for backend to start, then run:" -ForegroundColor Cyan
Write-Host "  cd fastapi-backend" -ForegroundColor Gray
Write-Host "  python check_documents.py" -ForegroundColor Gray
Write-Host ""
