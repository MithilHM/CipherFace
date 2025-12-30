# Homomorphic Face Encryption - Startup Script (Windows)
# Run this script to start the application with one command

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Homomorphic Face Encryption - Startup" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Check if Docker is running
try {
    $dockerVersion = docker --version
    Write-Host "[OK] Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Docker is not installed or not running!" -ForegroundColor Red
    Write-Host "Please install Docker Desktop from https://docker.com" -ForegroundColor Yellow
    exit 1
}

# Check if Docker Compose is available
try {
    $composeVersion = docker compose version
    Write-Host "[OK] Docker Compose found" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Docker Compose is not available!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Stopping any running containers..." -ForegroundColor Yellow
docker compose down 2>$null

Write-Host ""
Write-Host "Building and starting all services..." -ForegroundColor Yellow
docker compose up -d --build

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to start services!" -ForegroundColor Red
    Write-Host "Check the logs with: docker compose logs" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "Waiting for services to be ready..." -ForegroundColor Yellow

# Wait for backend to be healthy
$maxAttempts = 30
$attempt = 0
$backendReady = $false

while ($attempt -lt $maxAttempts -and -not $backendReady) {
    Start-Sleep -Seconds 2
    $attempt++
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:5000/api/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            $backendReady = $true
            Write-Host "[OK] Backend is ready!" -ForegroundColor Green
        }
    } catch {
        Write-Host "  Waiting for backend... (attempt $attempt/$maxAttempts)" -ForegroundColor Gray
    }
}

if (-not $backendReady) {
    Write-Host "[WARNING] Backend health check timed out. It may still be starting." -ForegroundColor Yellow
    Write-Host "Check logs with: docker compose logs app" -ForegroundColor Yellow
}

# Check frontend
try {
    $frontendResponse = Invoke-WebRequest -Uri "http://localhost:5173" -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
    if ($frontendResponse.StatusCode -eq 200) {
        Write-Host "[OK] Frontend is ready!" -ForegroundColor Green
    }
} catch {
    Write-Host "[WARNING] Frontend may still be starting." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "  Application Started Successfully!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Frontend:  http://localhost:5173" -ForegroundColor Cyan
Write-Host "Backend:   http://localhost:5000" -ForegroundColor Cyan
Write-Host "API Health: http://localhost:5000/api/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Yellow
Write-Host "  View logs:     docker compose logs -f"
Write-Host "  Stop:          docker compose down"
Write-Host "  Rebuild:       docker compose up --build -d"
Write-Host ""

# Open browser
$openBrowser = Read-Host "Open browser now? (Y/n)"
if ($openBrowser -ne "n" -and $openBrowser -ne "N") {
    Start-Process "http://localhost:5173"
}
