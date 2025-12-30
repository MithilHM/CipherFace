#!/bin/bash
# Homomorphic Face Encryption - Startup Script (macOS/Linux)
# Run this script to start the application with one command

set -e

echo "============================================="
echo "  Homomorphic Face Encryption - Startup"
echo "============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if Docker is running
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[ERROR] Docker is not installed!${NC}"
    echo -e "${YELLOW}Please install Docker from https://docker.com${NC}"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}[ERROR] Docker is not running!${NC}"
    echo -e "${YELLOW}Please start Docker Desktop or the Docker daemon${NC}"
    exit 1
fi

echo -e "${GREEN}[OK] Docker is running${NC}"

# Check if Docker Compose is available
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
    echo -e "${GREEN}[OK] Docker Compose found${NC}"
elif command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    echo -e "${GREEN}[OK] Docker Compose (legacy) found${NC}"
else
    echo -e "${RED}[ERROR] Docker Compose is not available!${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Stopping any running containers...${NC}"
$COMPOSE_CMD down 2>/dev/null || true

echo ""
echo -e "${YELLOW}Building and starting all services...${NC}"
$COMPOSE_CMD up -d --build

if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR] Failed to start services!${NC}"
    echo -e "${YELLOW}Check the logs with: $COMPOSE_CMD logs${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Waiting for services to be ready...${NC}"

# Wait for backend to be healthy
max_attempts=30
attempt=0
backend_ready=false

while [ $attempt -lt $max_attempts ] && [ "$backend_ready" = false ]; do
    sleep 2
    attempt=$((attempt + 1))
    
    if curl -s -f http://localhost:5000/api/health > /dev/null 2>&1; then
        backend_ready=true
        echo -e "${GREEN}[OK] Backend is ready!${NC}"
    else
        echo "  Waiting for backend... (attempt $attempt/$max_attempts)"
    fi
done

if [ "$backend_ready" = false ]; then
    echo -e "${YELLOW}[WARNING] Backend health check timed out. It may still be starting.${NC}"
    echo -e "${YELLOW}Check logs with: $COMPOSE_CMD logs app${NC}"
fi

# Check frontend
if curl -s -f http://localhost:5173 > /dev/null 2>&1; then
    echo -e "${GREEN}[OK] Frontend is ready!${NC}"
else
    echo -e "${YELLOW}[WARNING] Frontend may still be starting.${NC}"
fi

echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}  Application Started Successfully!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo -e "${CYAN}Frontend:   http://localhost:5173${NC}"
echo -e "${CYAN}Backend:    http://localhost:5000${NC}"
echo -e "${CYAN}API Health: http://localhost:5000/api/health${NC}"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo "  View logs:     $COMPOSE_CMD logs -f"
echo "  Stop:          $COMPOSE_CMD down"
echo "  Rebuild:       $COMPOSE_CMD up --build -d"
echo ""

# Open browser
read -p "Open browser now? (Y/n) " open_browser
if [ "$open_browser" != "n" ] && [ "$open_browser" != "N" ]; then
    # Detect OS and open browser
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "http://localhost:5173"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open "http://localhost:5173" 2>/dev/null || echo "Please open http://localhost:5173 in your browser"
    else
        echo "Please open http://localhost:5173 in your browser"
    fi
fi
