---
description: Complete guide to run the Homomorphic Face Encryption application
---

# Running the Homomorphic Face Encryption Application

## 🚀 One-Command Startup (Recommended)

### Windows (PowerShell)
```powershell
cd <project-directory>
.\start.ps1
```

### macOS / Linux (Bash)
```bash
cd <project-directory>
chmod +x start.sh
./start.sh
```

These scripts will:
1. Check Docker is running
2. Stop any existing containers
3. Build and start all services
4. Wait for health checks
5. Open the browser automatically

---

## 📋 Manual Startup

### Step 1: Stop Any Running Instances
```bash
docker compose down
```

### Step 2: Start All Services
```bash
docker compose up -d
```

### Step 3: Verify All Services Are Running
```bash
docker compose ps
```

You should see 4 containers running:
- `app` (Backend)
- `frontend` (Frontend)
- `postgres` (Database)
- `redis` (Cache)

### Step 4: Access the Application
Open your browser to: **http://localhost:5173**

---

## 📊 Service Details

### 1. Backend API (Flask)
- **Container:** `homomorphic-face-encyption-app-1`
- **Port:** 5000
- **URL:** http://localhost:5000
- **Health Check:** http://localhost:5000/api/health

### 2. Frontend (React + Vite)
- **Container:** `homomorphic-face-encyption-frontend-1`
- **Port:** 5173
- **URL:** http://localhost:5173

### 3. PostgreSQL Database
- **Container:** `homomorphic-face-encyption-postgres-1`
- **Port:** 5432
- **Database:** face_db
- **Username:** postgres
- **Password:** password

### 4. Redis Cache
- **Container:** `homomorphic-face-encyption-redis-1`
- **Port:** 6379

---

## 🧪 Testing Commands

### Test Backend Health
```powershell
(Invoke-WebRequest -Uri http://localhost:5000/api/health -UseBasicParsing).Content
```

### Get Authentication Token
```powershell
$body = @{username='TestUser'} | ConvertTo-Json
(Invoke-WebRequest -Uri http://localhost:5000/api/auth/token -Method POST -Body $body -ContentType 'application/json' -UseBasicParsing).Content
```

### Test Frontend
```powershell
(Invoke-WebRequest -Uri http://localhost:5173 -UseBasicParsing).StatusCode
```

---

## 📝 Management Commands

### View Live Logs (All Services)
```powershell
docker-compose logs -f
```

### View Specific Service Logs
```powershell
docker-compose logs -f app       # Backend only
docker-compose logs -f frontend  # Frontend only
docker-compose logs -f postgres  # Database only
docker-compose logs -f redis     # Cache only
```

### Restart Services
```powershell
docker-compose restart              # Restart all
docker-compose restart app          # Restart backend only
docker-compose restart frontend     # Restart frontend only
```

### Stop All Services
```powershell
docker-compose down
```

### Rebuild and Start (After Code Changes)
```powershell
docker-compose down
docker-compose up --build -d
```

---

## 🎯 Using the Application

1. **Open Frontend:** Navigate to http://localhost:5173
2. **Login:** Enter a username (e.g., "TestUser") and click "Initialize Session"
3. **Grant Consent:** Complete the consent onboarding (DPDP Act 2023 compliance)
4. **Enroll Face:** Click "Enroll Identity" → Activate camera → Capture your face
5. **Verify Identity:** Click "Secure Auth" → Activate camera → Verify your face
6. **Privacy Settings:** View and manage consents in "Privacy Center"

---

## 🔧 Troubleshooting

### Service Not Starting
```powershell
# Check logs
docker-compose logs app

# Restart specific service
docker-compose restart app
```

### Port Already in Use
```powershell
# Find what's using the port (e.g., 5000)
netstat -ano | findstr :5000

# Kill the process (replace PID with actual process ID)
taskkill /PID <PID> /F

# Then restart
docker-compose up -d
```

### Frontend Can't Connect to Backend
```powershell
# Restart both frontend and backend
docker-compose restart app frontend
```

### Database Issues
```powershell
# Reset database (WARNING: Deletes all data)
docker-compose down -v
docker-compose up -d
```

---

## 📋 Key API Endpoints

- `GET /api/health` - Health check
- `POST /api/auth/token` - Get JWT token (body: `{username: "string"}`)
- `POST /api/register` - Register face embedding (requires JWT)
- `POST /api/verify` - Verify face (requires JWT)
- `GET /api/templates` - Get user's biometric templates (requires JWT)
- `POST /api/consent/grant` - Grant consent
- `GET /api/consent/verify/{user_id}/{purpose}` - Verify consent

---

## 🔒 Security Features

- **Encryption:** FHE-CKKS (128-bit security)
- **Authentication:** JWT with RS256
- **Compliance:** India DPDP Act 2023 + GDPR
- **Privacy:** Homomorphic encryption, no plaintext biometric storage
- **Consent:** Granular consent management with audit trails

---

## 🐛 Known Issues Fixed

1. **JWT Manager Not Initialized** - Fixed in `app.py` by adding `JWTManager(app)`
2. **Flask-Talisman Compatibility** - Removed deprecated `content_type_options` parameter
3. **Vite Proxy Configuration** - Updated to use Docker service names
4. **CORS Issues** - Added proper CORS origins in docker-compose.yml

---

## 💡 Quick Reference

### One Command to Rule Them All
```powershell
cd "c:\Users\Mithil H M\Downloads\Homomorphic-face-encyption" && docker-compose down && docker-compose up -d && Start-Process "http://localhost:5173"
```

This single command will:
1. Navigate to project directory
2. Stop any running containers
3. Start all services fresh
4. Open the frontend in your browser

---

**Last Updated:** 2025-12-29
**Status:** ✅ All systems operational
