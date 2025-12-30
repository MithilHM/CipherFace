---
description: Deploy the Homomorphic Face Encryption application to Railway (No Credit Card Required)
---

# Deploy to Railway (FREE - No Credit Card)

## ⚡ Quick Facts
- **Cost:** FREE ($5/month credit, no credit card needed)
- **Time:** ~15 minutes
- **Difficulty:** Easy
- **Services:** Backend, Frontend, PostgreSQL, Redis all included

---

## 📋 Prerequisites

1. **GitHub Account** (free)
2. **Railway Account** (free, sign up with GitHub)
3. **Your code pushed to GitHub**

---

## 🚀 Deployment Steps

### Step 1: Push Code to GitHub

```powershell
# Navigate to project
cd "c:\Users\Mithil H M\Downloads\Homomorphic-face-encyption"

# Initialize git (if not already)
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit for Railway deployment"

# Create GitHub repo and push
# (Create repo at github.com first, then:)
git remote add origin https://github.com/YOUR_USERNAME/homomorphic-face-encryption.git
git branch -M main
git push -u origin main
```

### Step 2: Sign Up for Railway

1. Go to https://railway.app
2. Click "Login" → "Login with GitHub"
3. Authorize Railway to access your GitHub

**✅ You now have $5 free credit per month!**

---

### Step 3: Create New Project

1. **Click "New Project"**
2. **Select "Deploy from GitHub repo"**
3. **Choose your repository:** `homomorphic-face-encryption`
4. Railway will detect your Docker setup automatically

---

### Step 4: Add Database Services

#### Add PostgreSQL:
1. Click **"+ New"** → **"Database"** → **"Add PostgreSQL"**
2. Railway provisions it automatically
3. Note the connection details (auto-configured)

#### Add Redis:
1. Click **"+ New"** → **"Database"** → **"Add Redis"**
2. Railway provisions it automatically
3. Note the connection details (auto-configured)

---

### Step 5: Configure Environment Variables

Click on your **app service** → **"Variables"** tab → Add these:

```env
# Database (Railway auto-provides these, but verify)
DATABASE_URL=${{Postgres.DATABASE_URL}}
DB_HOST=${{Postgres.PGHOST}}
DB_PORT=${{Postgres.PGPORT}}
DB_USER=${{Postgres.PGUSER}}
DB_PASSWORD=${{Postgres.PGPASSWORD}}
DB_NAME=${{Postgres.PGDATABASE}}

# Redis
REDIS_URL=${{Redis.REDIS_URL}}

# App Config
SECRET_KEY=your-secret-key-here-change-this
JWT_SECRET=your-jwt-secret-here-change-this
FLASK_ENV=production
FLASK_DEBUG=0

# CORS (update after deployment with your Railway URL)
CORS_ORIGINS=https://your-frontend-url.railway.app
```

---

### Step 6: Deploy Backend

Railway automatically deploys when you push to GitHub!

**Monitor deployment:**
- Click on your service
- Go to "Deployments" tab
- Watch the build logs

**Get your backend URL:**
- Go to "Settings" → "Domains"
- Click "Generate Domain"
- You'll get: `https://your-app-name.up.railway.app`

---

### Step 7: Deploy Frontend Separately

**Option A: Create separate service on Railway**
1. Click "+ New" → "GitHub Repo" → Select your repo again
2. In settings, set **Root Directory** to `frontend`
3. Railway detects Vite automatically
4. Add environment variable:
   ```env
   VITE_API_URL=https://your-backend-url.up.railway.app
   ```

**Option B: Use Vercel/Netlify for frontend (free)**
- Deploy frontend to Vercel (faster for React apps)
- Backend stays on Railway
- Update CORS_ORIGINS in backend to include Vercel URL

---

## 🔧 Deployment Files Needed

### Create `railway.toml` in project root:

```toml
[build]
builder = "dockerfile"
dockerfilePath = "Dockerfile.prod"

[deploy]
startCommand = "gunicorn --bind 0.0.0.0:$PORT --workers 4 'homomorphic_face_encryption.app:create_app()'"
healthcheckPath = "/api/health"
healthcheckTimeout = 300
restartPolicyType = "on_failure"
restartPolicyMaxRetries = 10
```

### Create `Dockerfile.prod` (if not exists):

```dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application
COPY src ./src

# Set environment
ENV PYTHONPATH=/app/src
ENV PORT=8080

# Expose port
EXPOSE 8080

# Run with gunicorn
CMD gunicorn --bind 0.0.0.0:$PORT --workers 4 'homomorphic_face_encryption.app:create_app()'
```

---

## ✅ Post-Deployment Checklist

1. **Test Backend API:**
   ```
   https://your-backend.up.railway.app/api/health
   ```

2. **Test Token Generation:**
   ```bash
   curl -X POST https://your-backend.up.railway.app/api/auth/token \
     -H "Content-Type: application/json" \
     -d '{"username":"testuser"}'
   ```

3. **Update CORS:**
   - Add frontend URL to `CORS_ORIGINS` in backend environment variables

4. **Test Frontend:**
   - Open your frontend URL
   - Try logging in
   - Verify all features work

---

## 💰 Cost Monitoring

**Free Tier: $5/month credit**

Estimated usage for this app:
- Backend: ~$2-3/month
- PostgreSQL: ~$1/month
- Redis: ~$0.5/month
- Frontend (if on Railway): ~$1/month

**Total: ~$4.50/month (within free tier!)**

To monitor:
- Dashboard → Click your project
- View "Usage" tab
- Set up billing alerts

---

## 🐛 Troubleshooting

### Build Fails
- Check "Deployments" → "View Logs"
- Ensure `requirements.txt` has all dependencies
- Verify `Dockerfile.prod` is correct

### Database Connection Error
- Verify environment variables are set
- Check `DATABASE_URL` format
- Ensure PostgreSQL service is running

### CORS Errors
- Update `CORS_ORIGINS` to include your frontend URL
- Restart backend service

### App Won't Start
- Check logs: Click service → "Deployments" → Latest deployment → "View Logs"
- Verify `PORT` environment variable is used correctly
- Check healthcheck is responding

---

## 📚 Useful Commands

### Railway CLI (Optional)

```powershell
# Install CLI
npm i -g @railway/cli

# Login
railway login

# Link to project
railway link

# View logs
railway logs

# Deploy
railway up
```

---

## 🎯 Alternative: Hybrid Deployment (Frontend on Vercel)

If Railway is slow or you want better frontend performance:

**Frontend: Vercel (Free)**
1. Push frontend to GitHub
2. Import to Vercel
3. Add env: `VITE_API_URL=https://your-backend.railway.app`
4. Deploy in 2 minutes

**Backend: Railway (Free)**
1. Deploy backend + database + Redis on Railway
2. Update CORS to allow Vercel domain

**Advantages:**
- Faster frontend (Vercel CDN)
- Railway only runs backend (more free credits last longer)
- Best of both platforms

---

## ✨ Summary

**Railway is your best option because:**
1. ✅ No credit card required
2. ✅ Hosts everything (backend + database + Redis)
3. ✅ Docker support (already configured)
4. ✅ Free $5/month credit
5. ✅ Easy deployment from GitHub
6. ✅ Automatic HTTPS
7. ✅ Simple to use

**Estimated Time to Deploy:** 15-20 minutes

---

**Last Updated:** 2025-12-29
**Status:** Ready for deployment
