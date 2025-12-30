# Homomorphic Face Encryption

A privacy-preserving facial recognition system that uses Fully Homomorphic Encryption (FHE) to protect user biometric data while enabling secure face verification operations.

## Features

- **Privacy-Preserving**: Uses homomorphic encryption to perform computations on encrypted data without decryption
- **Facial Recognition**: Integrates FaceNet and MTCNN for robust face detection and feature extraction
- **GDPR Compliant**: Built-in consent management and data deletion capabilities
- **Modular Architecture**: Separated concerns with crypto, biometric, API, database, and consent modules
- **Containerized**: Docker Compose setup with Flask API, PostgreSQL, and Redis

## Project Structure

```
src/homomorphic_face_encryption/
├── crypto/          # FHE operations
├── biometric/       # Face processing and recognition
├── api/            # Flask REST API
├── database/       # PostgreSQL ORM models
└── consent/        # GDPR compliance management
```

## Prerequisites

- **Docker** and **Docker Compose** (v2.0 or higher)
  - Windows: Install Docker Desktop
  - macOS: Install Docker Desktop
  - Linux: Install docker and docker-compose
- **Git**

## Quick Setup with Docker (Recommended)

### One-Command Startup

**Windows (PowerShell):**
```powershell
.\start.ps1
```

**macOS / Linux:**
```bash
chmod +x start.sh && ./start.sh
```

These scripts handle everything: checking Docker, building images, starting services, and opening your browser.

### Manual Docker Compose

```bash
# Clone the repository
git clone <repository-url>
cd homomorphic-face-encryption

# Build and run
docker compose up --build -d

# Access the application
# Frontend: http://localhost:5173
# Backend:  http://localhost:5000
```

## Manual Setup (Alternative)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd homomorphic-face-encryption
   ```

2. **Install Python 3.10+**
   - Download from python.org or use your preferred package manager

3. **Install Poetry**
   ```bash
   pip install poetry
   ```

4. **Install dependencies**
   ```bash
   poetry install
   ```

5. **Set up environment**
   ```bash
   cp .env.template .env
   # Edit .env with your configuration if needed
   ```

6. **Install system dependencies** (for homomorphic encryption)
   ```bash
   # On Ubuntu/Debian:
   sudo apt-get update && sudo apt-get install -y gcc g++ cmake libssl-dev libgomp1
   
   # On macOS:
   # Install Xcode command line tools: xcode-select --install
   # Install dependencies via Homebrew: brew install cmake openssl
   
   # On Windows:
   # Install Visual Studio Build Tools or use WSL2 with Ubuntu
   ```

7. **Set up external dependencies**
   - **OpenFHE**: This is a critical dependency for homomorphic encryption
     - For Linux/macOS: Install from source following instructions at https://github.com/openfheorg/openfhe-development
     - For Python bindings: Check https://github.com/openfheorg/openfhe-python

8. **Run the application**
   ```bash
   poetry run python -m homomorphic_face_encryption.app
   ```

## API Endpoints

- `GET /api/health` - Health check
- `POST /api/register` - Register face embedding (JWT required)
- `POST /api/verify` - Verify face against stored embeddings (JWT required)
- `POST /api/consent` - Manage user consent (JWT required)
- `POST /api/enroll` - Enroll encrypted face embedding (JWT required)
- `POST /api/authenticate` - Authenticate face (JWT required)

## Development

- **Pre-commit hooks**: Automatically installed for code quality
- **Testing**: Run tests with `poetry run pytest`
- **Linting**: Code formatted with Black, linted with Flake8, type-checked with MyPy

## Dependencies

- Python 3.10+
- Poetry for dependency management
- Flask for API
- SQLAlchemy for ORM
- PostgreSQL with pgcrypto extension
- Redis for session management
- OpenFHE for homomorphic encryption (critical dependency)
- FaceNet and MTCNN for facial recognition

## Troubleshooting

1. **OpenFHE Installation Issues**:
   - This is the most common issue when running manually
   - The Docker setup handles this automatically
   - For manual setup, ensure OpenFHE C++ library is properly installed
   - Verify Python bindings are correctly configured

2. **CUDA/GPU Issues**:
   - The system works with CPU-only if CUDA is not available
   - FaceNet/MTCNN will automatically use CPU if CUDA is not available

3. **Database Connection Issues**:
   - Ensure PostgreSQL is running and accessible
   - Check environment variables in `.env` file
   - Verify pgcrypto extension is enabled

4. **Docker Build Issues**:
   - Ensure Docker has sufficient memory allocated (at least 4GB)
   - Check that build cache isn't causing issues (`docker system prune`)

## License

[License information]