# TraceX Development & Installation Guide

This guide details the prerequisites, environment setup, and development procedures for running and testing TraceX from source on Windows.

---

## 1. Prerequisites

Ensure the following tools are installed on your workstation:

* **Operating System:** Windows 10/11 x64
* **Python:** Python 3.11 x64 (`python --version` or `py -3.11 --version`)
* **Node.js:** Node.js v18+ or v20+ with `npm` (`node -v`, `npm -v`)
* **Java Runtime:** OpenJDK 17 or 21 (required for running JADX and Apktool)
* **Git:** Version control (`git --version`)

---

## 2. Repository Clone & Environment Setup

```powershell
# Clone the repository
git clone https://github.com/DeepakDubat/TraceX-Digital-Forensics.git
cd TraceX-Digital-Forensics

# Copy the environment template
copy .env.example .env
```

---

## 3. Backend Setup (FastAPI & Python 3.11)

```powershell
# Create a Python virtual environment (optional but recommended)
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install backend dependencies
py -3.11 -m pip install --upgrade pip
py -3.11 -m pip install -r backend/requirements.txt
```

---

## 4. Frontend Setup (React 19 & Vite)

```powershell
# Navigate to the frontend directory
cd frontend

# Install Node dependencies
npm.cmd install

# Return to project root
cd ..
```

---

## 5. Running the Development Workstation

You can start the frontend and backend servers together or independently:

### Option A: Complete Development Server
```powershell
# Run the pre-configured workstation starter
.\start_workbench.ps1
```
* **Frontend UI:** Available at `http://127.0.0.1:5173`
* **FastAPI Backend:** Available at `http://127.0.0.1:8000`
* **API Documentation (OpenAPI / Swagger):** Available at `http://127.0.0.1:8000/docs`

### Option B: Independent Manual Execution
```powershell
# Terminal 1: Backend API
py -3.11 run_backend.py

# Terminal 2: Frontend Vite Server
cd frontend
npm.cmd run dev
```

---

## 6. Running Automated Tests

TraceX maintains extensive automated verification suites covering security boundaries, forensic extraction, and report validation:

```powershell
# Run 200 MB upload limit and boundary tests
py -3.11 -m pytest tests/test_upload_size_limit_200mb.py -v

# Run IP Details intelligence and containment tests
py -3.11 -m pytest tests/test_ip_report_access_and_network_mode_sync.py -v

# Run full forensic regression suite
py -3.11 -m pytest tests/test_marriage_invite_ip_details.py tests/test_ip_details_feature.py -v

# Run API security and authentication tests
py -3.11 -m pytest tests/test_api_security_auth.py -v
```

---

## 7. Packaging & Desktop Release Builds

To compile the standalone desktop distribution:

```powershell
# Build the production frontend assets
cd frontend
npm.cmd run build
cd ..

# Build Windows installer and portable edition (requires Inno Setup 6)
powershell -ExecutionPolicy Bypass -File installer/build_release.ps1 -SkipTests
```
The compiled binaries will be output to `dist/`:
* `dist/TraceX-Setup.exe` (Windows Inno Setup Installer)
* `dist/TraceX-Portable.zip` (Isolated portable distribution)
