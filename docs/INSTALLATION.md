# TraceX Development & Installation Guide

This guide details the prerequisites, automated setup, and development procedures for running and testing TraceX from source on Windows, Linux, and macOS.

---

## 1. Quick Start: 1-Click Automated Setup (Recommended)

TraceX includes fully automated installation and launch scripts that configure the complete environment in two simple steps:

### Step 1: Automated Installation (Run Once)
Clone the repository and run the automated installer:
* **Windows:** Double-click `install.bat` (or execute `.\install.bat` in PowerShell / Command Prompt).
* **Linux / macOS:** Run `./install.sh` in terminal.

The installer automatically:
1. Detects Python 3.10+ / 3.11 and sets up a virtual environment.
2. Installs all required backend Python dependencies from `requirements.txt`.
3. Installs frontend npm packages and compiles the high-performance production bundle (`frontend/dist`).
4. Generates the default `.env` configuration file from `.env.example`.

### Step 2: Instant Application Launch
* **Windows:** Double-click `run_tracex.bat` (or `start.bat`).
* **Linux / macOS:** Run `./run_tracex.sh` (or `./start.sh`).

TraceX will initialize the FastAPI backend engine and automatically open your default browser directly to:
```
http://127.0.0.1:8000
```

---

## 2. Prerequisites (For Manual / Custom Setup)

Ensure the following tools are installed on your workstation:

* **Operating System:** Windows 10/11 x64 (Linux / Kali Linux / macOS also supported)
* **Python:** Python 3.10 or 3.11 x64 (`python --version` or `py -3.11 --version`)
* **Node.js:** Node.js v18+ or v20+ with `npm` (`node -v`, `npm -v`)
* **Java Runtime:** OpenJDK 17 or 21 (required for running JADX and Apktool)
* **Git:** Version control (`git --version`)

---

## 3. Manual Repository Clone & Environment Setup

```powershell
# Clone the repository
git clone https://github.com/DeepakDubat/TraceX-Digital-Forensics.git
cd TraceX-Digital-Forensics

# Copy the environment template
copy .env.example .env
```

---

## 4. Manual Backend Setup (FastAPI & Python)

```powershell
# Create a Python virtual environment (optional but recommended)
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install backend dependencies
py -3.11 -m pip install --upgrade pip
py -3.11 -m pip install -r requirements.txt
```

---

## 5. Manual Frontend Setup (React 19 & Vite)

```powershell
# Navigate to the frontend directory
cd frontend

# Install Node dependencies
npm.cmd install

# Compile production bundle
npm.cmd run build

# Return to project root
cd ..
```

---

## 6. Running the Development Workstation (Hot Reload Mode)

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
