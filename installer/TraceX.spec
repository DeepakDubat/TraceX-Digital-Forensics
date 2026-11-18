# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None
ROOT_DIR = Path.cwd().resolve()

# ------------------------------------------------------------------------------
# BACKEND SUBSYSTEM ANALYSIS
# ------------------------------------------------------------------------------

backend_submodules = collect_submodules('backend')

backend_hidden_imports = [
    'uvicorn',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.http.h11_impl',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'fastapi',
    'starlette',
    'starlette.middleware',
    'starlette.middleware.cors',
    'starlette.middleware.errors',
    'starlette.middleware.exceptions',
    'starlette.staticfiles',
    'starlette.responses',
    'pydantic',
    'pydantic_core',
    'sqlite3',
    'pefile',
    'yara',
    'androguard',
    'androguard.core',
    'androguard.core.apk',
    'androguard.core.dex',
    'pypdf',
    'PIL',
    'PIL.Image',
    'docx',
    'openpyxl',
    'cryptography',
    'requests',
    'httpx',
    'email_validator',
    'fitz',
    'pymupdf',
    'tkinter',
    'tkinter.filedialog',
] + backend_submodules

backend_datas = []

# Bundle YARA rules
rules_dir = ROOT_DIR / 'rules'
if rules_dir.is_dir():
    backend_datas.append((str(rules_dir), 'rules'))

# Bundle production frontend if built
frontend_dist = ROOT_DIR / 'frontend' / 'dist'
if frontend_dist.is_dir() and (frontend_dist / 'index.html').exists():
    backend_datas.append((str(frontend_dist), 'frontend/dist'))

# Bundle tool manifest
tool_manifest = ROOT_DIR / 'installer' / 'tool_manifest.json'
if tool_manifest.is_file():
    backend_datas.append((str(tool_manifest), 'installer'))

# Collect androguard package data
backend_datas += collect_data_files('androguard')
backend_datas += collect_data_files('pymupdf')

app_icon = str(ROOT_DIR / 'installer' / 'installer_assets' / 'app_icon.ico')

# Backend Analysis
a_backend = Analysis(
    [str(ROOT_DIR / 'launcher.py')],
    pathex=[str(ROOT_DIR)],
    binaries=[],
    datas=backend_datas,
    hiddenimports=backend_hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        '_pre_rollback_backup', 'tests', 'unittest',
        'torch', 'tensorflow', 'transformers', 'scipy', 'sklearn',
        'matplotlib', 'pandas', 'numpy.testing', 'sympy', 'IPython',
        'dask', 'cupy', 'botocore', 'boto3', 'azure', 'tornado',
        'twisted', 'zmq', 'pygments', 'jedi', 'parso', 'wcwidth',
        'sphinx', 'pytest', 'pip', 'setuptools', 'wheel'
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz_backend = PYZ(a_backend.pure, a_backend.zipped_data, cipher=block_cipher)

exe_backend = EXE(
    pyz_backend,
    a_backend.scripts,
    [],
    exclude_binaries=True,
    name='TraceX-Backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False, # Hidden headless child process
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=app_icon if Path(app_icon).exists() else None,
)

# ------------------------------------------------------------------------------
# DESKTOP HOST SUBSYSTEM ANALYSIS
# ------------------------------------------------------------------------------

host_hidden_imports = [
    'webview',
    'clr_loader',
    'pythonnet',
]

host_datas = []
if Path(app_icon).exists():
    host_datas.append((app_icon, 'installer/installer_assets'))

a_host = Analysis(
    [str(ROOT_DIR / 'desktop' / 'tracex_app.py')],
    pathex=[str(ROOT_DIR)],
    binaries=[],
    datas=host_datas,
    hiddenimports=host_hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tests', 'tkinter', 'unittest', 'pytest',
        'torch', 'tensorflow', 'transformers', 'scipy', 'sklearn'
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz_host = PYZ(a_host.pure, a_host.zipped_data, cipher=block_cipher)

exe_host = EXE(
    pyz_host,
    a_host.scripts,
    [],
    exclude_binaries=True,
    name='TraceX',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False, # Native desktop window — NO console window!
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=app_icon if Path(app_icon).exists() else None,
)

# ------------------------------------------------------------------------------
# UNIFIED RELEASE COLLECTION
# ------------------------------------------------------------------------------

coll = COLLECT(
    exe_host,
    a_host.binaries,
    a_host.zipfiles,
    a_host.datas,
    exe_backend,
    a_backend.binaries,
    a_backend.zipfiles,
    a_backend.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='TraceX',
)

