# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files, collect_dynamic_libs

block_cipher = None

# Root directory of the repository
ROOT_DIR = Path.cwd().resolve()

# Collect all backend submodules dynamically
backend_submodules = collect_submodules('backend')

hidden_imports = [
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
] + backend_submodules

# Collect static data files
datas = []

# Bundle YARA rules
rules_dir = ROOT_DIR / 'rules'
if rules_dir.is_dir():
    datas.append((str(rules_dir), 'rules'))

# Bundle production frontend if built
frontend_dist = ROOT_DIR / 'frontend' / 'dist'
if frontend_dist.is_dir() and (frontend_dist / 'index.html').exists():
    datas.append((str(frontend_dist), 'frontend/dist'))

# Bundle tool manifest
tool_manifest = ROOT_DIR / 'installer' / 'tool_manifest.json'
if tool_manifest.is_file():
    datas.append((str(tool_manifest), 'installer'))

# Collect androguard and yara package data if needed
datas += collect_data_files('androguard')

a = Analysis(
    [str(ROOT_DIR / 'launcher.py')],
    pathex=[str(ROOT_DIR)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        '_pre_rollback_backup', 'tests', 'tkinter', 'unittest',
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

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ForensicsWorkbench',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True, # Console enabled for visibility, diagnostic logs, and clean terminal shutdown
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT_DIR / 'installer' / 'installer_assets' / 'app_icon.ico') if (ROOT_DIR / 'installer' / 'installer_assets' / 'app_icon.ico').exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='ForensicsWorkbench',
)
