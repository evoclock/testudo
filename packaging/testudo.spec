# PyInstaller spec for the testudo-bridge standalone binary.
#
# Bundles `testudo serve` as a self-contained single-file executable for use
# in packaged Electron distributions. Run from the repo root after installing
# the [serve] and [dist] extras:
#
#   uv pip install -e ".[serve,dist]"
#   pyinstaller testudo.spec
#
# Output: dist/testudo-bridge
#
# Verify before wiring into electron-builder:
#   ./dist/testudo-bridge serve --help
#   ./dist/testudo-bridge serve --port 8001   # check token appears on stderr

from pathlib import Path

block_cipher = None

a = Analysis(
    [str(Path("src") / "testudo" / "cli.py")],
    pathex=[str(Path("src"))],
    binaries=[],
    datas=[],
    hiddenimports=[
        "uvicorn",
        "uvicorn.lifespan.on",
        "fastapi",
        "anyio",
        "anyio._backends._asyncio",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="testudo-bridge",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
