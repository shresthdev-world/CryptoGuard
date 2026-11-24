# -*- mode: python ; coding: utf-8 -*-
# Build this SPEC on Windows. This is a real native Tkinter application.
# Data assets are bundled beside the Python modules in PyInstaller's internal folder.
a = Analysis(
    ['Start-Detector.pyw'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('pools.json', '.'),
        ('app-icon.png', '.'),
        ('tools/windows.ps1', 'tools'),
    ],
    hiddenimports=['psutil'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name='CryptoGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon='app-icon.ico',
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='CryptoGuard')
