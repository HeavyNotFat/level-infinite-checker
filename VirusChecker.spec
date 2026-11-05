# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['packaging/entrypoint.py'],
    pathex=['.'],
    binaries=[],
    datas=[('tools', 'tools')],
    hiddenimports=[
        'vcheck',
        'vcheck_gui',
        'vcheck_lib.iocs',
        'vcheck_lib.leveldb',
        'vcheck_lib.incident',
        'vcheck_lib.netintel',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='VirusChecker',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets/viruschecker.ico'],
)
