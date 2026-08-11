# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ["aegisscan_app.py"],
    pathex=["."],
    binaries=[],
    datas=[
        ("src/aegisscan_rules.yml", "src"),
    ],
    hiddenimports=[
        "google.genai",
        "github",
        "pydantic",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AegisScan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=True, name="AegisScan")
app = BUNDLE(
    coll,
    name="AegisScan.app",
    icon="assets/AegisScan.icns",
    bundle_identifier="com.aegisscan.desktop",
    info_plist={
        "CFBundleDisplayName": "AegisScan",
        "CFBundleShortVersionString": "0.2.1",
        "CFBundleVersion": "4",
        "LSMinimumSystemVersion": "12.0",
        "NSHighResolutionCapable": True,
    },
)
