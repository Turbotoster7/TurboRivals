# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller recipe for the standalone launcher.

Build (from the repository root):
    .\\build.ps1                 # this, then the installer
    venv\\Scripts\\pyinstaller.exe TurboRivals.spec --noconfirm   # just this step

The result is dist/TurboRivals/ - a folder holding TurboRivals.exe next to
_internal/, with no console window and nothing else required on the target
machine: no Python, no repository, no openssl.

Deliberately a one-FOLDER build, not one file. A onefile exe unpacks ~30 MB
into %TEMP%\\_MEIxxxxx on every start and deletes it on exit; when something
still holds a file there, the bootloader reports "Failed to remove temporary
directory", which looks like a crash but is only failed cleanup. One folder
touches %TEMP% not at all and starts instantly. The folder ships through
installer/TurboRivals.iss - NOT as a zip: files extracted from a downloaded
archive carry Mark-of-the-Web, and .NET then refuses to load
pythonnet/runtime/Python.Runtime.dll, which pywebview needs.

What goes in and why:
  * launcher/web      - the interface; app.py looks for it next to itself, which
                       inside the bundle means the unpack directory.
  * proto-lab/*.py   - the Blaze server. The exe re-invokes itself behind
                       --run-server (see commands.build_command), so these have
                       to be importable modules, not loose scripts. They are
                       listed as hidden imports because nothing imports them at
                       module level in the launcher.
  * tools/hosts_switch.py - the hosts file block, shared with the console tool.
  * cryptography     - certificate generation, so the user needs no openssl.

Anything the program writes lives in %LOCALAPPDATA%\\TurboRivals (see
commands.py): the bundle itself is unpacked to a temp directory and wiped on
exit.
"""

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo,
    VarStruct, VSVersionInfo)

# One source of truth for the version: the VERSION file. It is bundled so the
# running launcher can show it, stamped into the exe's Windows version resource,
# and read again by installer/TurboRivals.iss for the setup file name.
APP_VERSION = open('VERSION', encoding='utf-8').read().strip()
_v = tuple(int(part) for part in (APP_VERSION.split('.') + ['0', '0', '0'])[:3]) + (0,)

version_resource = VSVersionInfo(
    ffi=FixedFileInfo(filevers=_v, prodvers=_v, mask=0x3F, flags=0x0,
                      OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
    kids=[
        StringFileInfo([StringTable('040904B0', [
            StringStruct('CompanyName', 'TurboRivals'),
            StringStruct('FileDescription', 'TurboRivals launcher for NFS Rivals'),
            StringStruct('FileVersion', APP_VERSION),
            StringStruct('InternalName', 'TurboRivals'),
            StringStruct('OriginalFilename', 'TurboRivals.exe'),
            StringStruct('ProductName', 'TurboRivals'),
            StringStruct('ProductVersion', APP_VERSION),
        ])]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])]),
    ],
)

a = Analysis(
    ['launcher/app.py'],
    pathex=['proto-lab', 'tools'],
    binaries=[],
    datas=[('launcher/web', 'web'), ('VERSION', '.')],
    hiddenimports=[
        # the server and everything it imports by bare name
        'tls_terminator', 'blaze', 'lobby', 'player_store', 'tcp_proxy',
        # career save id detection, shared by the server and commands.py
        'ea_identity',
        # certificate generation, called in-process by commands.make_cert
        'make_stub_cert',
        # the hosts file switcher, imported by commands.py
        'hosts_switch',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # the launcher used customtkinter before the move to pywebview; Pillow
        # came with it. Neither is referenced any more.
        'tkinter', 'customtkinter', 'PIL',
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,   # the payload goes next to the exe, not inside it
    name='TurboRivals',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,          # no console window, for the launcher and the server alike
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='launcher/web/icon.ico',
    version=version_resource,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='TurboRivals',     # -> dist/TurboRivals/{TurboRivals.exe,_internal/}
)
