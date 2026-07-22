# Windows Packaging Plan

Recommended first target:

1. Build two PyInstaller executables:
   - `what-was-that-port.exe` for the GUI.
   - `what-was-that-port-worker.exe` for the privileged worker.
2. Place both executables in the same install directory. The GUI automatically
   prefers a sibling `what-was-that-port-worker.exe` for UAC elevation.
3. Use Inno Setup or NSIS to create the installer.
4. Detect Npcap during installation or first advanced scan.

Advanced scans on Windows need:

- Administrator authorization through UAC.
- Npcap for Scapy packet send/receive support.

The GUI should remain unelevated. Only the worker executable should be launched
with UAC.

## Build

From a Windows shell with project dependencies installed:

```powershell
pip install pyinstaller
.\packaging\windows\build-windows.ps1
```

or:

```bat
packaging\windows\build-windows.bat
```

The executables are written to `dist\windows`.

## Installer

The Inno Setup template is `what-was-that-port.iss`. Build executables first,
then compile the `.iss` file with Inno Setup.
