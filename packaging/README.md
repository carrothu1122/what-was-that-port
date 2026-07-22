# Packaging Notes

This project is moving toward two install targets:

- Linux: `.deb` package first, then optional apt repository.
- Windows: PyInstaller executable first, then an Inno Setup or NSIS installer.

The application now has three stable Python entry points:

- `what-was-that-port`: GUI.
- `what-was-that-port-cli`: command-line scanner.
- `what-was-that-port-worker`: privileged worker used by the GUI for TCP SYN, TCP FIN, and UDP scans.

## Linux target

The Linux package should install:

- GUI entry point.
- CLI entry point.
- privileged worker entry point.
- desktop file under `/usr/share/applications/`.
- icon assets under `/usr/share/icons/`.
- polkit policy under `/usr/share/polkit-1/actions/`.

Runtime expectations:

- TCP Connect and ICMP paths run without elevation.
- TCP SYN, TCP FIN, and UDP are executed by the privileged worker.
- `pkexec` must be available for GUI-triggered privileged scans.

Build the lightweight local `.deb` package with:

```bash
bash packaging/linux/build-deb.sh
```

The output is written to `dist/`.

## Windows target

The Windows package should install:

- GUI executable.
- CLI executable.
- worker executable.
- Start menu shortcut.
- optional desktop shortcut.

Runtime expectations:

- TCP Connect runs without elevation.
- TCP SYN, TCP FIN, and UDP trigger UAC for the worker only.
- Npcap should be installed for Scapy raw packet support.

## Current packaging status

The repository has `pyproject.toml` and installable console entry points. Full
`.deb` scripts, PyInstaller specs, and Windows installer scripts are the next
packaging layer. Linux desktop and polkit template files are under
`packaging/linux/`.
