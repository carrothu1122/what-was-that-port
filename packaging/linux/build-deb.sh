#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

VERSION="$(
  cd "$ROOT_DIR"
  python3 - <<'PY'
import tomllib
from pathlib import Path

data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
print(data["project"]["version"])
PY
)"

PACKAGE_DIR="$TMP_DIR/what-was-that-port_${VERSION}_all"
APP_DIR="$PACKAGE_DIR/usr/lib/what-was-that-port"
BIN_DIR="$PACKAGE_DIR/usr/bin"
DOC_DIR="$PACKAGE_DIR/usr/share/doc/what-was-that-port"
DESKTOP_DIR="$PACKAGE_DIR/usr/share/applications"
POLKIT_DIR="$PACKAGE_DIR/usr/share/polkit-1/actions"
DEBIAN_DIR="$PACKAGE_DIR/DEBIAN"

mkdir -p "$APP_DIR" "$BIN_DIR" "$DOC_DIR" "$DESKTOP_DIR" "$POLKIT_DIR" "$DEBIAN_DIR" "$DIST_DIR"

install -m 0644 "$ROOT_DIR"/*.py "$APP_DIR/"
install -m 0644 "$ROOT_DIR/README.md" "$DOC_DIR/"
install -m 0644 "$ROOT_DIR/requirements.txt" "$DOC_DIR/"
install -m 0755 "$ROOT_DIR/packaging/linux/bin/what-was-that-port" "$BIN_DIR/"
install -m 0755 "$ROOT_DIR/packaging/linux/bin/what-was-that-port-cli" "$BIN_DIR/"
install -m 0755 "$ROOT_DIR/packaging/linux/bin/what-was-that-port-worker" "$BIN_DIR/"
install -m 0644 "$ROOT_DIR/packaging/linux/what-was-that-port.desktop" "$DESKTOP_DIR/"
install -m 0644 "$ROOT_DIR/packaging/linux/org.whatwasthatport.policy" "$POLKIT_DIR/"

cat > "$DEBIAN_DIR/control" <<EOF
Package: what-was-that-port
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Maintainer: what-was-that-port contributors <maintainers@example.invalid>
Depends: python3 (>= 3.10), python3-pyside6.qtwidgets | python3-pyside6, python3-scapy, policykit-1
Description: GUI and CLI port scanner
 What Was That Port provides TCP Connect, TCP SYN, TCP FIN, UDP, ICMP,
 and service fingerprinting scans. The GUI stays unprivileged and launches
 a short-lived privileged worker for raw socket scan modes.
EOF

dpkg-deb --build --root-owner-group "$PACKAGE_DIR" "$DIST_DIR/what-was-that-port_${VERSION}_all.deb"
echo "$DIST_DIR/what-was-that-port_${VERSION}_all.deb"
