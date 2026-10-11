#!/usr/bin/env bash
# Installs media_drop into ~/.local/share/media-drop (own virtualenv) and
# creates the `media-drop` command in ~/.local/bin.
#   curl -fsSL https://raw.githubusercontent.com/Emp5r0R/grimoires/main/anon-media-uploader/install.sh | bash
# Override with MEDIA_DROP_REF=<branch|tag>, MEDIA_DROP_HOME=<dir>, MEDIA_DROP_BIN=<dir>.
set -euo pipefail

REPO="${MEDIA_DROP_REPO:-Emp5r0R/grimoires}"
REF="${MEDIA_DROP_REF:-main}"
HOME_DIR="${MEDIA_DROP_HOME:-$HOME/.local/share/media-drop}"
BIN_DIR="${MEDIA_DROP_BIN:-$HOME/.local/bin}"

for cmd in python3 curl tar; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "error: $cmd is required" >&2; exit 1; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "[*] downloading $REPO@$REF"
curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$REF" | tar -xz -C "$tmp"
src="$(find "$tmp" -mindepth 2 -maxdepth 2 -type d -name anon-media-uploader | head -n1)"
[ -n "$src" ] || { echo "error: anon-media-uploader not found in $REPO@$REF" >&2; exit 1; }

mkdir -p "$HOME_DIR"
rm -rf "$HOME_DIR/app"
cp -R "$src" "$HOME_DIR/app"

echo "[*] installing python modules"
if python3 -m venv "$HOME_DIR/venv" >/dev/null 2>&1; then
  PY="$HOME_DIR/venv/bin/python"
  "$PY" -m pip install -q --upgrade pip >/dev/null 2>&1 || true
  "$PY" -m pip install -q -r "$HOME_DIR/app/requirements.txt"
else
  echo "[!] python3 venv unavailable, installing with --user"
  PY="$(command -v python3)"
  "$PY" -m pip install -q --user -r "$HOME_DIR/app/requirements.txt" \
    || "$PY" -m pip install -q --user --break-system-packages -r "$HOME_DIR/app/requirements.txt"
fi

mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/media-drop" <<LAUNCHER
#!/bin/sh
exec "$PY" "$HOME_DIR/app/media_drop.py" "\$@"
LAUNCHER
chmod +x "$BIN_DIR/media-drop"

echo "[+] installed: $BIN_DIR/media-drop"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "[!] add $BIN_DIR to your PATH, e.g.: echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc" ;;
esac
"$BIN_DIR/media-drop" --version
