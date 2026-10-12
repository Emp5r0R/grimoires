#!/usr/bin/env bash
# grimoire.sh - install, update, uninstall or run (without installing) the tools in this repo.
#
#   curl -fsSL https://raw.githubusercontent.com/Emp5r0R/grimoires/main/grimoire.sh | bash -s -- <command> <tool> [options]
#
# Commands
#   install   <tool> [--system | --dir DIR] [--bin DIR] [--ref REF] [--force]
#   update    <tool|all> [--system|--local] [--ref REF]
#   uninstall <tool|all> [--system|--local] [--purge]   (alias: remove)
#   run       <tool> [tool arguments...]    download -> run -> delete everything
#   list
#
# Install locations
#   local  (default)  ~/.local/share/grimoires/<tool>   command in ~/.local/bin
#   system (--system) /opt/grimoires/<tool>             command in /usr/local/bin (uses sudo)
#
# Environment: GRIMOIRE_REF (branch/tag, default main), GRIMOIRE_REPO (owner/repo).
set -euo pipefail

REPO="${GRIMOIRE_REPO:-Emp5r0R/grimoires}"
DEFAULT_REF="${GRIMOIRE_REF:-main}"
LOCAL_ROOT="${XDG_DATA_HOME:-$HOME/.local/share}/grimoires"
LOCAL_BIN="$HOME/.local/bin"
SYSTEM_ROOT="/opt/grimoires"
SYSTEM_BIN="/usr/local/bin"
LAUNCHER_TAG="grimoire launcher"

# ---------------------------------------------------------------------------
# tool registry:  name | folder | entry script | requirements file | needed commands | cache dir
# ---------------------------------------------------------------------------
TOOLS="media-drop email-guard"

tool_info() {
  case "$1" in
    media-drop | anon-media-uploader)
      echo "media-drop|anon-media-uploader|media_drop.py|requirements.txt|python3|${XDG_CACHE_HOME:-$HOME/.cache}/media-drop" ;;
    email-guard | github-email-guard | github-email-scanAndScrub)
      echo "email-guard|github-email-scanAndScrub|github_email_guard.py|requirements.txt|python3 git|" ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
say()  { printf '[*] %s\n' "$*" >&2; }
ok()   { printf '[+] %s\n' "$*" >&2; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,19p' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null | sed 's/^# \{0,1\}//' || true
  cat >&2 <<EOF
usage: grimoire.sh install|update|uninstall|run|list <tool> [options]
tools: $TOOLS
EOF
}

need() {
  local c
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "'$c' is required but not installed"; done
}

load_tool() {
  local info
  info="$(tool_info "${1:-}")" || die "unknown tool '${1:-}' (tools: $TOOLS)"
  IFS='|' read -r T_NAME T_DIR T_ENTRY T_REQ T_NEEDS T_CACHE <<<"$info"
}

# fetch_source REF DEST  -> copies <repo>/<T_DIR> to DEST/app and grimoire.sh to DEST
fetch_source() {
  local ref="$1" dest="$2" tmp src
  tmp="$(mktemp -d)"
  say "downloading $REPO@$ref"
  if ! curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$ref" | tar -xz -C "$tmp"; then
    rm -rf "$tmp"; die "download failed (check the ref '$ref' and your network)"
  fi
  src="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -n1)"
  [ -d "$src/$T_DIR" ] || { rm -rf "$tmp"; die "$T_DIR not found in $REPO@$ref"; }
  $SUDO mkdir -p "$dest"
  $SUDO rm -rf "$dest/app.new"
  $SUDO cp -R "$src/$T_DIR" "$dest/app.new"
  if [ -f "$src/grimoire.sh" ]; then $SUDO cp "$src/grimoire.sh" "$dest/grimoire.sh"; fi
  $SUDO rm -rf "$dest/app"
  $SUDO mv "$dest/app.new" "$dest/app"
  rm -rf "$tmp"
}

# setup_python DEST -> sets PY (interpreter) and VENV_BIN (may be empty)
setup_python() {
  local dest="$1" req="$1/app/$T_REQ"
  VENV_BIN=""
  if $SUDO python3 -m venv "$dest/venv" >/dev/null 2>&1; then
    PY="$dest/venv/bin/python"
    VENV_BIN="$dest/venv/bin"
    say "installing python modules into $dest/venv"
    $SUDO "$PY" -m pip install -q --disable-pip-version-check --upgrade pip >/dev/null 2>&1 || true
    if [ -f "$req" ]; then
      $SUDO "$PY" -m pip install -q --disable-pip-version-check --upgrade -r "$req"
    fi
  else
    warn "python3 venv not available (install python3-venv for an isolated setup); using pip --user"
    PY="$(command -v python3)"
    if [ -f "$req" ]; then
      "$PY" -m pip install -q --user -r "$req" 2>/dev/null \
        || "$PY" -m pip install -q --user --break-system-packages -r "$req"
    fi
  fi
}

write_launcher() {
  local bin="$1" dest="$2" path_line="" scope_flag
  scope_flag="--dir \"$(dirname "$2")\""
  if [ "$dest" = "$SYSTEM_ROOT/$T_NAME" ]; then scope_flag="--system"; fi
  if [ "$dest" = "$LOCAL_ROOT/$T_NAME" ]; then scope_flag="--local"; fi
  if [ -n "$VENV_BIN" ]; then path_line="PATH=\"$VENV_BIN:\$PATH\"; export PATH"; fi
  $SUDO mkdir -p "$bin"
  $SUDO tee "$bin/$T_NAME" >/dev/null <<EOF
#!/bin/sh
# $LAUNCHER_TAG for $T_NAME ($dest)
case "\${1:-}" in
  self-update) shift; exec bash "$dest/grimoire.sh" update $T_NAME $scope_flag "\$@" ;;
  self-uninstall|self-remove) shift; exec bash "$dest/grimoire.sh" uninstall $T_NAME $scope_flag "\$@" ;;
esac
$path_line
exec "$PY" "$dest/app/$T_ENTRY" "\$@"
EOF
  $SUDO chmod 755 "$bin/$T_NAME"
}

write_meta() {
  local dest="$1" ref="$2" scope="$3" bin="$4"
  $SUDO tee "$dest/.grimoire" >/dev/null <<EOF
tool=$T_NAME
ref=$ref
scope=$scope
bin=$bin
python=$PY
venv_bin=$VENV_BIN
installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
}

meta_get() { sed -n "s/^$2=//p" "$1/.grimoire" 2>/dev/null | head -n1; }

# all_installs -> prints every install dir of T_NAME (custom, local, system)
all_installs() {
  local d
  for d in "${CUSTOM_DIR:+$CUSTOM_DIR/$T_NAME}" "$LOCAL_ROOT/$T_NAME" "$SYSTEM_ROOT/$T_NAME"; do
    if [ -n "$d" ] && [ -f "$d/.grimoire" ]; then echo "$d"; fi
  done
}

# find_install -> sets DEST (honours WANT_SCOPE=local|system), or returns 1
find_install() {
  local d found=""
  case "${WANT_SCOPE:-}" in
    local) [ -f "$LOCAL_ROOT/$T_NAME/.grimoire" ] && found="$LOCAL_ROOT/$T_NAME" ;;
    system) [ -f "$SYSTEM_ROOT/$T_NAME/.grimoire" ] && found="$SYSTEM_ROOT/$T_NAME" ;;
    *)
      for d in $(all_installs); do
        if [ -z "$found" ]; then found="$d"; else warn "$T_NAME is also installed in $d (use --system or --local to pick)"; fi
      done ;;
  esac
  [ -n "$found" ] || return 1
  DEST="$found"
}

use_sudo_for() {
  SUDO=""
  local target="$1"
  while [ ! -e "$target" ]; do target="$(dirname "$target")"; done
  if [ ! -w "$target" ] && [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "no write access to $1 and sudo is not available"
    SUDO="sudo"
  fi
}

check_path() {
  case ":$PATH:" in
    *":$1:"*) ;;
    *) warn "$1 is not in your PATH; add it:  echo 'export PATH=\"$1:\$PATH\"' >> ~/.bashrc" ;;
  esac
}

# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
cmd_install() {
  local scope="local" root="$LOCAL_ROOT" bin="$LOCAL_BIN" ref="$DEFAULT_REF" force=0
  load_tool "${1:-}"; shift || true
  while [ $# -gt 0 ]; do
    case "$1" in
      --system) scope="system"; root="$SYSTEM_ROOT"; bin="$SYSTEM_BIN" ;;
      --local) scope="local"; root="$LOCAL_ROOT"; bin="$LOCAL_BIN" ;;
      --dir) root="${2:?--dir needs a path}"; scope="custom"; shift ;;
      --bin) bin="${2:?--bin needs a path}"; shift ;;
      --ref) ref="${2:?--ref needs a value}"; shift ;;
      --force) force=1 ;;
      *) die "unknown option $1" ;;
    esac
    shift
  done
  # shellcheck disable=SC2086
  need curl tar $T_NEEDS
  local dest="$root/$T_NAME"
  if [ -f "$dest/.grimoire" ] && [ "$force" -eq 0 ]; then
    die "$T_NAME is already installed in $dest (use: update $T_NAME, or install --force)"
  fi
  use_sudo_for "$root"
  fetch_source "$ref" "$dest"
  setup_python "$dest"
  use_sudo_for "$bin"
  write_launcher "$bin" "$dest"
  use_sudo_for "$root"
  write_meta "$dest" "$ref" "$scope" "$bin"
  ok "installed $T_NAME -> $bin/$T_NAME  (files in $dest)"
  check_path "$bin"
  "$bin/$T_NAME" --version 2>/dev/null || "$bin/$T_NAME" --help >/dev/null 2>&1 || warn "installed, but '$T_NAME --help' failed"
}

cmd_update() {
  local target="${1:-}" ref=""
  shift || true
  while [ $# -gt 0 ]; do
    case "$1" in
      --ref) ref="${2:?--ref needs a value}"; shift ;;
      --dir) CUSTOM_DIR="${2:?}"; shift ;;
      --system) WANT_SCOPE="system" ;;
      --local) WANT_SCOPE="local" ;;
      *) die "unknown option $1" ;;
    esac
    shift
  done
  if [ "$target" = "all" ]; then
    local t any=0
    for t in $TOOLS; do
      load_tool "$t"
      local d
      for d in $(all_installs); do
        any=1
        if [ "$d" = "$SYSTEM_ROOT/$t" ]; then WANT_SCOPE=system; else WANT_SCOPE=local; fi
        cmd_update "$t" ${ref:+--ref "$ref"}
      done
    done
    [ "$any" -eq 1 ] || warn "nothing installed"
    return 0
  fi
  load_tool "$target"
  find_install || die "$T_NAME is not installed (use: install $T_NAME)"
  ref="${ref:-$(meta_get "$DEST" ref)}"
  local bin scope
  bin="$(meta_get "$DEST" bin)"; scope="$(meta_get "$DEST" scope)"
  use_sudo_for "$DEST"
  fetch_source "${ref:-$DEFAULT_REF}" "$DEST"
  setup_python "$DEST"
  use_sudo_for "$bin"
  write_launcher "$bin" "$DEST"
  use_sudo_for "$DEST"
  write_meta "$DEST" "${ref:-$DEFAULT_REF}" "${scope:-local}" "$bin"
  ok "updated $T_NAME ($DEST, ref ${ref:-$DEFAULT_REF})"
}

cmd_uninstall() {
  local target="${1:-}" purge=0
  shift || true
  while [ $# -gt 0 ]; do
    case "$1" in
      --purge) purge=1 ;;
      --dir) CUSTOM_DIR="${2:?}"; shift ;;
      --system) WANT_SCOPE="system" ;;
      --local) WANT_SCOPE="local" ;;
      *) die "unknown option $1" ;;
    esac
    shift
  done
  if [ "$target" = "all" ]; then
    local t
    for t in $TOOLS; do
      load_tool "$t"
      if find_install; then
        if [ "$purge" -eq 1 ]; then cmd_uninstall "$t" --purge; else cmd_uninstall "$t"; fi
      fi
      WANT_SCOPE=""
    done
    return 0
  fi
  load_tool "$target"
  find_install || die "$T_NAME is not installed"
  local bin
  bin="$(meta_get "$DEST" bin)"
  if [ -n "$bin" ] && [ -f "$bin/$T_NAME" ] && grep -q "$LAUNCHER_TAG" "$bin/$T_NAME"; then
    use_sudo_for "$bin"; $SUDO rm -f "$bin/$T_NAME"
  fi
  use_sudo_for "$DEST"
  $SUDO rm -rf "$DEST"
  rmdir "$(dirname "$DEST")" 2>/dev/null || true
  if [ "$purge" -eq 1 ] && [ -n "$T_CACHE" ] && [ -d "$T_CACHE" ]; then
    rm -rf "$T_CACHE"; say "removed cache $T_CACHE"
  fi
  ok "uninstalled $T_NAME"
}

cmd_run() {
  load_tool "${1:-}"; shift || true
  # shellcheck disable=SC2086
  need curl tar $T_NEEDS
  SUDO=""
  RUN_TMP="$(mktemp -d)"
  trap 'rm -rf "$RUN_TMP"' EXIT
  trap 'rm -rf "$RUN_TMP"; exit 130' INT TERM
  # keep pip's and the tool's caches inside the temp dir so nothing is left behind
  export PIP_CACHE_DIR="$RUN_TMP/pip-cache" XDG_CACHE_HOME="$RUN_TMP/cache"
  fetch_source "${GRIMOIRE_RUN_REF:-$DEFAULT_REF}" "$RUN_TMP" >&2
  setup_python "$RUN_TMP" >&2
  if [ -n "$VENV_BIN" ]; then export PATH="$VENV_BIN:$PATH"; fi
  say "running $T_NAME (temporary copy, removed afterwards)"
  local rc=0
  "$PY" "$RUN_TMP/app/$T_ENTRY" "$@" || rc=$?
  rm -rf "$RUN_TMP"
  trap - EXIT INT TERM
  say "cleaned up temporary files"
  return "$rc"
}

cmd_list() {
  local t
  printf '%-12s %-28s %s\n' "tool" "folder" "installed" >&2
  for t in $TOOLS; do
    load_tool "$t"
    local d shown=0
    for d in $(all_installs); do
      printf '%-12s %-28s %s (%s, %s)\n' "$T_NAME" "$T_DIR" "$d" "$(meta_get "$d" scope)" "$(meta_get "$d" ref)"
      shown=1
    done
    [ "$shown" -eq 1 ] || printf '%-12s %-28s %s\n' "$T_NAME" "$T_DIR" "-"
  done
}

main() {
  # When piped from curl, give the tool the terminal instead of the script pipe.
  if [ ! -t 0 ] && (exec </dev/tty) 2>/dev/null; then exec </dev/tty; fi
  SUDO="" CUSTOM_DIR="" WANT_SCOPE=""
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    install) cmd_install "$@" ;;
    update | upgrade) cmd_update "$@" ;;
    uninstall | remove) cmd_uninstall "$@" ;;
    run) cmd_run "$@" ;;
    list) cmd_list ;;
    -h | --help | help | "") usage ;;
    *) usage; die "unknown command '$cmd'" ;;
  esac
}

main "$@"
