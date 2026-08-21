#!/usr/bin/env bash
# WiFiAngel launcher: detect Linux family, install required packages, reuse .venv, exec wifiangel.py.
# The TUI requires root at runtime (airmon-ng / hostapd). Root is used for package install and for that exec.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV="$ROOT/.venv"
STATE_FILE="$ROOT/.run-state"
REQ_FILE="$ROOT/requirements.txt"
ENTRYPOINT="$ROOT/wifiangel.py"

OS_ID=""
OS_ID_LIKE=""
PKG_MGR=""

log() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }

die() {
  err "[!] $*"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_quiet() {
  local out rc
  out="$(mktemp)"
  set +e
  "$@" >"$out" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    cat "$out" >&2
    rm -f "$out"
    return "$rc"
  fi
  rm -f "$out"
  return 0
}

run_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif need_cmd sudo; then
    sudo "$@"
  else
    die "Root is required to install system packages, and sudo is not available."
  fi
}

detect_distro() {
  local os_release="/etc/os-release"
  if [[ ! -f "$os_release" ]]; then
    OS_ID="unknown"
    OS_ID_LIKE=""
    return
  fi
  OS_ID="$(awk -F= '$1=="ID" {gsub(/"/, "", $2); print $2; exit}' "$os_release")"
  OS_ID_LIKE="$(awk -F= '$1=="ID_LIKE" {gsub(/"/, "", $2); print $2; exit}' "$os_release")"
  OS_ID="${OS_ID:-unknown}"
  OS_ID_LIKE="${OS_ID_LIKE:-}"
}

detect_package_manager() {
  local hint="${OS_ID} ${OS_ID_LIKE}"
  hint="${hint,,}"

  for token in $hint; do
    case "$token" in
      debian|ubuntu|kali|linuxmint|pop|raspbian)
        PKG_MGR="apt"
        return
        ;;
      fedora)
        PKG_MGR="dnf"
        return
        ;;
      rhel|centos|rocky|almalinux)
        if need_cmd dnf; then
          PKG_MGR="dnf"
        else
          PKG_MGR="yum"
        fi
        return
        ;;
      arch|manjaro|endeavouros)
        PKG_MGR="pacman"
        return
        ;;
      opensuse*|suse|sles|sled)
        PKG_MGR="zypper"
        return
        ;;
      alpine)
        PKG_MGR="apk"
        return
        ;;
      gentoo)
        PKG_MGR="emerge"
        return
        ;;
    esac
  done

  if need_cmd apt-get && [[ -d /etc/apt ]]; then
    PKG_MGR="apt"
  elif need_cmd dnf; then
    PKG_MGR="dnf"
  elif need_cmd yum; then
    PKG_MGR="yum"
  elif need_cmd pacman; then
    PKG_MGR="pacman"
  elif need_cmd zypper; then
    PKG_MGR="zypper"
  elif need_cmd apk; then
    PKG_MGR="apk"
  elif need_cmd emerge; then
    PKG_MGR="emerge"
  else
    PKG_MGR="unknown"
  fi
}

pkg_for_role() {
  local role="$1"
  case "$PKG_MGR:$role" in
    apt:python) echo "python3" ;;
    apt:venv) echo "python3-venv" ;;
    apt:aircrack) echo "aircrack-ng" ;;
    apt:hashcat) echo "hashcat" ;;
    apt:hcxdumptool) echo "hcxdumptool" ;;
    apt:iproute) echo "iproute2" ;;
    apt:iw) echo "iw" ;;
    apt:pydev) echo "python3-dev" ;;
    apt:gcc) echo "gcc" ;;
    apt:libpcap) echo "libpcap0.8" ;;

    dnf:python|yum:python) echo "python3" ;;
    dnf:venv|yum:venv) echo "python3" ;;
    dnf:aircrack|yum:aircrack) echo "aircrack-ng" ;;
    dnf:hashcat|yum:hashcat) echo "hashcat" ;;
    dnf:hcxdumptool|yum:hcxdumptool) echo "hcxdumptool" ;;
    dnf:iproute|yum:iproute) echo "iproute" ;;
    dnf:iw|yum:iw) echo "iw" ;;
    dnf:pydev|yum:pydev) echo "python3-devel" ;;
    dnf:gcc|yum:gcc) echo "gcc" ;;
    dnf:libpcap|yum:libpcap) echo "libpcap" ;;

    pacman:python) echo "python" ;;
    pacman:venv) echo "python" ;;
    pacman:aircrack) echo "aircrack-ng" ;;
    pacman:hashcat) echo "hashcat" ;;
    pacman:hcxdumptool) echo "hcxdumptool" ;;
    pacman:iproute) echo "iproute2" ;;
    pacman:iw) echo "iw" ;;
    pacman:pydev) echo "python" ;;
    pacman:gcc) echo "gcc" ;;
    pacman:libpcap) echo "libpcap" ;;

    zypper:python) echo "python3" ;;
    zypper:venv) echo "python3-venv" ;;
    zypper:aircrack) echo "aircrack-ng" ;;
    zypper:hashcat) echo "hashcat" ;;
    zypper:hcxdumptool) echo "hcxdumptool" ;;
    zypper:iproute) echo "iproute2" ;;
    zypper:iw) echo "iw" ;;
    zypper:pydev) echo "python3-devel" ;;
    zypper:gcc) echo "gcc" ;;
    zypper:libpcap) echo "libpcap1" ;;

    apk:python) echo "python3" ;;
    apk:venv) echo "python3" ;;
    apk:aircrack) echo "aircrack-ng" ;;
    apk:hashcat) echo "hashcat" ;;
    apk:hcxdumptool) echo "hcxdumptool" ;;
    apk:iproute) echo "iproute2" ;;
    apk:iw) echo "iw" ;;
    apk:pydev) echo "python3-dev" ;;
    apk:gcc) echo "gcc musl-dev" ;;
    apk:libpcap) echo "libpcap" ;;

    emerge:python) echo "dev-lang/python" ;;
    emerge:venv) echo "dev-lang/python" ;;
    emerge:aircrack) echo "net-analyzer/aircrack-ng" ;;
    emerge:hashcat) echo "app-crypt/hashcat" ;;
    emerge:hcxdumptool) echo "net-wireless/hcxdumptool" ;;
    emerge:iproute) echo "sys-apps/iproute2" ;;
    emerge:iw) echo "net-wireless/iw" ;;
    emerge:pydev) echo "dev-lang/python" ;;
    emerge:gcc) echo "sys-devel/gcc" ;;
    emerge:libpcap) echo "net-libs/libpcap" ;;
    *) echo "" ;;
  esac
}

python_bin() {
  if need_cmd python3; then
    command -v python3
  elif need_cmd python; then
    command -v python
  else
    echo ""
  fi
}

python_ok() {
  local py="$1"
  [[ -n "$py" ]] || return 1
  "$py" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null
}

venv_ok() {
  local py
  py="$(python_bin)"
  [[ -n "$py" ]] || return 1
  "$py" -c 'import venv' 2>/dev/null
}

pkg_installed() {
  local pkg="$1"
  case "$PKG_MGR" in
    apt)
      dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'
      ;;
    dnf|yum|zypper)
      rpm -q "$pkg" >/dev/null 2>&1
      ;;
    pacman)
      pacman -Q "$pkg" >/dev/null 2>&1
      ;;
    apk)
      apk info -e "$pkg" >/dev/null 2>&1
      ;;
    emerge)
      ls -d /var/db/pkg/*/"${pkg##*/}"-* >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

collect_missing_roles() {
  local roles=()
  local py
  py="$(python_bin)"
  if ! python_ok "$py"; then
    roles+=(python)
  fi
  if ! venv_ok; then
    roles+=(venv)
  fi
  need_cmd airmon-ng && need_cmd airodump-ng && need_cmd aireplay-ng || roles+=(aircrack)
  need_cmd hashcat || roles+=(hashcat)
  need_cmd hcxdumptool || roles+=(hcxdumptool)
  need_cmd ip || roles+=(iproute)
  need_cmd iw || roles+=(iw)
  printf '%s\n' "${roles[@]+"${roles[@]}"}"
}

packages_for_roles() {
  local role pkg
  local -a out=()
  for role in "$@"; do
    [[ -n "$role" ]] || continue
    pkg="$(pkg_for_role "$role")"
    [[ -n "$pkg" ]] || continue
    local token
    for token in $pkg; do
      if ! pkg_installed "$token"; then
        out+=("$token")
      fi
    done
  done
  if [[ "${#out[@]}" -gt 0 ]]; then
    printf '%s\n' "${out[@]}"
  fi
}

refresh_pkg_index() {
  case "$PKG_MGR" in
    apt)
      run_quiet run_root env DEBIAN_FRONTEND=noninteractive apt-get update -qq
      ;;
    pacman)
      run_quiet run_root pacman -Sy --noconfirm
      ;;
    apk)
      run_quiet run_root apk update
      ;;
    zypper)
      run_quiet run_root zypper --non-interactive refresh
      ;;
    *)
      ;;
  esac
}

install_packages() {
  local -a pkgs=("$@")
  [[ "${#pkgs[@]}" -gt 0 ]] || return 0
  case "$PKG_MGR" in
    apt)
      run_quiet run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${pkgs[@]}"
      ;;
    dnf)
      run_quiet run_root dnf install -y -q "${pkgs[@]}"
      ;;
    yum)
      run_quiet run_root yum install -y -q "${pkgs[@]}"
      ;;
    pacman)
      run_quiet run_root pacman -S --needed --noconfirm "${pkgs[@]}"
      ;;
    zypper)
      run_quiet run_root zypper --non-interactive install --no-recommends "${pkgs[@]}"
      ;;
    apk)
      run_quiet run_root apk add -q "${pkgs[@]}"
      ;;
    emerge)
      run_quiet run_root emerge --noreplace --quiet-build y "${pkgs[@]}"
      ;;
    *)
      return 1
      ;;
  esac
}

check_privileges() {
  if [[ "$(id -u)" -eq 0 ]]; then
    return 0
  fi
  if need_cmd sudo; then
    return 0
  fi
  die "Installing system packages needs root. Install sudo or re-run as root."
}

install_system_dependencies() {
  local -a roles pkgs unique=()
  mapfile -t roles < <(collect_missing_roles)
  if [[ "${#roles[@]}" -eq 0 ]]; then
    return 0
  fi
  if [[ "$PKG_MGR" == "unknown" ]]; then
    err "[!] Linux distribution could not be supported automatically."
    err "[!] Missing packages: ${roles[*]}"
    err "[!] Install them with your package manager, then re-run ./run.sh"
    exit 1
  fi
  mapfile -t pkgs < <(packages_for_roles "${roles[@]}")
  if [[ "${#pkgs[@]}" -eq 0 ]]; then
    err "[!] Missing tools remain: ${roles[*]}"
    err "[!] Matching packages are already installed or unavailable. Install the tools manually."
    exit 1
  fi
  local pkg
  for pkg in "${pkgs[@]}"; do
    local seen=0
    local u
    for u in "${unique[@]+"${unique[@]}"}"; do
      [[ "$u" == "$pkg" ]] && seen=1 && break
    done
    if [[ "$seen" -eq 0 ]]; then
      unique+=("$pkg")
    fi
  done
  check_privileges
  log "[+] Installing missing system packages"
  refresh_pkg_index
  if ! install_packages "${unique[@]}"; then
    err "[!] Failed to install: ${unique[*]}"
    exit 1
  fi
  mapfile -t roles < <(collect_missing_roles)
  if [[ "${#roles[@]}" -gt 0 ]]; then
    err "[!] Still missing after install: ${roles[*]}"
    err "[!] Install them with your package manager, then re-run ./run.sh"
    exit 1
  fi
}

file_hash() {
  local path="$1"
  local py
  if need_cmd sha256sum; then
    sha256sum "$path" | awk '{print $1}'
  elif need_cmd shasum; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    py="$(python_bin)"
    [[ -n "$py" ]] || die "sha256sum is required to track Python dependencies"
    "$py" -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$path"
  fi
}

setup_environment() {
  local py
  py="$(python_bin)"
  python_ok "$py" || die "Python 3.8+ is required."
  venv_ok || die "Python venv module is missing (install python3-venv)."

  if [[ -e "$VENV" && ! -x "$VENV/bin/python" ]]; then
    err "[!] Virtual environment is invalid; recreating"
    rm -rf "$VENV"
  fi
  if [[ -d "$VENV" && ! -w "$VENV" && "$(id -u)" -ne 0 ]]; then
    die ".venv is not writable. Fix ownership or remove it, then re-run."
  fi
  if [[ ! -x "$VENV/bin/python" ]]; then
    run_quiet "$py" -m venv "$VENV"
  fi
  if [[ ! -x "$VENV/bin/python" ]]; then
    die "Could not create $VENV"
  fi
  log "[+] Environment ready"
}

deps_satisfied() {
  "$VENV/bin/python" -c 'import rich, scapy, netifaces, psutil, bleak' 2>/dev/null
}

install_app_dependencies() {
  [[ -f "$REQ_FILE" ]] || die "requirements.txt not found"
  local digest saved=""
  digest="$(file_hash "$REQ_FILE")"
  if [[ -f "$STATE_FILE" ]]; then
    saved="$(awk -F= '$1=="REQ_SHA256" {print $2; exit}' "$STATE_FILE")"
  fi
  if [[ "$saved" == "$digest" ]] && deps_satisfied; then
    log "[+] Dependencies ready"
    return 0
  fi
  if ! run_quiet "$VENV/bin/python" -m pip install -q -r "$REQ_FILE"; then
    log "[+] Installing missing system packages"
    local -a build_pkgs=()
    mapfile -t build_pkgs < <(packages_for_roles pydev gcc libpcap)
    if [[ "${#build_pkgs[@]}" -gt 0 && "$PKG_MGR" != "unknown" ]]; then
      check_privileges
      refresh_pkg_index
      install_packages "${build_pkgs[@]}" || true
    fi
    if ! run_quiet "$VENV/bin/python" -m pip install -q -r "$REQ_FILE"; then
      die "Python dependency install failed"
    fi
  fi
  printf 'REQ_SHA256=%s\n' "$digest" >"$STATE_FILE"
  deps_satisfied || die "Python dependencies installed but imports still fail"
  log "[+] Dependencies ready"
}

detect_entrypoint() {
  [[ -f "$ENTRYPOINT" ]] || die "Entrypoint not found: wifiangel.py"
}

run_application() {
  detect_entrypoint
  log "[+] Starting application"
  if [[ "$(id -u)" -eq 0 ]]; then
    exec "$VENV/bin/python" "$ENTRYPOINT"
  fi
  if ! need_cmd sudo; then
    die "WiFiAngel requires root at runtime. Install sudo or re-run as root."
  fi
  exec sudo -- "$VENV/bin/python" "$ENTRYPOINT"
}

main() {
  [[ "$(uname -s)" == "Linux" ]] || die "This application only runs on Linux."
  detect_distro
  detect_package_manager
  install_system_dependencies
  setup_environment
  install_app_dependencies
  run_application
}

main "$@"
