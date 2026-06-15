#!/usr/bin/env bash
# ==============================================================================
# MIL-STD-498 GENERAL SERVER STACK INSTALLER
# ==============================================================================
# SYSTEM:             Rootcastle Home Watcher Stack
# SUBSYSTEM:          General Linux Provisioning & Setup
# FILE NAME:          install.sh
# VERSION:            1.2.0
# DATE:               2026-06-15
# SECURITY CLASSIF:   UNCLASSIFIED
# DESCRIPTION:        Automates dependency installation, stages stack directories,
#                     generates SSL proxy certs, runs the interactive setup wizard,
#                     and spins up the Home Watcher container services on any
#                     generic Debian/Ubuntu PC, laptop, or server.
# ==============================================================================
set -euo pipefail

FRIGATE_DIR="${FRIGATE_DIR:-/opt/frigate}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TZ_VALUE="${TZ:-Europe/Istanbul}"
LOCAL_IP="$(hostname -I | awk '{print $1}' 2>/dev/null || echo '127.0.0.1')"
WAN_IP="${WAN_IP:-}"

log() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    die "Docker Compose is not installed"
  fi
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run with sudo: sudo bash install.sh"
  fi
}

check_repo_layout() {
  local required=(
    "docker-compose.yml"
    ".env.example"
    "config/config.yml"
    "caddy/Caddyfile"
    "mosquitto/mosquitto.conf"
    "security-ai-alerts/app.py"
    "scripts/setup_esp32_ap.sh"
    "configure.sh"
  )
  for path in "${required[@]}"; do
    [[ -e "${SCRIPT_DIR}/${path}" ]] || die "Missing ${path}; run this script from the repository root"
  done
}

install_packages() {
  log "Installing server base packages..."
  apt-get update
  apt-get install -y ca-certificates curl gnupg lsb-release openssl rsync usbutils v4l-utils iw wireless-tools

  if ! command -v docker >/dev/null 2>&1; then
    log "Installing Docker Engine..."
    curl -fsSL https://get.docker.com | sh
  else
    log "Docker already installed"
  fi

  if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
    log "Installing Docker Compose plugin..."
    apt-get install -y docker-compose-plugin || apt-get install -y docker-compose
  fi

  systemctl enable --now docker
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    usermod -aG docker "${SUDO_USER}" || true
  fi
}

sync_stack() {
  log "Syncing stack files into ${FRIGATE_DIR}..."
  mkdir -p "${FRIGATE_DIR}"
  if [[ "$(realpath "${SCRIPT_DIR}")" == "$(realpath "${FRIGATE_DIR}")" ]]; then
    log "Repository already lives at ${FRIGATE_DIR}; sync skipped"
    mkdir -p "${FRIGATE_DIR}/media"
    return
  fi
  rsync -a \
    --exclude ".git" \
    --exclude "storage" \
    --exclude "media" \
    --exclude ".env" \
    --exclude "*.pem" \
    "${SCRIPT_DIR}/docker-compose.yml" \
    "${SCRIPT_DIR}/.env.example" \
    "${SCRIPT_DIR}/caddy" \
    "${SCRIPT_DIR}/mosquitto" \
    "${SCRIPT_DIR}/security-ai-alerts" \
    "${SCRIPT_DIR}/scripts" \
    "${SCRIPT_DIR}/configure.sh" \
    "${SCRIPT_DIR}/convert_pc_to_server.sh" \
    "${FRIGATE_DIR}/"
  
  if [[ ! -f "${FRIGATE_DIR}/config/config.yml" ]]; then
    rsync -a "${SCRIPT_DIR}/config" "${FRIGATE_DIR}/"
  else
    log "Keeping existing ${FRIGATE_DIR}/config/config.yml"
  fi
  mkdir -p "${FRIGATE_DIR}/media"
}

run_configuration_wizard() {
  local env_file="${FRIGATE_DIR}/.env"
  if [[ -f "${env_file}" ]]; then
    log "Keeping existing environment configurations at ${env_file}."
    return
  fi

  log "Launching interactive configuration form..."
  cd "${FRIGATE_DIR}"
  bash configure.sh
}

ensure_proxy_cert() {
  local cert_dir="${FRIGATE_DIR}/caddy/certs"
  local cert_file="${cert_dir}/frigate-local.crt"
  local key_file="${cert_dir}/frigate-local.key"
  if [[ -f "${cert_file}" && -f "${key_file}" ]]; then
    chmod 600 "${key_file}"
    return
  fi

  log "Creating local self-signed HTTPS certificate for Caddy ingress proxy..."
  mkdir -p "${cert_dir}"

  local alt_names="IP:127.0.0.1,IP:${LOCAL_IP},DNS:frigate-local,DNS:localhost"
  if [[ -n "${WAN_IP}" ]]; then
    alt_names="${alt_names},IP:${WAN_IP}"
  fi

  openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
    -keyout "${key_file}" \
    -out "${cert_file}" \
    -subj "/CN=frigate-local" \
    -addext "subjectAltName=${alt_names}"
  chmod 600 "${key_file}"
}

maybe_setup_esp32_ap() {
  if [[ "${SETUP_ESP32_AP:-false}" == "true" ]]; then
    log "Configuring isolated Wi-Fi AP for wireless cameras..."
    
    # Auto-detect default wireless interface
    local default_wifi
    default_wifi=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(wlan|wl)' | head -n 1 || echo "")
    
    if [[ -z "${default_wifi}" ]]; then
      warn "No wireless interface detected on this machine. Skipping wireless AP setup."
      return
    fi
    
    log "Detected Wi-Fi interface: ${default_wifi}"
    
    # Set ESP_AP_IFACE variable to pass to setup script
    export ESP_AP_IFACE="${default_wifi}"
    bash "${FRIGATE_DIR}/scripts/setup_esp32_ap.sh"
  else
    warn "Wireless AP setup skipped. (To isolate cameras, run with SETUP_ESP32_AP=true and ESP_AP_PASSWORD)"
  fi
}

start_stack() {
  cd "${FRIGATE_DIR}"
  compose config >/dev/null
  compose pull mqtt frigate frigate-proxy
  compose build security-ai-alerts
  compose up -d
}

main() {
  require_root
  check_repo_layout
  install_packages
  sync_stack
  run_configuration_wizard
  ensure_proxy_cert
  maybe_setup_esp32_ap
  start_stack

  log "Rootcastle Home Watcher is starting..."
  log "LAN Web UI: https://${LOCAL_IP}:8971"
  log "Proxy Web UI: https://${LOCAL_IP}:10443"
  log "Modem port forward rule: WAN 10443/TCP -> ${LOCAL_IP}:10443/TCP"
  log "Check logs: cd ${FRIGATE_DIR} && docker compose logs -f"
}

main "$@"
