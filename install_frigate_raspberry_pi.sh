#!/usr/bin/env bash
# ==============================================================================
# MIL-STD-498 INSTALLATION AND CONFIGURATION SCRIPT
# ==============================================================================
# SYSTEM:             Rootcastle Home Watcher Stack
# SUBSYSTEM:          Deployment & Environment Provisioning
# FILE NAME:          install_frigate_raspberry_pi.sh
# VERSION:            1.2.0
# DATE:               2026-06-15
# SECURITY CLASSIF:   UNCLASSIFIED
# DESCRIPTION:        Automates base package configuration, Docker environments,
#                     directory structures, self-signed HTTPS proxy certificates,
#                     and starts the Home Watcher container services.
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
    die "Run with sudo: sudo bash install_frigate_raspberry_pi.sh"
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
  )
  for path in "${required[@]}"; do
    [[ -e "${SCRIPT_DIR}/${path}" ]] || die "Missing ${path}; run this script from the repository root"
  done
}

install_packages() {
  log "Installing Raspberry Pi base packages"
  apt-get update
  apt-get install -y ca-certificates curl gnupg lsb-release openssl rsync usbutils v4l-utils

  if ! command -v docker >/dev/null 2>&1; then
    log "Installing Docker Engine"
    curl -fsSL https://get.docker.com | sh
  else
    log "Docker already installed"
  fi

  if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
    log "Installing Docker Compose plugin"
    apt-get install -y docker-compose-plugin || apt-get install -y docker-compose
  fi

  systemctl enable --now docker
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    usermod -aG docker "${SUDO_USER}" || true
  fi
}

sync_stack() {
  log "Syncing Frigate stack into ${FRIGATE_DIR}"
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
    "${FRIGATE_DIR}/"
  if [[ ! -f "${FRIGATE_DIR}/config/config.yml" ]]; then
    rsync -a "${SCRIPT_DIR}/config" "${FRIGATE_DIR}/"
  else
    log "Keeping existing ${FRIGATE_DIR}/config/config.yml"
  fi
  mkdir -p "${FRIGATE_DIR}/media"
}

ensure_env() {
  local env_file="${FRIGATE_DIR}/.env"
  if [[ -f "${env_file}" ]]; then
    chmod 600 "${env_file}"
    log "Keeping existing ${env_file}"
    return
  fi

  local rtsp_password
  rtsp_password="$(openssl rand -base64 32 | tr -d '/+=' | head -c 24)"
  cp "${FRIGATE_DIR}/.env.example" "${env_file}"
  sed -i "s/^FRIGATE_RTSP_PASSWORD=.*/FRIGATE_RTSP_PASSWORD=${rtsp_password}/" "${env_file}"
  sed -i "s|^TZ=.*|TZ=${TZ_VALUE}|" "${env_file}"
  chmod 600 "${env_file}"
  warn "Created ${env_file}. Fill TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, and OPENROUTER_API_KEY before relying on alerts."
}

ensure_proxy_cert() {
  local cert_dir="${FRIGATE_DIR}/caddy/certs"
  local cert_file="${cert_dir}/frigate-local.crt"
  local key_file="${cert_dir}/frigate-local.key"
  if [[ -f "${cert_file}" && -f "${key_file}" ]]; then
    chmod 600 "${key_file}"
    return
  fi

  log "Creating local self-signed HTTPS certificate for the Frigate proxy"
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
    log "Configuring isolated ESP32 AP"
    bash "${FRIGATE_DIR}/scripts/setup_esp32_ap.sh"
  else
    warn "ESP32 AP setup skipped. Run with SETUP_ESP32_AP=true and ESP_AP_PASSWORD to isolate the ESP32 camera."
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
  ensure_env
  ensure_proxy_cert
  maybe_setup_esp32_ap
  start_stack

  log "Frigate stack is starting"
  log "LAN UI: https://${LOCAL_IP}:8971"
  log "Proxy UI: https://${LOCAL_IP}:10443"
  log "Modem rule: WAN 10443/TCP -> ${LOCAL_IP}:10443/TCP"
  log "Logs: cd ${FRIGATE_DIR} && docker compose logs -f"
}

main "$@"
