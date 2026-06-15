#!/usr/bin/env bash
# ==============================================================================
# MIL-STD-498 INTERACTIVE SETUP WIZARD & CONFIGURATOR
# ==============================================================================
# SYSTEM:             Rootcastle Home Watcher Stack
# SUBSYSTEM:          Provisioning & Parameters Form
# FILE NAME:          configure.sh
# VERSION:            1.2.0
# DATE:               2026-06-15
# SECURITY CLASSIF:   UNCLASSIFIED
# DESCRIPTION:        Interactive terminal configuration wizard that prompts
#                     users for environment values, performs format validations,
#                     and writes the validated parameters to the stack's .env file.
# ==============================================================================
set -euo pipefail

log() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

ENV_FILE=".env"
TEMPLATE_FILE=".env.example"

# Load existing values if .env already exists
load_current_value() {
  local var_name="$1"
  local default_val="$2"
  if [[ -f "${ENV_FILE}" ]]; then
    local val
    val=$(grep "^${var_name}=" "${ENV_FILE}" | cut -d'=' -f2-)
    if [[ -n "${val}" ]]; then
      echo "${val}"
      return
    fi
  fi
  echo "${default_val}"
}

prompt_value() {
  local var_name="$1"
  local description="$2"
  local default_val="$3"
  local current_val
  current_val=$(load_current_value "${var_name}" "${default_val}")

  local user_input
  read -rp "Enter ${description} [Current/Default: ${current_val}]: " user_input
  if [[ -z "${user_input}" ]]; then
    user_input="${current_val}"
  fi
  echo "${user_input}"
}

prompt_secret() {
  local var_name="$1"
  local description="$2"
  local current_val
  current_val=$(load_current_value "${var_name}" "")

  local user_input
  if [[ -n "${current_val}" ]]; then
    read -rsp "Enter ${description} [Current: **** (Press Enter to keep)]: " user_input
    echo ""
    if [[ -z "${user_input}" ]]; then
      user_input="${current_val}"
    fi
  else
    while true; do
      read -rsp "Enter ${description} (Required): " user_input
      echo ""
      if [[ -n "${user_input}" ]]; then
        break
      fi
      warn "This parameter is required."
    done
  fi
  echo "${user_input}"
}

main() {
  echo "======================================================================"
  echo "         Rootcastle Home Watcher Configuration Setup Form             "
  echo "======================================================================"
  echo "This wizard generates the local .env configuration file."
  echo "Press Enter to accept the current value or default fallback."
  echo "----------------------------------------------------------------------"

  # Core Settings
  local tz
  tz=$(prompt_value "TZ" "Timezone (e.g. Europe/London)" "Europe/Istanbul")
  
  local shm
  shm=$(prompt_value "FRIGATE_SHM_SIZE" "Frigate Shared Memory size (e.g. 256mb, 512mb)" "256mb")

  # IPs
  echo "----------------------------------------------------------------------"
  echo "Network IP Addresses of your Cameras & Hardware"
  echo "----------------------------------------------------------------------"
  local dvr_ip
  dvr_ip=$(prompt_value "FRIGATE_DVR_IP" "XMeye DVR Network IP Address" "10.0.10.10")

  local ptz_ip
  ptz_ip=$(prompt_value "FRIGATE_PTZ_IP" "PTZ IP Camera Network IP Address" "10.0.10.20")

  local esp_ip
  esp_ip=$(prompt_value "FRIGATE_ESP32_IP" "ESP32 office camera Network IP Address" "10.0.10.30")

  local printer_ip
  printer_ip=$(prompt_value "FRIGATE_PRINTER_IP" "3D Printer camera Network IP Address" "10.0.10.40")

  # Credentials
  echo "----------------------------------------------------------------------"
  echo "Security Credentials for Video Streams"
  echo "----------------------------------------------------------------------"
  local dvr_user
  dvr_user=$(prompt_value "FRIGATE_DVR_USER" "DVR Stream Username" "admin")
  local dvr_pass
  dvr_pass=$(prompt_secret "FRIGATE_DVR_PASSWORD" "DVR Stream Password")

  local ptz_user
  ptz_user=$(prompt_value "FRIGATE_PTZ_USER" "PTZ Stream Username" "admin")
  local ptz_pass
  ptz_pass=$(prompt_secret "FRIGATE_PTZ_PASSWORD" "PTZ Stream Password")

  local esp_user
  esp_user=$(prompt_value "FRIGATE_ESP32_USER" "ESP32 Camera Username" "rootcastle")
  local esp_pass
  esp_pass=$(prompt_secret "FRIGATE_ESP32_PASSWORD" "ESP32 Camera Password")

  # API Keys
  echo "----------------------------------------------------------------------"
  echo "External API Keys and Integrations"
  echo "----------------------------------------------------------------------"
  local tg_token
  tg_token=$(prompt_secret "TELEGRAM_BOT_TOKEN" "Telegram Bot API Token (e.g. 12345:AA-XX)")
  
  local tg_chat
  tg_chat=$(prompt_value "TELEGRAM_CHAT_ID" "Telegram Destination Chat ID" "")

  local or_key
  or_key=$(prompt_secret "OPENROUTER_API_KEY" "OpenRouter Authentication API Key")

  local or_model
  or_model=$(prompt_value "OPENROUTER_MODEL" "OpenRouter AI model endpoint" "openrouter/free")

  local ext_url
  ext_url=$(prompt_value "FRIGATE_EXTERNAL_URL" "External Access URL of this appliance" "https://localhost:10443")

  # Write configuration
  log "Writing configuration keys to ${ENV_FILE}..."
  
  cat > "${ENV_FILE}" <<EOF
# ==============================================================================
# GENERATED ENVIRONMENT CONFIGURATION
# ==============================================================================
# SYSTEM:             Rootcastle Home Watcher Stack
# CONFIG FILE:        .env
# DATE:               $(date '+%Y-%m-%d %H:%M:%S')
# ==============================================================================

# Core System Settings
TZ=${tz}
FRIGATE_RTSP_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=' | head -c 24)
FRIGATE_SHM_SIZE=${shm}

# Camera & Device IP Configurations
FRIGATE_DVR_IP=${dvr_ip}
FRIGATE_PTZ_IP=${ptz_ip}
FRIGATE_ESP32_IP=${esp_ip}
FRIGATE_PRINTER_IP=${printer_ip}

# Camera Credentials
FRIGATE_DVR_USER=${dvr_user}
FRIGATE_DVR_PASSWORD=${dvr_pass}
FRIGATE_PTZ_USER=${ptz_user}
FRIGATE_PTZ_PASSWORD=${ptz_pass}
FRIGATE_ESP32_USER=${esp_user}
FRIGATE_ESP32_PASSWORD=${esp_pass}

# Alert Service Integration Keys
TELEGRAM_BOT_TOKEN=${tg_token}
TELEGRAM_CHAT_ID=${tg_chat}
OPENROUTER_API_KEY=${or_key}
OPENROUTER_MODEL=${or_model}
OPENROUTER_SITE_URL=${ext_url}

# Camera polling and notification policy.
ALERT_CAMERAS=ofis,giris_1,giris_2,ptz_dis,esp32_ofis
ALERT_OFFICE_CAMERAS=ofis,esp32_ofis
ALERT_POLL_INTERVAL_SECONDS=3
ALERT_COOLDOWN_SECONDS=90
ALERT_OFFICE_COOLDOWN_SECONDS=60
ALERT_MOTION_PIXEL_RATIO=0.035
ALERT_RATE_LIMIT_BACKOFF_SECONDS=600
ALERT_HTTP_TIMEOUT_SECONDS=12

# Configurable alerts, external links, and interactive command polling
ALERT_LABELS=person,cat,bird,dog
FRIGATE_EXTERNAL_URL=${ext_url}
TELEGRAM_POLLING_ENABLED=true

# FLSun T1 3D Printer camera and motion monitoring settings
PRINTER_ENABLED=true
PRINTER_SNAPSHOT_URL=http://${printer_ip}/webcam/?action=snapshot
PRINTER_CHECK_INTERVAL_SECONDS=20
PRINTER_MOVEMENT_THRESHOLD_PCT=0.5
EOF

  chmod 600 "${ENV_FILE}"
  log "Configuration file written successfully: ${ENV_FILE}"
  log "Note: Keep this file secure; do not share or commit it."
}

main "$@"
