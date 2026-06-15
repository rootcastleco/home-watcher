#!/usr/bin/env bash
# ==============================================================================
# MIL-STD-498 PC-TO-SERVER CONVERTER & SYSTEM HARDENER
# ==============================================================================
# SYSTEM:             Rootcastle Home Watcher Stack
# SUBSYSTEM:          OS Hardening & Headless Server Conversion
# FILE NAME:          convert_pc_to_server.sh
# VERSION:            1.2.0
# DATE:               2026-06-15
# SECURITY CLASSIF:   UNCLASSIFIED
# DESCRIPTION:        Converts standard Debian/Ubuntu PCs or laptops into dedicated
#                     headless home security servers. Disables sleep/lid switches,
#                     stops desktop GUI managers to free RAM, configures UFW firewall,
#                     detects network interfaces, and installs Docker dependencies.
# ==============================================================================
set -euo pipefail

log() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

# Check root privileges
if [[ "${EUID}" -ne 0 ]]; then
  die "This server conversion script must be run with root privileges: sudo bash convert_pc_to_server.sh"
fi

echo "======================================================================"
echo "         Rootcastle PC-to-Server Conversion & Hardening Tool         "
echo "======================================================================"
echo "This tool prepares a generic PC or Laptop to run as a dedicated,      "
echo "headless Home Watcher security server.                                "
echo "----------------------------------------------------------------------"

# 1. Disable Sleep & Lid Close Suspend (Essential for Laptop Servers)
disable_sleep_suspend() {
  log "Configuring system power management to disable suspend/sleep..."
  
  # Configure systemd logind for laptop lid actions
  local logind_conf="/etc/systemd/logind.conf"
  if [[ -f "${logind_conf}" ]]; then
    # Backup logind
    cp "${logind_conf}" "${logind_conf}.bak"
    
    # Set lid switches to ignore
    sed -i 's/^#\?HandleLidSwitch=.*/HandleLidSwitch=ignore/' "${logind_conf}"
    sed -i 's/^#\?HandleLidSwitchExternalPower=.*/HandleLidSwitchExternalPower=ignore/' "${logind_conf}"
    sed -i 's/^#\?HandleLidSwitchDocked=.*/HandleLidSwitchDocked=ignore/' "${logind_conf}"
    sed -i 's/^#\?LidSwitchIgnoreInhibit=.*/LidSwitchIgnoreInhibit=no/' "${logind_conf}"
    
    systemctl restart systemd-logind || true
    log "Laptop lid switch actions configured to ignore suspend."
  fi

  # Mask systemd sleep/suspend targets
  log "Masking systemd sleep, suspend, and hibernate targets..."
  systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
}

# 2. Disable Desktop Environment (Stop GUI to free RAM)
disable_desktop_gui() {
  read -rp "Do you want to disable the graphical desktop GUI to free memory? (y/n) [n]: " choice
  if [[ "${choice}" =~ ^[Yy]$ ]]; then
    log "Configuring system default runlevel to headless CLI mode (multi-user)..."
    systemctl set-default multi-user.target
    log "Headless runlevel configured. GUI will be disabled on next reboot."
    log "To revert this, run: sudo systemctl set-default graphical.target"
  else
    log "Graphical desktop environment configuration kept unchanged."
  fi
}

# 3. Configure Restrictive Firewall (UFW)
configure_firewall() {
  log "Configuring UFW firewall settings..."
  
  # Install UFW if missing
  if ! command -v ufw >/dev/null 2>&1; then
    apt-get update
    apt-get install -y ufw
  fi

  # Set default policies
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  # Allow SSH
  ufw allow ssh
  
  # Allow HTTPS proxy
  ufw allow 10443/tcp comment "Caddy Ingress Proxy"
  
  # Allow local network monitoring access to Frigate (internal LAN)
  ufw allow 8971/tcp comment "Frigate UI direct LAN"

  log "Firewall defaults configured (SSH and HTTPS allowed)."
}

# 4. Network Interface Detection
detect_interfaces() {
  log "Detecting physical network interfaces..."

  # Find ethernet interfaces
  local eth_ifs
  eth_ifs=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|en|em|p)' || true)
  
  # Find wireless interfaces
  local wifi_ifs
  wifi_ifs=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(wlan|wl)' || true)

  echo "----------------------------------------------------------------------"
  echo "Detected Network Interfaces:"
  echo "----------------------------------------------------------------------"
  if [[ -n "${eth_ifs}" ]]; then
    echo "Ethernet (LAN/WAN):"
    echo "${eth_ifs}" | sed 's/^/  - /'
  else
    warn "No physical Ethernet interface detected!"
  fi

  if [[ -n "${wifi_ifs}" ]]; then
    echo "Wireless (Wi-Fi):"
    echo "${wifi_ifs}" | sed 's/^/  - /'
    
    # Save first detected wifi interface name
    local first_wifi
    first_wifi=$(echo "${wifi_ifs}" | head -n 1)
    echo "----------------------------------------------------------------------"
    echo "Default Wi-Fi AP interface will be set to: ${first_wifi}"
    echo "If you install the ESP32 isolated access point, configure wlan0 to ${first_wifi}."
    echo "----------------------------------------------------------------------"
  else
    warn "No Wireless (Wi-Fi) interface detected. Isolated AP setup is unavailable."
  fi
}

# 5. Install Base Dependencies
install_dependencies() {
  log "Installing required packages..."
  apt-get update
  apt-get install -y curl wget git net-tools fail2ban ca-certificates gnupg lsb-release

  # Install Docker Engine
  if ! command -v docker >/dev/null 2>&1; then
    log "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
  else
    log "Docker is already installed."
  fi

  # Install Docker Compose
  if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
    log "Installing Docker Compose plugin..."
    apt-get install -y docker-compose-plugin || apt-get install -y docker-compose
  fi

  systemctl enable --now docker
  systemctl enable --now fail2ban
}

# 6. Hardware Acceleration Guidelines
show_hardware_acceleration_info() {
  echo "======================================================================"
  echo "             Hardware Video Decoding Configuration                    "
  echo "======================================================================"
  echo "For Intel CPUs (Core/Celeron with QuickSync):"
  echo "  - In config/config.yml, add the preset: preset-intel-vaapi"
  echo "  - Map device: /dev/dri/renderD128 to the Frigate container."
  echo ""
  echo "For AMD Radeon GPUs:"
  echo "  - In config/config.yml, add the preset: preset-vaapi"
  echo "  - Map device: /dev/dri/renderD128 to the Frigate container."
  echo ""
  echo "For NVIDIA GPUs:"
  echo "  - Install NVIDIA Container Toolkit."
  echo "  - Enable 'deploy.resources.reservations.devices' in docker-compose.yml."
  echo "======================================================================"
}

# Main Execution Flow
main() {
  install_dependencies
  disable_sleep_suspend
  disable_desktop_gui
  configure_firewall
  detect_interfaces
  
  # Enable firewall
  ufw --force enable
  log "Firewall enabled successfully."

  echo "----------------------------------------------------------------------"
  echo "PC-to-Server Conversion completed successfully!"
  echo "Please reboot your system to apply runlevel and GUI changes."
  echo "After reboot, run './configure.sh' to set up settings, then"
  echo "run 'docker compose up -d' to start the Home Watcher Stack."
  echo "----------------------------------------------------------------------"
  show_hardware_acceleration_info
}

main "$@"
