#!/usr/bin/env bash
# ==============================================================================
# MIL-STD-498 BOOTSTRAP ONE-CLICK INSTALLER
# ==============================================================================
# SYSTEM:             Rootcastle Home Watcher Stack
# SUBSYSTEM:          Deployment & Provisioning Bootstrap
# FILE NAME:          easy_install.sh
# VERSION:            1.2.0
# DATE:               2026-06-15
# SECURITY CLASSIF:   UNCLASSIFIED
# DESCRIPTION:        One-line installer bootstrap that provisions Git, clones
#                     the Home Watcher stack from GitHub, and executes the
#                     installation script to deploy Caddy, Mosquitto, and Frigate.
# ==============================================================================
set -euo pipefail

log() { printf '[INFO] %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

# Require root execution
if [[ "${EUID}" -ne 0 ]]; then
  die "This bootstrap script must be run with root privileges: sudo bash easy_install.sh"
fi

log "Initializing Rootcastle Home Watcher Stack deployment..."

# Install Git if missing
if ! command -v git >/dev/null 2>&1; then
  log "Git is not detected. Installing Git..."
  apt-get update
  apt-get install -y git
fi

# Set installation paths
INSTALL_TEMP="/tmp/home-watcher-bootstrap"
rm -rf "${INSTALL_TEMP}"

log "Downloading latest release files from GitHub..."
git clone --depth 1 https://github.com/rootcastleco/home-watcher.git "${INSTALL_TEMP}"

# Pass variables and execute installer
log "Running main stack installation scripts..."
cd "${INSTALL_TEMP}"
bash install_frigate_raspberry_pi.sh "$@"

# Clean up installer cache
rm -rf "${INSTALL_TEMP}"
log "Bootstrap installer completed successfully."
