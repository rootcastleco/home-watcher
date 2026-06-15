#!/usr/bin/env bash
# ==============================================================================
# MIL-STD-498 AI STACK DIAGNOSTIC TEST RUNNER
# ==============================================================================
# SYSTEM:             Rootcastle Home Watcher Stack
# SUBSYSTEM:          Vision AI & Telegram Integration Testing
# FILE NAME:          test_ai.sh
# VERSION:            1.2.0
# DATE:               2026-06-15
# SECURITY CLASSIF:   UNCLASSIFIED
# DESCRIPTION:        Diagnostic launcher that starts the test_ai_integration.py
#                     tool inside the security-ai-alerts container environment
#                     so that no Python libraries need to be installed on the host.
# ==============================================================================
set -euo pipefail

log() { printf '[INFO] %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

# Check Docker installation
if ! command -v docker >/dev/null 2>&1; then
  die "Docker is not installed or not running on the host system."
fi

# Check for .env file
if [[ ! -f ".env" ]]; then
  die "Missing .env configuration file in the current directory. Run ./configure.sh first."
fi

log "Bootstrapping AI alerts diagnostic client..."

# Build container if not already built to ensure environment is ready
docker compose build security-ai-alerts

# Run the test python script inside the container using the loaded env parameters
log "Running diagnostics in container context..."
docker compose run --rm \
  --entrypoint python \
  -v "$(pwd)/scripts:/app/scripts" \
  security-ai-alerts \
  /app/scripts/test_ai_integration.py "$@"

log "Diagnostics execution finished."
