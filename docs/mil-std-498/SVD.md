# Software Version Description (SVD)
## for Rootcastle Home Watcher Stack

**Document Identifier**: RC-HW-SVD-V1.2.0  
**Version**: 1.2.0  
**Date**: 2026-06-15  
**Security Classification**: UNCLASSIFIED  
**Branding**: Rootcastle Security (https://www.rootcastle.com)

---

### 1. Scope

#### 1.1 Identification
This document establishes the Software Version Description (SVD) for the **Rootcastle Home Watcher Stack**, Version 1.2.0.

#### 1.2 System Overview
The Rootcastle Home Watcher Stack is a local-first surveillance and GenAI-powered alert stack designed for low-power hardware appliances (such as the Raspberry Pi 5).

---

### 2. Version Description

#### 2.1 Inventory of Software Contents
The release package contains the following source files and directories:

| Component Path | File Type | Description |
|:---|:---:|:---|
| `docker-compose.yml` | YAML | Core service stack definitions |
| `.env.example` | Template | Template configuration parameters |
| `install.sh` | Bash | Generic Linux server installer script |
| `install_frigate_raspberry_pi.sh` | Bash | Deprecated Raspberry Pi-specific installer |
| `configure.sh` | Bash | Interactive configuration setup form |
| `convert_pc_to_server.sh` | Bash | OS hardening and headless PC-to-server converter |
| `repository-metadata.json` | JSON | Package descriptor and index keywords |
| `caddy/Caddyfile` | Config | Caddy proxy configuration rules |
| `config/config.yml` | YAML | Frigate cameras and model configurations |
| `config/rtsp_nginx_append.conf` | Config | Nginx RTSP parameters |
| `mosquitto/mosquitto.conf` | Config | Mosquitto broker setup |
| `scripts/setup_esp32_ap.sh` | Bash | AP routing and network segregator |
| `security-ai-alerts/Dockerfile` | Docker | Docker building description for alert service |
| `security-ai-alerts/requirements.txt` | Python | List of Python dependencies |
| `security-ai-alerts/app.py` | Python | Source code for the alert daemon |

#### 2.2 Changes in Version 1.2.0
The following features and security refactoring items have been completed in this release:
- **Redacted Hardcoded Credentials**: Removed plain-text usernames and passwords (`rootcastle:2302`, `admin:2302`) from the core configuration, shifting them to environmental parameters.
- **Dynamic IP Resolution**: Replaced static local network IPs (`192.168.1.21`) and public WAN IPs (`188.3.149.17`) with dynamic local IP resolving techniques (`LOCAL_IP`) in shell setups and proxy certificate parameters.
- **Rootcastle Branding**: Integrated branding signatures across logging, directories, and developer documents.
- **MIL-STD-498 Compliance**: Restructured all codebase document sets (SRS, SDD, SVD, SUM) and introduced military-grade headers to all scripts.

---

### 3. Subsystem Dependencies

- **Host Operating System**: Raspberry Pi OS (Bookworm 64-bit) or any Debian 12 compatible distribution.
- **Docker Engine**: Version `24.0.0` or higher.
- **Docker Compose**: Version `2.20.0` or higher.
- **Python Libraries**:
  - `httpx` == `0.28.1`
  - `numpy` == `2.2.6`
  - `opencv-python-headless` == `4.12.0.88`
  - `paho-mqtt` == `1.6.1`
- **Reverse Proxy**: Caddy `2.7.0` (Alpine version).
- **Message Broker**: Eclipse Mosquitto `2.0.0` or higher.

---

### 4. Adaptation Data
To adapt this version to a target system:
1. Clone the repository and execute `install_frigate_raspberry_pi.sh`.
2. Configure the generated `/opt/frigate/.env` with local network camera IPs (`FRIGATE_DVR_IP`, `FRIGATE_PTZ_IP`, `FRIGATE_ESP32_IP`, `FRIGATE_PRINTER_IP`).
3. Set your private keys for the Telegram Bot API (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`) and OpenRouter API (`OPENROUTER_API_KEY`).
