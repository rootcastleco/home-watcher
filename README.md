<p align="center">
  <img src="https://img.shields.io/badge/Rootcastle-Home__Watcher-0052FF?style=for-the-badge&logo=shield&logoColor=white" alt="Rootcastle Logo" height="60px"/>
</p>

<h1 align="center">Rootcastle Home Watcher</h1>

<p align="center">
  <strong>A Hardened, MIL-STD-498 Compliant local-first intelligent video surveillance and AI alert security appliance stack.</strong>
</p>

<p align="center">
  <a href="https://www.rootcastle.com"><img src="https://img.shields.io/badge/Website-rootcastle.com-0052FF?style=flat-square&logo=google-chrome&logoColor=white" alt="Website"/></a>
  <img src="https://img.shields.io/badge/Hardware-Raspberry%20Pi%205-C51A4A?style=flat-square&logo=raspberry-pi&logoColor=white" alt="Raspberry Pi 5"/>
  <img src="https://img.shields.io/badge/NVR-Frigate%20%20v0.17-orange?style=flat-square&logo=openlayers&logoColor=white" alt="Frigate NVR"/>
  <img src="https://img.shields.io/badge/Proxy-Caddy-11B3E0?style=flat-square&logo=caddy&logoColor=white" alt="Caddy"/>
  <img src="https://img.shields.io/badge/AI-OpenRouter-7E00FF?style=flat-square&logo=openai&logoColor=white" alt="OpenRouter"/>
  <img src="https://img.shields.io/badge/Alerts-Telegram-26A69A?style=flat-square&logo=telegram&logoColor=white" alt="Telegram"/>
</p>

---

## About Rootcastle

Developed by Batuhan Ayrıbaş (Lead Security Architect at Rootcastle), the Rootcastle Home Watcher converts low-overhead single board computers (such as the Raspberry Pi 5) into fully hardened local NVR appliances. Combining containerized security routing, offline local camera access points, and remote AI-augmented alerts, the stack guarantees video data isolation and high-fidelity threat notifications.

For more security stacks, customer integration services, and operational support, visit:  
[www.rootcastle.com](https://www.rootcastle.com)

---

## System Architecture

The Home Watcher appliance employs a dual-interface network model to enforce zero-trust local stream isolation:

```
                                  ┌──────────────────────────────────────────────┐
                                  │             Secure WAN Link                  │
                                  └──────────────────────┬───────────────────────┘
                                                         │ (Port 10443 HTTPS Proxy)
                                                         ▼
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │ Rootcastle Appliance Stack (Host Network Mode)                                         │
  │                                                                                        │
  │   ┌──────────────────┐          ┌──────────────┐          ┌────────────────────────┐   │
  │   │   Caddy Proxy    │ ───────> │  Frigate UI  │          │  security-ai-alerts    │   │
  │   │   (Port 10443)   │          │ (Port 8971)  │          │  (Bot / Worker Daemon) │   │
  │   └──────────────────┘          └──────┬───────┘          └───────────┬────────────┘   │
  │                                        │                              │                │
  │                                        ▼                              │                │
  │                                 ┌──────────────┐                      │                │
  │                                 │ Frigate NVR  │ <────────────────────┤                │
  │                                 │ (Port 5000)  │ (HTTP API / Snap)    │                │
  │                                 └──────┬───────┘                      │                │
  │                                        │                              │                │
  │                                        ▼                              │                │
  │                                 ┌──────────────┐                      │                │
  │                                 │  Mosquitto   │ <────────────────────┘                │
  │                                 │  MQTT Broker │ (Event Topics &                       │
  │                                 │ (Port 1883)  │  PTZ Controls)                        │
  │                                 └──────────────┘                                       │
  │                                                                                        │
  │   ┌────────────────────────────────────────────────────────────────────────────────┐   │
  │   │ Local Isolated Wi-Fi AP (SSID: frigate-esp-local, Subnet 192.168.50.0/24)      │   │
  │   │ (Blocks WAN forwarding for wireless modules to preserve feed security)          │   │
  │   │                                                                                │   │
  │   │   ┌──────────────┐                                                             │   │
  │   │   │  ESP32-CAM   ├─(RTSP/MJPEG)──┐                                             │   │
  │   │   └──────────────┘               │                                             │   │
  │   │   ┌──────────────┐               │                                             │   │
  │   │   │ ESP32-S3-EYE ├─(RTSP/MJPEG)──┼─┐                                           │   │
  │   │   └──────────────┘               │ │                                           │   │
  │   │   ┌──────────────┐               │ │                                           │   │
  │   │   │ M5Stack Cam  ├─(RTSP/MJPEG)──┼─┼─┐                                         │   │
  │   │   └──────────────┘               │ │ │                                         │   │
  │   └──────────────────────────────────┼─┼─┼─────────────────────────────────────────┘   │
  │                                      ▼ ▼ ▼                                             │
  │                              (Wireless AP Streams)                                     │
  │                                      │                                                 │
  │                                      ▼                                                 │
  │   ┌────────────────────────────────────────────────────────────────────────────────┐   │
  │   │ Local Administrative Network / LAN Subnet                                      │   │
  │   │                                                                                │   │
  │   │   ┌──────────────┐                                                             │   │
  │   │   │ ONVIF Camera ├─(RTSP/ONVIF PTZ Command)──────────┐                         │   │
  │   │   └──────────────┘                                   │                         │   │
  │   │   ┌──────────────┐                                   │                         │   │
  │   │   │ XMeye DVR    ├─(H.264/H.265 RTSP streams)────────┼─┐                       │   │
  │   │   └──────────────┘                                   │ │                       │   │
  │   │   ┌──────────────┐                                   │ │                       │   │
  │   │   │ RTSP IP Cam  ├─(Hikvision/Dahua/Reolink RTSP)────┼─┼─┐                     │   │
  │   │   └──────────────┘                                   │ │ │                     │   │
  │   │   ┌──────────────┐                                   │ │ │                     │   │
  │   │   │ HTTP Webcams ├─(MJPEG / HTTP stream profiles)────┼─┼─┼─┐                   │   │
  │   │   └──────────────┘                                   │ │ │ │                   │   │
  │   └──────────────────────────────────────────────────────┼─┼─┼─┼───────────────────┘   │
  │                                                          ▼ ▼ ▼ ▼                       │
  │                                                   (Physical Network Feeds)             │
  └────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Key Capabilities and Security Hardening

### Network Isolation (Zero-Trust Camera Streams)
To block camera video feeds from leaking to the public internet:
- **eth0 (Ethernet Interface)**: Connects to the local network router for admin dashboard access and outbound notifications.
- **wlan0 (Access Point)**: Broadcasts an isolated `frigate-esp-local` SSID (`192.168.50.1`). Kernel-level `iptables` rules strictly reject forwarding packets between the AP subnet and the WAN interface, isolating the cameras.

### Intelligent Motion and AI Verification
The alert service daemon (`security-ai-alerts`) bridges physical camera streams with GenAI vision intelligence:
- **OpenCV Motion Gating**: Evaluates frames locally using a fast frame-difference threshold checking loop. Discards snapshots with no motion to conserve API tokens and billing credits.
- **Cognitive Verification**: Submits valid motion snapshots to OpenRouter Vision API (such as Gemini models) for confirmation of target labels (such as `person`, `cat`, `bird`, `dog`).
- **Telegram Outbound Alerts**: If object verification returns positive, a Telegram alert with the high-resolution snapshot is generated.

### Real-Time PTZ Control Keypad
Administrators can steer physical PTZ cameras dynamically:
- Sending the `/ptz` command generates an inline keyboard controller containing arrows and zoom options.
- Activating a direction publishes command payloads to the MQTT control topic `frigate/<camera>/ptz`.
- To prevent infinite pan drift, the daemon automatically publishes a STOP command exactly 0.5 seconds after start.
- A fresh snapshot is then fetched and refreshed inline within the bot message interface.

---

## Supported Hardware and Camera Models

The Rootcastle Home Watcher stack utilizes `go2rtc` and `ffmpeg` inside the Frigate core, enabling native compatibility with a wide range of IP-based camera hardware and wireless microcontroller modules:

### 1. Isolated Wireless Microcontroller Cameras (ESP Subnet)
These devices connect directly to the isolated `frigate-esp-local` Wi-Fi Access Point to keep video traffic localized:
- **ESP32-CAM**: Low-cost camera modules executing standard RTSP firmware or MJPEG web servers (resolving streams via local AP IP mapping, e.g. `http://192.168.50.X:80/stream`).
- **ESP32-S3-EYE**: High-performance camera module supporting higher framerates and resolutions, running RTSP or MJPEG configurations.
- **M5Stack Camera Modules (Unit Cam, M5Camera)**: ESP32-based modular camera systems running custom video streaming firmware.

### 2. Local Network Security Cameras (LAN Subnet)
These standard security cameras communicate over the local administrative LAN:
- **ONVIF Compliant Cameras**: Cameras supporting ONVIF specifications (such as PTZ cameras) for dynamic directional navigation, zoom, and preset controls.
- **XMeye / DVR Systems**: Multi-channel DVR/NVR appliances streaming H.264 or H.265 feeds via RTSP.
- **RTSP IP Cameras**: Generic IP security cameras (such as Hikvision, Dahua, Reolink, Amcrest, and TP-Link Tapo) streaming main or sub-streams natively.
- **HTTP / MJPEG Webcams**: Local HTTP-based network cams, USB webcams (reverse-proxied via local MJPEG streamers), or 3D printer cameras (such as FLSun/Creality webcam streams).

---

## Getting Started

### Prerequisites
- A target machine running Debian/Ubuntu or Raspberry Pi OS (Bookworm).
- Docker and Docker Compose installed.
- A Telegram Bot token (from `@BotFather`) and a Telegram Chat ID.
- An OpenRouter API key.

### Installation

#### Option 1: One-Command Automated Installation (Recommended)
You can automatically provision dependencies, SSL configurations, directories, and launch the stack using a single command:

```bash
# Standard installation
curl -fsSL https://raw.githubusercontent.com/rootcastleco/home-watcher/main/easy_install.sh | sudo bash

# Installation with isolated ESP32 access point configuration
curl -fsSL https://raw.githubusercontent.com/rootcastleco/home-watcher/main/easy_install.sh | sudo SETUP_ESP32_AP=true ESP_AP_PASSWORD='your-secure-ap-password' bash
```

#### Option 2: Manual Installation
Alternatively, you can manually clone the repository and execute the installer script:
```bash
git clone https://github.com/rootcastleco/home-watcher.git
cd home-watcher
sudo bash install.sh
```

### Headless PC/Laptop Server Conversion (Optional)
If you are deploying on a generic PC or Laptop running Ubuntu/Debian (instead of a pre-hardened server OS), you can convert and harden the machine into a dedicated headless surveillance server before installation:
```bash
sudo bash convert_pc_to_server.sh
```
This utility disables desktop GUI resource consumption, blocks system suspends (e.g. laptop lid closes), restricts incoming traffic via UFW firewall, and automatically provisions Docker and Git dependencies.

### Interactive Configuration Wizard
The stack features an interactive configuration form to quickly generate the required `.env` file without manual editing:
```bash
./configure.sh
```
This script runs in the terminal, prompting you for camera IPs, stream credentials, and API integration keys, validating the inputs before saving them.

3. **Configure Settings**:
   Add network IPs, keys, and tokens to your generated `/opt/frigate/.env` file:
   ```env
   # Camera IP Mappings
   FRIGATE_DVR_IP=10.0.10.10
   FRIGATE_PTZ_IP=10.0.10.20
   FRIGATE_ESP32_IP=10.0.10.30
   FRIGATE_PRINTER_IP=10.0.10.40

   # Credentials
   FRIGATE_DVR_USER=admin
   FRIGATE_DVR_PASSWORD=change-me
   FRIGATE_PTZ_USER=admin
   FRIGATE_PTZ_PASSWORD=change-me
   FRIGATE_ESP32_USER=rootcastle
   FRIGATE_ESP32_PASSWORD=change-me

   # Integration Tokens
   TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
   TELEGRAM_CHAT_ID=-100123456789
   OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxxxxxxxxxxxx
   ```

4. **Launch services**:
   ```bash
   cd /opt/frigate
   sudo docker compose up -d
   ```

---

## Interactive Bot Console Commands

Authorized users can interact with the system via direct Telegram messages:

| Command | Args | Description |
|:---|:---|:---|
| `/status` | — | Returns appliance uptime, resource usage, queue status, and active muting states. |
| `/cameras` | — | Lists camera streams, health states, and mute cooldown parameters. |
| `/snapshot` | `<camera>` | Requests a high-resolution snapshot from the specified camera. |
| `/pause` | `<camera> <min>`| Temporarily silences notifications for the specified camera (e.g. `/pause ofis 30`). |
| `/resume` | `<camera>` | Instantly restores notification routing for the camera. |
| `/ptz` | — | Spawns the interactive directional Arrow Keypad and zoom interface. |

---

## File Architecture

```
├── README.md                      # Premium system documentation
├── docker-compose.yml             # Containerized services orchestrator
├── install_frigate_raspberry_pi.sh # System stack deployment & cert provisioner
├── repository-metadata.json       # Repository metadata manifest
├── caddy/
│   └── Caddyfile                  # Caddy reverse proxy rules
├── config/
│   ├── config.yml                 # NVR config and camera streams
│   └── rtsp_nginx_append.conf     # RTSP parameters
├── mosquitto/
│   └── mosquitto.conf             # MQTT message broker rules
├── scripts/
│   └── setup_esp32_ap.sh          # Network segregation shell script
├── docs/
│   └── mil-std-498/               # MIL-STD-498 Design Document Set
│       ├── SRS.md                 # Software Requirements Specification
│       ├── SDD.md                 # Software Design Description
│       ├── SVD.md                 # Software Version Description
│       └── SUM.md                 # Software User Manual
└── security-ai-alerts/            # Custom alert processing daemon
    ├── app.py                     # Main alert daemon logic
    ├── Dockerfile                 # Docker building description
    └── requirements.txt           # Python dependency lists
```

---

## MIL-STD-498 Compliance
This codebase is developed and packaged in accordance with MIL-STD-498 (Military Standard for Software Development and Documentation) guidelines to ensure robust configuration management, traceable design decisions, and strict boundary isolation. Architectural specification matrices can be referenced under [docs/mil-std-498/](file:///Users/mac/Downloads/frigate-main/docs/mil-std-498).

---

## Author and Maintainer

- **Batuhan Ayrıbaş** — *Lead Security Architect* — [rootcastleco](https://github.com/rootcastleco)
- **Website**: [www.rootcastle.com](https://www.rootcastle.com)
- **Enquiries**: admin@rootcastle.com

---
<p align="center">
  <small>© 2026 Rootcastle. All rights reserved. Hardened private surveillance stacks.</small>
</p>
