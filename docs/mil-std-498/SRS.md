# Software Requirements Specification (SRS)
## for Rootcastle Home Watcher Stack

**Document Identifier**: RC-HW-SRS-V1.2.0  
**Version**: 1.2.0  
**Date**: 2026-06-15  
**Security Classification**: UNCLASSIFIED  
**Branding**: Rootcastle Security (https://www.rootcastle.com)

---

### 1. Scope

#### 1.1 Identification
This document establishes the Software Requirements Specification (SRS) for the **Rootcastle Home Watcher Stack**, Version 1.2.0, a hardened, local-first intelligent video surveillance and AI alert security appliance.

#### 1.2 System Overview
The Rootcastle Home Watcher Stack is designed to convert standard low-cost hardware (such as the Raspberry Pi 5) into a secure, private NVR security hub. The system integrates the following core software items (SIs):
1. **Frigate NVR**: Coordinates video feed ingestion, local recording, object tracking, and user-facing dashboards.
2. **Mosquitto MQTT Broker**: Facilitates message broker communication and control topic routing.
3. **security-ai-alerts**: Serves as the intelligent alert verification worker and interactive Telegram interface daemon.
4. **Caddy HTTPS Proxy**: Hardens local network endpoints with SSL/TLS termination and reverse proxies the user interface.

#### 1.3 Document Overview
This document specifies the software requirements to be satisfied by the Rootcastle Home Watcher system. It details functional requirements, external interface requirements, security and privacy constraints, and verification qualification provisions.

---

### 2. Referenced Documents

- **MIL-STD-498**: Military Standard, Software Development and Documentation, December 5, 1994.
- **Rootcastle SDD**: Software Design Description for Rootcastle Home Watcher Stack.
- **Frigate Documentation**: https://docs.frigate.video
- **OpenRouter Multimodal API Guideline**: https://openrouter.ai/docs

---

### 3. Requirements

#### 3.1 State and Mode Requirements
The system shall operate in two primary modes:
- **Initialization Mode**: Auto-provisions environment templates, generates self-signed TLS certificates for local domain/IP, configures network routing tables, and builds local container assets.
- **Operational Mode**: Ingests video feeds, monitors MQTT trigger topics, processes OpenCV motion difference evaluations, performs AI vision verification calls, routes Telegram alerts, and listens for interactive administrator commands.

#### 3.2 Capability Requirements

##### 3.2.1 Secure Network AP Isolation (Zero-Trust Local Stream)
- The system shall broadcast a local Wi-Fi Access Point (SSID: `frigate-esp-local`) on subnet `192.168.50.0/24` for wireless camera streams (e.g., ESP32-CAM).
- The system shall implement kernel-level routing blocks via `iptables` to strictly deny forwarding of packets from the local AP interface (`wlan0` or equivalent) to the WAN interface (`eth0` or equivalent).
- The local AP DHCP server shall not advertise a gateway route (`dhcp-option=3,0.0.0.0`) to client devices to ensure camera feeds remain entirely isolated.

##### 3.2.2 OpenCV Motion Gating
- The `security-ai-alerts` daemon shall poll low-resolution snapshot frames from enabled Frigate cameras.
- The daemon shall perform frame-difference calculations on subsequent frames.
- If the calculated motion pixel difference does not exceed the configurable threshold (`ALERT_MOTION_PIXEL_RATIO`), the frame shall be discarded to prevent unnecessary API utilization.

##### 3.2.3 Cognitive Vision Verification
- For frames passing the motion gate, the system shall execute an asynchronous vision query to OpenRouter API using configured models (e.g., Google Gemini 2.0 Flash).
- The prompt shall require the model to identify target labels (default: `person`, `cat`, `bird`, `dog`).
- The system shall only trigger Telegram notifications if the AI model confirms a positive detection.

##### 3.2.4 Interactive Bot Console Interface
- The system shall host an interactive Telegram polling listener to process administrator commands.
- The system shall support the following console commands:
  - `/status`: Query system health, uptime, memory, queue, and muting states.
  - `/cameras`: Query status, cooldown metrics, and pause intervals for all cameras.
  - `/snapshot <name>`: Request a live, high-resolution snapshot.
  - `/pause <name> <min>`: Temporarily mute notifications for the selected camera.
  - `/resume <name>`: Instantly unmute notifications.
  - `/ptz`: Open the interactive Pan-Tilt-Zoom interface.

##### 3.2.5 Real-Time Pan-Tilt-Zoom (PTZ) Control
- The `/ptz` interface shall generate an inline arrow pad (Up, Down, Left, Right, Stop, Zoom In/Out).
- Clicking a directional button shall publish command payloads to the MQTT topic `frigate/<camera>/ptz`.
- To prevent camera drift, the daemon shall automatically publish a `STOP` command exactly **`0.5 seconds`** after any directional start command.
- The system shall capture a fresh frame post-movement and refresh the inline dashboard snapshot.

#### 3.3 External Interface Requirements
- **Video Ingestion Interface**: RTSP/HTTP MJPEG streams from network cameras.
- **MQTT Message Protocol**: Ingestion of events on topic `{prefix}/events` and publishing of PTZ control payloads on `{prefix}/{camera}/ptz`.
- **Telegram Bot API**: Outbound HTTP POST payloads with media bytes for alerts and inbound polling for admin queries.
- **OpenRouter Vision API**: Outbound HTTPS payloads containing base64 encoded JPEG frames and model selection headers.

#### 3.4 Security and Privacy Requirements
- **No Hardcoded Credentials**: All passwords, API tokens, chat identifiers, and network IPs must be configured dynamically via the `/opt/frigate/.env` file. No real secrets shall be stored in repository configurations.
- **TLS Hardening**: External ingress to the Frigate dashboard must be reverse-proxied through Caddy on port `10443` using TLS 1.3 encryption. Direct access to the internal Frigate port `5000` must be restricted.

---

### 4. Qualification Provisions

| Requirement Section | Description | Verification Method |
|:---|:---|:---:|
| **3.2.1** | Network AP Isolation | Verification of iptables REJECT rules and AP routing table |
| **3.2.2** | OpenCV Motion Gating | Log observation of frame-diff checks and CPU utilization |
| **3.2.3** | Vision Verification | Testing with positive/negative sample frames via OpenRouter |
| **3.2.4** | Interactive Bot Console | Manual execution of commands via authorized Telegram chat |
| **3.2.5** | Real-Time PTZ | Ingestion of PTZ stop command check via MQTT client |
| **3.4** | Security & Privacy | Scanning codebase for hardcoded secrets and verifying TLS proxy |
