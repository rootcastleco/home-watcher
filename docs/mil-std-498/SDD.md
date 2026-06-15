# Software Design Description (SDD)
## for Rootcastle Home Watcher Stack

**Document Identifier**: RC-HW-SDD-V1.2.0  
**Version**: 1.2.0  
**Date**: 2026-06-15  
**Security Classification**: UNCLASSIFIED  
**Branding**: Rootcastle Security (https://www.rootcastle.com)

---

### 1. Scope

#### 1.1 Identification
This document establishes the Software Design Description (SDD) for the **Rootcastle Home Watcher Stack**, Version 1.2.0.

#### 1.2 System Overview
The system provides a hardened, local-first NVR surveillance appliance utilizing containerized microservices. The design targets low-overhead, zero-trust network segregation for wireless security cameras, motion-gated AI event validation, and interactive Telegram control.

#### 1.3 Document Overview
This document describes the high-level architecture and detailed design of the system's software items (SIs), including execution control, data flows, and database designs.

---

### 2. Design Decision History

- **Host Network Mode Selection**: To support high-throughput, low-latency video streaming (via WebRTC and RTSP) and allow Caddy to proxy traffic directly to Frigate's loopback interface, all core services (`frigate`, `security-ai-alerts`, `frigate-proxy`) run in Docker `host` network mode.
- **Local Motion Pre-Gating**: To avoid cost and latency overhead of continuous AI vision calls, a local OpenCV frame-difference algorithm executes before invoking the OpenRouter API.
- **Isolated ESP32 AP**: Designed to isolate wireless cameras (like ESP32-CAM) from the local WAN network to ensure camera feeds cannot leak externally.

---

### 3. Architectural Design

#### 3.1 Software Items (SIs) and Containers
The system comprises four major containerized items managed by Docker Compose:

1. **`frigate`**: Real-time NVR and object tracking. Runs BLAKE Blackshear's Frigate container.
2. **`frigate-mqtt`**: Eclipse Mosquitto MQTT message broker. Processes event topics and controls.
3. **`security-ai-alerts`**: Custom Python application containing the MQTT alert queue and OpenRouter client.
4. **`frigate-proxy`**: Caddy Alpine container serving as the HTTPS ingress controller.

```
       [Client Browsers / WAN Ingress]
                     │ (TCP 10443)
                     ▼
      ┌──────────────────────────────┐
      │         Caddy Proxy          │
      └──────────────┬───────────────┘
                     │ (TCP 8971 - localhost)
                     ▼
      ┌──────────────────────────────┐
      │         Frigate UI           │
      └──────────────┬───────────────┘
                     │ (RTSP / HTTP MJPEG)
                     ▼
  [Isolated cameras on wlan0] / [DVR on eth0]
```

#### 3.2 Network Subsystem Topology
The host system establishes two network zones:
- **Zone 1: Local WAN (`eth0`)**: Connects the appliance to the administrative LAN and WAN gateway. Facilitates outbound API requests to Telegram and OpenRouter.
- **Zone 2: Isolated AP (`wlan0`)**: Broadcasts the private `frigate-esp-local` wireless network. Routing tables drop all forwarding traffic from `wlan0` to `eth0`.

---

### 4. Detailed Design

#### 4.1 Caddy Reverse Proxy (`caddy/Caddyfile`)
Caddy listens on host port `10443` and terminates TLS 1.3. It proxies traffic to the local Frigate dashboard on `127.0.0.1:8971` while skipping insecure TLS verification (since Frigate uses self-signed keys internally). It uses Gzip and Zstd compression.

#### 4.2 Mosquitto Broker Configuration (`mosquitto/mosquitto.conf`)
The broker listens on port `1883` on all interfaces. Anonymous connections are allowed internally. Data persistence is set to `/mosquitto/data/`.

#### 4.3 custom AI Alert Daemon (`security-ai-alerts/app.py`)
The Python daemon consists of three primary threads:
1. **MQTT Client Thread**: Connects to the local Mosquitto broker, subscribes to `frigate/events`, and parses incoming JSON payloads. Valid events are loaded into a FIFO event queue.
2. **Alert Processor Loop (Asyncio)**:
   - Polls events from the queue.
   - Verifies camera configuration and check-cooldown timers.
   - Executes frame-difference motion calculations using OpenCV.
   - Translates base64 snapshots and issues OpenRouter vision prompts.
   - Broad-casts positive results to configured Telegram chats.
3. **Interactive Telegram Bot Listener**: Periodically polls `getUpdates` or runs a webhook listener to process admin commands, publishes PTZ controls to `frigate/<camera>/ptz`, and updates inline message layouts.

#### 4.4 State Management and Database Design
The alert daemon implements the `StateManager` class which writes configurations to a JSON file at `/app/state/state.json`:
- **Structure**:
  ```json
  {
    "muted_cameras": {
      "camera_name": "ISO_timestamp_until_which_muted"
    },
    "cooldowns": {
      "camera_name": 90
    }
  }
  ```
- **Operations**: Atomic write operations utilizing temporary files (`state.json.tmp`) renamed via `os.replace` to prevent database corruption during power loss.
