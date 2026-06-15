"""
================================================================================
MIL-STD-498 SOFTWARE DESIGN DESCRIPTION (SDD) & SOFTWARE VERSION DESCRIPTION (SVD)
================================================================================
SYSTEM:             Frigate Pi Security Stack
SOFTWARE ITEM:      security-ai-alerts
VERSION:            1.2.0
DATE:               2026-06-04
SECURITY CLASSIF:   UNCLASSIFIED
DISTRIBUTION:       RESTRICTED TO SYSTEM OWNER

SYSTEM DESCRIPTION:
  This Software Configuration Item (SCI) serves as the primary alert processing
  and notification engine for the Frigate-based surveillance stack. It consumes
  asynchronous MQTT event streams published by the Frigate detection engine,
  applies user-configured filters and cooldown constraints, queries AI analysis for
  object verification, and broadcasts alert media to multiple destination Telegram
  recipients concurrently.

ARCHITECTURAL OVERVIEW:
  - Input Layer: Paho MQTT client executing in a dedicated worker thread, forwarding
    payloads to an asynchronous event loop queue. Supports resilient backoff reconnect.
  - Processing Layer: Async event worker routing events based on status changes.
  - State Layer: StateManager implementing atomic JSON-file persistence for alert state.
  - Diagnostics: HealthServer HTTP server exposing a REST endpoint on port 8082.
  - Output Layer: Parallel HTTP request scheduling utilizing asyncio.gather.
================================================================================
"""

from __future__ import annotations

import asyncio
import base64
import http.server
import json
import logging
import os
import re
import signal
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import cv2
import httpx
import numpy as np
import paho.mqtt.client as mqtt

# Configure system-wide logging with formal trace format
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("security-ai-alerts")
logging.getLogger("httpx").setLevel(logging.WARNING)


class ConfigurationError(Exception):
    """Raised when configuration variables fail strict schema validation constraints."""
    pass


def env_float(name: str, default: float) -> float:
    """
    Retrieve environment variable as float with safe default fallback.
    
    Inputs:
      name: str - The name of the environment variable.
      default: float - Fallback value if variable is missing or invalid.
    Outputs:
      float - Resolved parameter value.
    """
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def env_int(name: str, default: int) -> int:
    """
    Retrieve environment variable as integer with safe default fallback.
    
    Inputs:
      name: str - The name of the environment variable.
      default: int - Fallback value if variable is missing or invalid.
    Outputs:
      int - Resolved parameter value.
    """
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def split_csv(value: str) -> List[str]:
    """
    Parse a comma-separated values string into a cleaned list of strings.
    
    Inputs:
      value: str - Raw comma-separated string.
    Outputs:
      List[str] - List of stripped non-empty string components.
    """
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    """
    Configuration Settings Dataclass representing the system's operational parameters.
    Performs strict schema validation upon initialization.
    """
    frigate_api_url: str = os.getenv("FRIGATE_API_URL", "http://127.0.0.1:5000").rstrip("/")
    mqtt_host: str = os.getenv("MQTT_HOST", "127.0.0.1")
    mqtt_port: int = env_int("MQTT_PORT", 1883)
    mqtt_topic: str = os.getenv("MQTT_TOPIC", "frigate/events")
    openrouter_api_key: str = os.getenv("OPENROUTER_API_KEY", "")
    openrouter_model: str = os.getenv("OPENROUTER_MODEL", "openrouter/free")
    openrouter_site_url: str = os.getenv("OPENROUTER_SITE_URL", "https://localhost:10443")
    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_ids: Tuple[str, ...] = tuple(split_csv(os.getenv("TELEGRAM_CHAT_ID", "")))
    cameras: Tuple[str, ...] = tuple(split_csv(os.getenv("ALERT_CAMERAS", "ofis,giris_1,giris_2,ptz_dis,esp32_ofis")))
    office_cameras: Tuple[str, ...] = tuple(split_csv(os.getenv("ALERT_OFFICE_CAMERAS", "ofis,esp32_ofis")))
    cooldown_seconds: int = env_int("ALERT_COOLDOWN_SECONDS", 90)
    office_cooldown_seconds: int = env_int("ALERT_OFFICE_COOLDOWN_SECONDS", 60)
    rate_limit_backoff_seconds: int = env_int("ALERT_RATE_LIMIT_BACKOFF_SECONDS", 600)
    http_timeout_seconds: float = env_float("ALERT_HTTP_TIMEOUT_SECONDS", 15.0)
    state_file_path: str = os.getenv("STATE_FILE_PATH", "/app/state/state.json")
    health_port: int = env_int("HEALTH_PORT", 8089)
    alert_labels: Tuple[str, ...] = tuple(split_csv(os.getenv("ALERT_LABELS", "person,cat,bird,dog")))
    frigate_external_url: str = os.getenv("FRIGATE_EXTERNAL_URL", "")
    telegram_polling_enabled: bool = os.getenv("TELEGRAM_POLLING_ENABLED", "true").lower() == "true"
    printer_enabled: bool = os.getenv("PRINTER_ENABLED", "true").lower() == "true"
    printer_snapshot_url: str = os.getenv("PRINTER_SNAPSHOT_URL", "http://localhost/webcam/?action=snapshot")
    printer_check_interval: int = env_int("PRINTER_CHECK_INTERVAL_SECONDS", 20)
    printer_movement_threshold_pct: float = env_float("PRINTER_MOVEMENT_THRESHOLD_PCT", 0.5)

    def validate(self) -> None:
        """
        Validate all operational parameters against formal software requirements.
        Raises ConfigurationError upon validation failure.
        """
        if not self.frigate_api_url.startswith(("http://", "https://")):
            raise ConfigurationError(f"FRIGATE_API_URL must start with http/https protocols: {self.frigate_api_url}")
        
        if not self.mqtt_host:
            raise ConfigurationError("MQTT_HOST cannot be empty.")
        
        if not (1 <= self.mqtt_port <= 65535):
            raise ConfigurationError(f"MQTT_PORT out of range: {self.mqtt_port}")

        if not self.telegram_bot_token:
            raise ConfigurationError("TELEGRAM_BOT_TOKEN cannot be empty.")
            
        if not re.match(r"^\d+:[A-Za-z0-9_-]+$", self.telegram_bot_token):
            raise ConfigurationError("TELEGRAM_BOT_TOKEN fails standard Telegram Bot API token formatting regex.")

        if not self.telegram_chat_ids:
            raise ConfigurationError("TELEGRAM_CHAT_ID must contain at least one valid chat ID target.")
            
        for cid in self.telegram_chat_ids:
            if not re.match(r"^-?\d+$", cid):
                raise ConfigurationError(f"Invalid Telegram Chat ID format: {cid}")

        if self.cooldown_seconds < 0:
            raise ConfigurationError("ALERT_COOLDOWN_SECONDS must be a non-negative integer.")

        if self.office_cooldown_seconds < 0:
            raise ConfigurationError("ALERT_OFFICE_COOLDOWN_SECONDS must be a non-negative integer.")

        if self.rate_limit_backoff_seconds <= 0:
            raise ConfigurationError("ALERT_RATE_LIMIT_BACKOFF_SECONDS must be a positive integer.")

        if self.http_timeout_seconds <= 0.0:
            raise ConfigurationError("ALERT_HTTP_TIMEOUT_SECONDS must be a positive float.")

        if not self.alert_labels:
            raise ConfigurationError("ALERT_LABELS must contain at least one valid object label.")

        if self.frigate_external_url and not self.frigate_external_url.startswith(("http://", "https://")):
            raise ConfigurationError(f"FRIGATE_EXTERNAL_URL must start with http/https protocols: {self.frigate_external_url}")

        if self.printer_enabled and not self.printer_snapshot_url.startswith(("http://", "https://")):
            raise ConfigurationError(f"PRINTER_SNAPSHOT_URL must start with http/https protocols: {self.printer_snapshot_url}")
        
        if self.printer_check_interval <= 0:
            raise ConfigurationError("PRINTER_CHECK_INTERVAL_SECONDS must be a positive integer.")
            
        if self.printer_movement_threshold_pct < 0.0:
            raise ConfigurationError("PRINTER_MOVEMENT_THRESHOLD_PCT must be a non-negative float.")


class StateManager:
    """
    [REQ-080-STATE-PERSISTENCE]
    Implements atomic, thread-safe JSON serialization to persist alert states
    (cooldown timestamps and active event state matrices) across system restarts.
    """

    def __init__(self, file_path: str) -> None:
        """
        Initialize the StateManager.
        
        Inputs:
          file_path: str - Path to the persistent JSON state file.
        """
        self.file_path = file_path
        self._lock = threading.Lock()

    def load_state(self) -> Tuple[Dict[str, float], Dict[str, Dict[str, Any]], Dict[str, float], Dict[str, int], List[Dict[str, Any]], str]:
        """
        Load the stored state from the JSON file on disk.
        
        Outputs:
          Tuple[Dict[str, float], Dict[str, Dict[str, Any]], Dict[str, float], Dict[str, int], List[Dict[str, Any]], str] - Resolved state maps and variables.
        """
        with self._lock:
            if not os.path.exists(self.file_path):
                return {}, {}, {}, {}, [], ""
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    last_alert_at = data.get("last_alert_at", {})
                    active_events = data.get("active_events", {})
                    camera_mutes = data.get("camera_mutes", {})
                    dynamic_cooldowns = data.get("dynamic_cooldowns", {})
                    event_log = data.get("event_log", [])
                    last_summary_date = data.get("last_summary_date", "")
                    
                    # Ensure timestamps and parameters are loaded correctly
                    last_alert_at = {k: float(v) for k, v in last_alert_at.items()}
                    camera_mutes = {k: float(v) for k, v in camera_mutes.items()}
                    dynamic_cooldowns = {k: int(v) for k, v in dynamic_cooldowns.items()}
                    if not isinstance(event_log, list):
                        event_log = []
                    
                    logger.info("StateManager loaded state successfully. last_alerts=%d active_events=%d camera_mutes=%d event_log=%d", len(last_alert_at), len(active_events), len(camera_mutes), len(event_log))
                    return last_alert_at, active_events, camera_mutes, dynamic_cooldowns, event_log, last_summary_date
            except Exception as exc:
                logger.error("state_load_failed error=%s. Starting with clean state.", exc)
                return {}, {}, {}, {}, [], ""

    def save_state(
        self,
        last_alert_at: Dict[str, float],
        active_events: Dict[str, Dict[str, Any]],
        camera_mutes: Dict[str, float],
        dynamic_cooldowns: Dict[str, int],
        event_log: List[Dict[str, Any]],
        last_summary_date: str,
    ) -> None:
        """
        Write state variables to disk atomically.
        
        Inputs:
          last_alert_at: Dict[str, float] - Camera cooldown map.
          active_events: Dict[str, Dict[str, Any]] - Active detection events mapping.
          camera_mutes: Dict[str, float] - Camera mute/pause expiration timestamps.
          dynamic_cooldowns: Dict[str, int] - Dynamic camera cooldown overrides.
          event_log: List[Dict[str, Any]] - Saved daily events log.
          last_summary_date: str - Last date daily summary was sent.
        """
        with self._lock:
            temp_path = self.file_path + ".tmp"
            try:
                # Ensure directory structure exists
                dir_name = os.path.dirname(self.file_path)
                if dir_name:
                    os.makedirs(dir_name, exist_ok=True)
                
                payload = {
                    "last_alert_at": last_alert_at,
                    "active_events": active_events,
                    "camera_mutes": camera_mutes,
                    "dynamic_cooldowns": dynamic_cooldowns,
                    "event_log": event_log,
                    "last_summary_date": last_summary_date,
                    "updated_at": time.time(),
                }
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                
                # Atomic filesystem rename replaces target file safely
                os.replace(temp_path, self.file_path)
            except Exception as exc:
                logger.error("state_save_failed error=%s", exc)
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass


class HealthHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler executing within the diagnostic thread pool."""
    
    def log_message(self, format: str, *args: Any) -> None:
        """Supress default console stdout reporting to keep logs clean."""
        pass

    def do_GET(self) -> None:
        """Handle GET requests. Serves JSON details on /health endpoint."""
        if self.path == "/health":
            try:
                status = self.server.get_status_callback()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(json.dumps(status).encode("utf-8"))
            except Exception as exc:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(exc).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


class HealthServer:
    """
    [REQ-090-HEALTH-PROBE]
    Exposes a lightweight REST HTTP server running on a daemon thread
    to allow container engine liveness and readiness monitoring.
    """

    def __init__(self, get_status_callback, port: int) -> None:
        """
        Initialize the HealthServer.
        
        Inputs:
          get_status_callback: Callable - Returns status statistics.
          port: int - HTTP socket port configuration.
        """
        self.port = port
        self.get_status_callback = get_status_callback
        self.httpd: Optional[http.server.HTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the HTTP daemon thread."""
        try:
            self.httpd = http.server.HTTPServer(("0.0.0.0", self.port), HealthHandler)
            self.httpd.get_status_callback = self.get_status_callback
            self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self.thread.start()
            logger.info("Diagnostics health check server started on port %d", self.port)
        except Exception as exc:
            logger.error("health_server_init_failed error=%s", exc)

    def stop(self) -> None:
        """Stop and teardown the HTTP daemon cleanly."""
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
                logger.info("Diagnostics health check server stopped.")
            except Exception as exc:
                logger.error("health_server_stop_failed error=%s", exc)


class AlertService:
    """
    Central service manager handling MQTT event routing, AI visual validation,
    cooldown management, and parallelized multi-target Telegram alert delivery.
    """

    def __init__(self, settings: Settings) -> None:
        """
        Initialize the AlertService instance.
        
        Inputs:
          settings: Settings - The validated configuration settings instance.
        """
        self.settings = settings
        self.state_manager = StateManager(settings.state_file_path)
        
        # Load state from disk or fall back to empty maps
        self.last_alert_at, self.active_events, self.camera_mutes, self.dynamic_cooldowns, self.event_log, self.last_summary_date = self.state_manager.load_state()
        
        self.openrouter_pause_until: float = 0.0
        self.event_lock = asyncio.Lock()
        self.start_time: float = time.time()
        self.mqtt_connected: bool = False
        self.last_event_received_at: float = 0.0
        self.notifications_sent_count: int = 0
        
        # Diagnostics setup
        self.health_server = HealthServer(self.get_diagnostics_status, settings.health_port)
        self.mqtt_client: Optional[mqtt.Client] = None
        self.is_shutting_down: bool = False

    def get_diagnostics_status(self) -> Dict[str, Any]:
        """
        Retrieve diagnostic status information for the health endpoint.
        
        Outputs:
          Dict[str, Any] - Operational stats mapping.
        """
        return {
            "status": "healthy",
            "uptime_seconds": int(time.time() - self.start_time),
            "mqtt_connected": self.mqtt_connected,
            "last_event_received_at": datetime.fromtimestamp(self.last_event_received_at).isoformat() if self.last_event_received_at else None,
            "active_events_count": len(self.active_events),
            "notifications_sent_count": self.notifications_sent_count,
            "openrouter_paused": time.time() < self.openrouter_pause_until,
            "openrouter_paused_seconds_remaining": max(0, int(self.openrouter_pause_until - time.time())),
            "timestamp": datetime.now().isoformat(),
        }

    async def run(self) -> None:
        """
        Start the service daemon loop. Sets up the MQTT thread handler, connects,
        subscribes to topics, and processes event data from the queue asynchronously.
        
        Preconditions:
          Settings must be validated and correct.
        Postconditions:
          Infinite daemon loop runs processing events.
        Exceptions:
          Propagates fatal loop exceptions or reconnects on network failure.
        """
        # Validate settings before run
        self.settings.validate()

        if not self.settings.openrouter_api_key:
            logger.warning("OPENROUTER_API_KEY is empty; direct labels will be used without AI-augmented analysis.")

        # Start health check server
        self.health_server.start()

        # Start Telegram polling loop if enabled
        if self.settings.telegram_polling_enabled and self.settings.telegram_bot_token:
            asyncio.create_task(self.telegram_polling_loop())

        # Start Daily AI summary scheduler
        asyncio.create_task(self.daily_summary_scheduler())

        # Start FLSun T1 3D Printer Monitor
        if self.settings.printer_enabled:
            asyncio.create_task(self.printer_monitoring_loop())

        # [REQ-100-GRACEFUL-SHUTDOWN] Register system signal handlers for clean exit
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.shutdown(s)))
            except NotImplementedError:
                # Fallback for platforms without add_signal_handler
                pass

        # [REQ-020-MQTT-QUEUE] Async queue to safely decouple MQTT reception from processing thread
        queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()

        def on_message(client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
            try:
                self.last_event_received_at = time.time()
                payload = json.loads(msg.payload.decode("utf-8"))
                loop.call_soon_threadsafe(queue.put_nowait, payload)
            except Exception as exc:
                logger.error("mqtt_parse_error error=%s", exc)

        def on_connect(client: mqtt.Client, userdata: Any, flags: Any, rc: int) -> None:
            if rc == 0:
                logger.info("Successfully connected to MQTT broker.")
                self.mqtt_connected = True
                client.subscribe(self.settings.mqtt_topic)
            else:
                logger.error("MQTT connection rejected with code=%d", rc)
                self.mqtt_connected = False

        def on_disconnect(client: mqtt.Client, userdata: Any, rc: int) -> None:
            logger.warning("MQTT broker disconnected. rc=%d", rc)
            self.mqtt_connected = False

        # Initialize native Paho MQTT Client
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = on_message
        self.mqtt_client.on_connect = on_connect
        self.mqtt_client.on_disconnect = on_disconnect
        
        # [REQ-110-RESILIENT-MQTT] Resilient MQTT connection retry loop with exponential backoff
        backoff = 1.0
        while not self.is_shutting_down:
            try:
                logger.info("Connecting to MQTT broker at %s:%d (backoff=%.1fs)", self.settings.mqtt_host, self.settings.mqtt_port, backoff)
                self.mqtt_client.connect(self.settings.mqtt_host, self.settings.mqtt_port, 60)
                break
            except Exception as exc:
                logger.error("mqtt_connect_failed error=%s. Retrying...", exc)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)

        if self.is_shutting_down:
            return

        self.mqtt_client.loop_start()
        
        async with httpx.AsyncClient(timeout=self.settings.http_timeout_seconds) as client:
            while not self.is_shutting_down:
                try:
                    event_data = await queue.get()
                    asyncio.create_task(self.process_event(client, event_data))
                    queue.task_done()
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.error("main_loop_error error=%s", exc, exc_info=True)
                    await asyncio.sleep(1)

    async def process_event(self, client: httpx.AsyncClient, data: Dict[str, Any]) -> None:
        """
        Process a single MQTT event payload. Routes based on state machine ("new", "update", "end").
        
        Inputs:
          client: httpx.AsyncClient - HTTP client to perform API queries.
          data: Dict[str, Any] - Raw event payload.
        """
        event_type = data.get("type", "")
        before = data.get("before") or {}
        after = data.get("after") or {}
        event_id = after.get("id") or before.get("id")

        if not event_id:
            return

        camera = after.get("camera") or before.get("camera", "")
        label = after.get("label") or before.get("label", "")
        score = after.get("top_score") or before.get("top_score", 0.0)

        # [REQ-030-ALERT-FILTER] Camera and configurable object class checks
        if camera not in self.settings.cameras:
            return
        if label not in self.settings.alert_labels:
            return

        # Check if camera is temporarily muted by a command
        now = time.time()
        if now < self.camera_mutes.get(camera, 0.0):
            logger.debug("camera_muted camera=%s event_id=%s", camera, event_id)
            return

        async with self.event_lock:
            if event_id not in self.active_events:
                self.active_events[event_id] = {
                    "snapshot_sent": False,
                    "clip_sent": False,
                    "camera": camera,
                    "label": label,
                    "score": score,
                    "created_at": time.time(),
                }
                # Sync active events state change to disk
                self.state_manager.save_state(self.last_alert_at, self.active_events, self.camera_mutes, self.dynamic_cooldowns, self.event_log, self.last_summary_date)
            event_state = self.active_events[event_id]

        # 1. Handle snapshot alert (during new or update event)
        if event_type in ("new", "update") and not event_state["snapshot_sent"]:
            has_snapshot = after.get("has_snapshot", False)
            if has_snapshot:
                # [REQ-040-ALERT-COOLDOWN] Check camera-specific cooldown validation
                cooldown = self.cooldown_for(camera)
                if now - self.last_alert_at.get(camera, 0) < cooldown:
                    logger.debug("cooldown_active camera=%s event_id=%s", camera, event_id)
                    return

                # Check lock and set processing flag to prevent concurrent snapshot alerts for the same event
                async with self.event_lock:
                    if event_state.get("snapshot_processing", False) or event_state["snapshot_sent"]:
                        return
                    event_state["snapshot_processing"] = True

                try:
                    logger.info("new_detection camera=%s label=%s score=%.2f event_id=%s", camera, label, score, event_id)
                    
                    snapshot_bytes = await self.fetch_snapshot(client, event_id)
                    if snapshot_bytes:
                        label_tr = {"person": "İnsan", "cat": "Kedi", "bird": "Kuş", "dog": "Köpek"}.get(label, label)
                        description = f"Algılama: {label_tr} ({score:.0%})"
                        
                        # [REQ-050-AI-ANALYSIS] Safe snapshot analysis via OpenRouter API with backoff mechanism
                        if self.settings.openrouter_api_key and now >= self.openrouter_pause_until:
                            ai_verdict = await self.ask_openrouter(client, camera, snapshot_bytes, label)
                            if ai_verdict.get("description"):
                                description = ai_verdict["description"]

                        # [REQ-060-TELEGRAM-PARALLEL] Send snapshot to Telegram Chat IDs in parallel
                        await self.send_telegram_photo(client, camera, snapshot_bytes, label, score, description, event_id)
                        
                        async with self.event_lock:
                            event_state["snapshot_sent"] = True
                            event_state["snapshot_processing"] = False
                            self.last_alert_at[camera] = now
                            self.event_log.append({
                                "timestamp": now,
                                "camera": camera,
                                "label": label,
                                "score": score,
                                "description": description
                            })
                            # Persist updated cooldowns and event state to disk
                            self.state_manager.save_state(self.last_alert_at, self.active_events, self.camera_mutes, self.dynamic_cooldowns, self.event_log, self.last_summary_date)
                    else:
                        # Fetch failed, reset processing flag so it can be retried on next update
                        async with self.event_lock:
                            event_state["snapshot_processing"] = False
                except Exception as exc:
                    logger.error("error processing snapshot camera=%s event_id=%s error=%s", camera, event_id, exc)
                    async with self.event_lock:
                        event_state["snapshot_processing"] = False

        # 2. Handle video clip alert (when event ends)
        elif event_type == "end":
            has_clip = after.get("has_clip", False)
            snapshot_sent = event_state["snapshot_sent"]
            
            if snapshot_sent and has_clip and not event_state["clip_sent"]:
                # Grace period to guarantee Frigate finishes writing the media clip file
                await asyncio.sleep(4.0)
                
                logger.info("fetching_clip camera=%s event_id=%s", camera, event_id)
                clip_bytes = await self.fetch_clip(client, event_id)
                if clip_bytes:
                    # [REQ-060-TELEGRAM-PARALLEL] Send video clip to Telegram Chat IDs in parallel
                    await self.send_telegram_video(client, camera, label, clip_bytes, event_id)
                    async with self.event_lock:
                        event_state["clip_sent"] = True
                        # Persist status change
                        self.state_manager.save_state(self.last_alert_at, self.active_events, self.camera_mutes, self.dynamic_cooldowns, self.event_log, self.last_summary_date)

            # Purge completed active event state
            async with self.event_lock:
                self.active_events.pop(event_id, None)
                # Persist updated mapping
                self.state_manager.save_state(self.last_alert_at, self.active_events, self.camera_mutes, self.dynamic_cooldowns, self.event_log, self.last_summary_date)

    async def fetch_snapshot(self, client: httpx.AsyncClient, event_id: str) -> Optional[bytes]:
        """
        Query Frigate API to fetch event snapshot with bounding boxes.
        
        Inputs:
          client: httpx.AsyncClient - HTTP client.
          event_id: str - Unique Frigate event identifier.
        Outputs:
          Optional[bytes] - Raw JPEG bytes if query succeeds, otherwise None.
        """
        url = f"{self.settings.frigate_api_url}/api/events/{event_id}/snapshot.jpg"
        params = {"bbox": 1, "cache": int(time.time())}
        try:
            response = await client.get(url, params=params)
            if response.status_code in {404, 500, 502, 503}:
                logger.debug("event_snapshot_unavailable event_id=%s status=%d", event_id, response.status_code)
                return None
            response.raise_for_status()
            return response.content
        except Exception as exc:
            logger.debug("event_snapshot_error event_id=%s error=%s", event_id, exc)
            return None

    async def fetch_clip(self, client: httpx.AsyncClient, event_id: str) -> Optional[bytes]:
        """
        Query Frigate API to fetch recorded event video clip.
        
        Inputs:
          client: httpx.AsyncClient - HTTP client.
          event_id: str - Unique Frigate event identifier.
        Outputs:
          Optional[bytes] - Raw MP4 bytes if query succeeds, otherwise None.
        """
        url = f"{self.settings.frigate_api_url}/api/events/{event_id}/clip.mp4"
        try:
            response = await client.get(url)
            if response.status_code in {404, 500, 502, 503}:
                logger.debug("event_clip_unavailable event_id=%s status=%d", event_id, response.status_code)
                return None
            response.raise_for_status()
            return response.content
        except Exception as exc:
            logger.debug("event_clip_error event_id=%s error=%s", event_id, exc)
            return None

    def cooldown_for(self, camera: str) -> int:
        """
        Resolve the configured cooldown limit for a specific camera.
        
        Inputs:
          camera: str - The source camera name.
        Outputs:
          int - Cooldown period in seconds.
        """
        if camera in self.dynamic_cooldowns:
            return self.dynamic_cooldowns[camera]
        if camera in self.settings.office_cameras:
            return self.settings.office_cooldown_seconds
        return self.settings.cooldown_seconds

    async def ask_openrouter(
        self,
        client: httpx.AsyncClient,
        camera: str,
        image_bytes: bytes,
        detected_label: str,
    ) -> Dict[str, Any]:
        """
        Utilize OpenRouter API to query LLM visual description.
        Implements rate limiting backoff and [REQ-070-GRACEFUL-DEGRADATION].
        
        Inputs:
          client: httpx.AsyncClient - HTTP Client.
          camera: str - Name of source camera.
          image_bytes: bytes - JPEG image bytes.
          detected_label: str - Target classification label.
        Outputs:
          Dict[str, Any] - Dictionary containing "description" or empty string on failure.
        """
        if not self.settings.openrouter_api_key:
            return {"description": ""}

        try:
            encoded = base64.b64encode(image_bytes).decode("ascii")
        except Exception as exc:
            logger.error("image_encoding_failed error=%s", exc)
            return {"description": ""}

        # Specific detailing instructions based on detected label
        detail_instruction = ""
        if detected_label == "person":
            detail_instruction = (
                "Özellikle kişinin üzerindeki kıyafetlerin türünü ve renklerini (örn. kırmızı tişört, siyah ceket), "
                "elinde bir şey taşıyıp taşımadığını (örn. kutu, çanta, paket, poşet, alet) "
                "ve belirgin diğer aksesuarlarını (şapka, gözlük, kask vb.) belirt."
            )
        elif detected_label == "cat":
            detail_instruction = (
                "Özellikle kedinin rengini/desenini (örn. sarman, tekir, beyaz, siyah, alacalı), "
                "tahmini boyutunu, ne yaptığını (örn. koşuyor, yürüyor, çimenlerde oturuyor, bir yere tırmanıyor) "
                "ve belirgin durumunu belirt."
            )
        elif detected_label == "bird":
            detail_instruction = (
                "Özellikle kuşun rengini, türünü/cinsini (örn. karga, güvercin, serçe, martı) "
                "ve ne yaptığını (örn. uçuyor, yerde yem yiyor, dala konmuş) belirt."
            )
        else:
            detail_instruction = (
                f"Özellikle bu '{detected_label}' nesnesinin/canlısının rengini, "
                "türünü, cinsini veya belirgin durumunu belirt."
            )

        prompt = (
            f"Bu bir güvenlik kamerası karesidir. Kamera adı: {camera}. "
            f"Kamera sistemi burada bir '{detected_label}' algıladı. "
            f"{detail_instruction} "
            "Gördüklerini 1-2 kısa cümleyle samimi ve net bir şekilde Türkçe olarak betimle. "
            "(Örnek: 'Kırmızı tişörtlü, elinde paket taşıyan bir kişi yaklaştı' veya 'Bahçede kahverengi bir köpek koşuyor'). "
            "Cevabını JSON formatında tam olarak şu yapıda döndür: {\"description\": \"kisa_aciklama\"}. "
            "Başka hiçbir açıklama veya markdown ekleme, sadece saf JSON döndür."
        )
        body = {
            "model": self.settings.openrouter_model,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{encoded}"},
                        },
                    ],
                }
            ],
            "temperature": 0.1,
            "max_tokens": 120,
        }
        headers = {
            "Authorization": f"Bearer {self.settings.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": self.settings.openrouter_site_url,
            "X-Title": "Raspberry Pi Frigate Security",
        }

        try:
            response = await client.post("https://openrouter.ai/api/v1/chat/completions", json=body, headers=headers)
            if response.status_code in {402, 404, 408, 409, 429, 500, 502, 503, 504}:
                self.openrouter_pause_until = time.time() + self.settings.rate_limit_backoff_seconds
                logger.warning("openrouter_backoff status=%d", response.status_code)
                return {"description": ""}
            response.raise_for_status()
        except Exception as exc:
            self.openrouter_pause_until = time.time() + 60
            logger.warning("openrouter_error error=%s", exc)
            return {"description": ""}

        data = response.json()
        try:
            content = data["choices"][0]["message"]["content"]
            if content:
                match = re.search(r"\{.*\}", content.strip(), flags=re.DOTALL)
                if match:
                    parsed = json.loads(match.group(0))
                    return {"description": str(parsed.get("description", "")).strip()[:400]}
        except Exception as exc:
            logger.debug("openrouter_parse_error error=%s data=%s", exc, data)
        return {"description": ""}

    def build_reply_markup(self, camera: str, event_id: str) -> Optional[str]:
        """
        Construct the inline keyboard markup JSON string containing stream links
        and quick mute buttons.
        
        Inputs:
          camera: str - Source camera.
          event_id: str - Frigate event ID.
        Outputs:
          Optional[str] - JSON serialized inline keyboard markup or None.
        """
        if not self.settings.frigate_external_url:
            keyboard = {
                "inline_keyboard": [
                    [
                        {"text": "🔇 10 Dk", "callback_data": f"mute:{camera}:10"},
                        {"text": "🔇 30 Dk", "callback_data": f"mute:{camera}:30"},
                        {"text": "🔇 1 Saat", "callback_data": f"mute:{camera}:60"}
                    ]
                ]
            }
            return json.dumps(keyboard)
            
        base_url = self.settings.frigate_external_url.rstrip("/")
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "🎥 Canlı Yayın", "url": f"{base_url}/cameras/{camera}"},
                    {"text": "🎬 Olay Kaydı", "url": f"{base_url}/events?query={event_id}"}
                ],
                [
                    {"text": "🔇 10 Dk", "callback_data": f"mute:{camera}:10"},
                    {"text": "🔇 30 Dk", "callback_data": f"mute:{camera}:30"},
                    {"text": "🔇 1 Saat", "callback_data": f"mute:{camera}:60"}
                ]
            ]
        }
        return json.dumps(keyboard)

    async def post_with_retry(
        self,
        client: httpx.AsyncClient,
        url: str,
        data: Dict[str, Any],
        files: Optional[Dict[str, Any]] = None,
        max_retries: int = 3,
    ) -> httpx.Response:
        """
        Perform a POST request with retry backoff for rate limits and server errors.
        
        Inputs:
          client: httpx.AsyncClient - HTTP Client.
          url: str - POST target URL.
          data: Dict[str, Any] - Request parameters.
          files: Optional[Dict[str, Any]] - Files payload.
          max_retries: int - Retries bound limit.
        Outputs:
          httpx.Response - The completed HTTP response object.
        """
        backoff = 1.0
        for attempt in range(max_retries):
            try:
                # To prevent consumption issues on retry attempts, reconstruct files dictionary
                current_files = None
                if files:
                    current_files = {}
                    for k, v in files.items():
                        current_files[k] = v

                response = await client.post(url, data=data, files=current_files)
                
                # Check for permanent client/auth errors (400, 401, 403, 404)
                if response.status_code in (400, 401, 403, 404):
                    logger.error("Telegram API permanent client error (%d): %s. Skipping retries.", response.status_code, response.text)
                    response.raise_for_status()
                    return response

                # Check for Telegram Rate Limiting (HTTP 429)
                if response.status_code == 429:
                    retry_after = 5.0
                    try:
                        retry_after = float(response.json().get("parameters", {}).get("retry_after", 5.0))
                    except Exception:
                        pass
                    logger.warning("Telegram API rate limited (429). Retrying after %.1fs...", retry_after)
                    await asyncio.sleep(retry_after)
                    continue
                    
                # Check for gateway or internal server errors
                if response.status_code >= 500:
                    logger.warning("Telegram API server error (%d). Retrying after %.1fs...", response.status_code, backoff)
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue
                    
                response.raise_for_status()
                return response
            except httpx.HTTPError as exc:
                # If it's a HTTPStatusError with status code in (400, 401, 403, 404), do not retry
                if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in (400, 401, 403, 404):
                    raise
                if attempt == max_retries - 1:
                    raise
                logger.warning("Telegram API request failed: %s. Retrying after %.1fs...", exc, backoff)
                await asyncio.sleep(backoff)
                backoff *= 2
        raise httpx.HTTPError("Max retries exceeded")

    async def send_telegram_photo(
        self,
        client: httpx.AsyncClient,
        camera: str,
        image_bytes: bytes,
        label: str,
        score: float,
        description: str,
        event_id: str,
    ) -> None:
        """
        [REQ-060-TELEGRAM-PARALLEL] Dispatch annotated snapshot to multiple destination Chat targets.
        Includes robust error capture per channel to isolate failures.
        
        Inputs:
          client: httpx.AsyncClient - HTTP Client.
          camera: str - Name of source camera.
          image_bytes: bytes - Bounding box annotated JPEG bytes.
          label: str - Detected object class.
          score: float - Bounding box confidence score.
          description: str - Text caption detailing event scenario.
          event_id: str - Unique Frigate event ID.
        """
        if not self.settings.telegram_bot_token or not self.settings.telegram_chat_ids:
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        label_tr = {"person": "İnsan", "cat": "Kedi", "bird": "Kuş", "dog": "Köpek"}.get(label, label)
        caption = (
            f"🔔 <b>GÜVENLİK UYARISI</b>\n"
            f"📷 <b>Kamera:</b> {camera}\n"
            f"🏷️ <b>Algılanan:</b> {label_tr} ({score:.0%})\n"
            f"⏰ <b>Saat:</b> {timestamp}\n"
            f"📝 <b>Açıklama:</b> {description}"
        )
        url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendPhoto"
        reply_markup = self.build_reply_markup(camera, event_id)

        async def send_to_one(chat_id: str) -> None:
            files = {"photo": ("snapshot.jpg", image_bytes, "image/jpeg")}
            data = {
                "chat_id": chat_id,
                "caption": caption,
                "parse_mode": "HTML",
            }
            if reply_markup:
                data["reply_markup"] = reply_markup

            try:
                response = await self.post_with_retry(client, url, data=data, files=files)
                logger.info("telegram_photo_sent camera=%s label=%s chat_id=%s", camera, label, chat_id)
                self.notifications_sent_count += 1
            except Exception as exc:
                logger.warning("telegram_photo_error camera=%s chat_id=%s error=%s", camera, chat_id, exc)

        await asyncio.gather(*(send_to_one(cid) for cid in self.settings.telegram_chat_ids))

    async def send_telegram_video(
        self,
        client: httpx.AsyncClient,
        camera: str,
        label: str,
        video_bytes: bytes,
        event_id: str,
    ) -> None:
        """
        [REQ-060-TELEGRAM-PARALLEL] Dispatch MP4 video clip to multiple destination Chat targets.
        Includes supports_streaming=true for seamless inline playback.
        
        Inputs:
          client: httpx.AsyncClient - HTTP Client.
          camera: str - Name of source camera.
          label: str - Detected object class.
          video_bytes: bytes - MP4 format video bytes.
          event_id: str - Unique Frigate event ID.
        """
        if not self.settings.telegram_bot_token or not self.settings.telegram_chat_ids:
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        label_tr = {"person": "İnsan", "cat": "Kedi", "bird": "Kuş", "dog": "Köpek"}.get(label, label)
        caption = (
            f"📹 <b>OLAY VİDEOSU</b>\n"
            f"📷 <b>Kamera:</b> {camera}\n"
            f"🏷️ <b>Nesne:</b> {label_tr}\n"
            f"⏰ <b>Saat:</b> {timestamp}"
        )
        url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendVideo"
        reply_markup = self.build_reply_markup(camera, event_id)

        async def send_to_one(chat_id: str) -> None:
            files = {"video": ("clip.mp4", video_bytes, "video/mp4")}
            data = {
                "chat_id": chat_id,
                "caption": caption,
                "parse_mode": "HTML",
                "supports_streaming": "true",
            }
            if reply_markup:
                data["reply_markup"] = reply_markup

            try:
                response = await self.post_with_retry(client, url, data=data, files=files)
                logger.info("telegram_video_sent camera=%s label=%s chat_id=%s", camera, label, chat_id)
                self.notifications_sent_count += 1
            except Exception as exc:
                logger.warning("telegram_video_error camera=%s chat_id=%s error=%s", camera, chat_id, exc)

        await asyncio.gather(*(send_to_one(cid) for cid in self.settings.telegram_chat_ids))

    async def telegram_polling_loop(self) -> None:
        """
        [REQ-120-TELEGRAM-COMMANDS]
        Asynchronous polling loop to fetch and process Telegram bot commands.
        Permits authorized chat targets to query system diagnostic status and
        dynamically manipulate system parameters (e.g. cooldowns, mutes).
        """
        logger.info("Telegram command polling loop initialized.")
        offset = 0
        async with httpx.AsyncClient(timeout=35.0) as client:
            while not self.is_shutting_down:
                try:
                    url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/getUpdates"
                    params = {"offset": offset, "timeout": 30}
                    response = await client.get(url, params=params)
                    response.raise_for_status()
                    updates = response.json().get("result", [])
                    for update in updates:
                        offset = update["update_id"] + 1
                        
                        message = update.get("message")
                        if message:
                            chat_id = str(message.get("chat", {}).get("id", ""))
                            if chat_id not in self.settings.telegram_chat_ids:
                                logger.warning("Unauthorized command attempt from chat_id=%s", chat_id)
                                continue
                                
                            text = message.get("text", "").strip()
                            if text.startswith("/"):
                                await self.handle_telegram_command(client, chat_id, text)
                                
                        callback_query = update.get("callback_query")
                        if callback_query:
                            await self.handle_telegram_callback(client, callback_query)
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.warning("telegram_polling_error error=%s. Retrying in 5 seconds...", exc)
                    await asyncio.sleep(5)

    async def handle_telegram_command(self, client: httpx.AsyncClient, chat_id: str, text: str) -> None:
        """
        Parse and execute an authorized Telegram slash command.
        
        Inputs:
          client: httpx.AsyncClient - HTTP client.
          chat_id: str - Target chat identifier.
          text: str - Raw command input.
        """
        parts = text.split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        response_text = ""
        
        if cmd in ("/start", "/help"):
            response_text = (
                "🤖 <b>Güvenlik Botu Komutları:</b>\n\n"
                "📊 /status - Sistem durumunu gösterir\n"
                "📹 /snapshot &lt;kamera&gt; - Belirtilen kameradan anlık görüntü alır\n"
                "⏸️ /pause &lt;kamera&gt; &lt;dakika&gt; - Kamerayı geçici olarak susturur\n"
                "▶️ /resume &lt;kamera&gt; - Kamera susturmasını iptal eder\n"
                "⏳ /cooldown &lt;kamera&gt; &lt;saniye&gt; - Kamera cooldown süresini ayarlar\n"
                "📷 /cameras - Kameraların listesini ve durumunu gösterir\n"
                "📊 /summary - Günlük güvenlik özetini hemen üretir ve gönderir\n"
                "🎮 /ptz - PTZ kamera yönlendirme panelini açar"
            )
        elif cmd == "/status":
            status = self.get_diagnostics_status()
            active_mutes = []
            now = time.time()
            for cam in self.settings.cameras:
                pause_until = self.camera_mutes.get(cam, 0.0)
                if pause_until > now:
                     rem = int(pause_until - now)
                     active_mutes.append(f"{cam} ({rem}sn kaldı)")
            
            mutes_str = ", ".join(active_mutes) if active_mutes else "Yok"
            response_text = (
                f"📊 <b>Sistem Durumu:</b>\n"
                f"🟢 <b>Durum:</b> Çalışıyor\n"
                f"⏱️ <b>Uptime:</b> {status['uptime_seconds']} sn\n"
                f"🔌 <b>MQTT Bağlantısı:</b> {'Bağlı' if status['mqtt_connected'] else 'Bağlı Değil'}\n"
                f"🔔 <b>Gönderilen Bildirim:</b> {status['notifications_sent_count']}\n"
                f"🔄 <b>Aktif Olaylar:</b> {status['active_events_count']}\n"
                f"🔇 <b>Susturulmuş Kameralar:</b> {mutes_str}"
            )
        elif cmd == "/cameras":
            lines = []
            for cam in self.settings.cameras:
                cooldown = self.cooldown_for(cam)
                last_alert = self.last_alert_at.get(cam, 0.0)
                now = time.time()
                time_since = int(now - last_alert) if last_alert else 999999
                is_cooling = time_since < cooldown
                mute_until = self.camera_mutes.get(cam, 0.0)
                is_muted = mute_until > now
                
                status_emoji = "🔇" if is_muted else ("⏳" if is_cooling else "🟢")
                status_detail = "susturuldu" if is_muted else (f"cooldown ({cooldown - time_since}sn)" if is_cooling else "aktif")
                lines.append(f"{status_emoji} <b>{cam}</b>: {status_detail} (cooldown: {cooldown}sn)")
            response_text = "📷 <b>Kamera Listesi ve Durumları:</b>\n\n" + "\n".join(lines)
        elif cmd == "/pause":
            if len(args) < 2:
                response_text = "❌ <b>Hata:</b> Eksik parametre. Kullanım: /pause &lt;kamera&gt; &lt;dakika&gt;"
            else:
                cam, mins_str = args[0], args[1]
                if cam not in self.settings.cameras:
                    response_text = f"❌ <b>Hata:</b> Geçersiz kamera '{cam}'."
                else:
                    try:
                        mins = int(mins_str)
                        if mins <= 0:
                            response_text = "❌ <b>Hata:</b> Dakika pozitif bir sayı olmalıdır."
                        else:
                            self.camera_mutes[cam] = time.time() + (mins * 60)
                            response_text = f"🔇 <b>{cam}</b> kamerası <b>{mins} dakika</b> boyunca susturuldu."
                            self.state_manager.save_state(self.last_alert_at, self.active_events, self.camera_mutes, self.dynamic_cooldowns, self.event_log, self.last_summary_date)
                    except ValueError:
                        response_text = "❌ <b>Hata:</b> Dakika sayı olmalıdır."
        elif cmd == "/resume":
            if len(args) < 1:
                response_text = "❌ <b>Hata:</b> Eksik parametre. Kullanım: /resume &lt;kamera&gt;"
            else:
                cam = args[0]
                if cam not in self.settings.cameras:
                    response_text = f"❌ <b>Hata:</b> Geçersiz kamera '{cam}'."
                else:
                    self.camera_mutes[cam] = 0.0
                    response_text = f"▶️ <b>{cam}</b> kamerası tekrar aktif."
                    self.state_manager.save_state(self.last_alert_at, self.active_events, self.camera_mutes, self.dynamic_cooldowns, self.event_log, self.last_summary_date)
        elif cmd == "/cooldown":
            if len(args) < 2:
                response_text = "❌ <b>Hata:</b> Eksik parametre. Kullanım: /cooldown &lt;kamera&gt; &lt;saniye&gt;"
            else:
                cam, secs_str = args[0], args[1]
                if cam not in self.settings.cameras:
                    response_text = f"❌ <b>Hata:</b> Geçersiz kamera '{cam}'."
                else:
                    try:
                        secs = int(secs_str)
                        if secs < 0:
                            response_text = "❌ <b>Hata:</b> Saniye sıfır veya pozitif olmalıdır."
                        else:
                            self.dynamic_cooldowns[cam] = secs
                            response_text = f"⏳ <b>{cam}</b> kamerası cooldown süresi <b>{secs} saniye</b> olarak güncellendi."
                            self.state_manager.save_state(self.last_alert_at, self.active_events, self.camera_mutes, self.dynamic_cooldowns, self.event_log, self.last_summary_date)
                    except ValueError:
                        response_text = "❌ <b>Hata:</b> Saniye sayı olmalıdır."
        elif cmd == "/snapshot":
            if len(args) < 1:
                response_text = "❌ <b>Hata:</b> Eksik parametre. Kullanım: /snapshot &lt;kamera&gt;"
            else:
                cam = args[0]
                if cam not in self.settings.cameras:
                    response_text = f"❌ <b>Hata:</b> Geçersiz kamera '{cam}'."
                else:
                    snapshot_bytes = await self.fetch_camera_latest_frame(client, cam)
                    if snapshot_bytes:
                        url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendPhoto"
                        files = {"photo": ("snapshot.jpg", snapshot_bytes, "image/jpeg")}
                        data = {
                            "chat_id": chat_id,
                            "caption": f"📷 <b>Anlık Görüntü:</b> {cam}\n⏰ <b>Saat:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                            "parse_mode": "HTML",
                        }
                        try:
                            await self.post_with_retry(client, url, data=data, files=files)
                            return
                        except Exception as exc:
                            response_text = f"❌ <b>Hata:</b> Görüntü Telegram'a gönderilemedi: {exc}"
                    else:
                         response_text = f"❌ <b>Hata:</b> {cam} kamerasından anlık görüntü alınamadı."
        elif cmd == "/ptz":
            response_text = "🎮 <b>PTZ Kamera Kontrol Paneli</b>\n\nAşağıdaki butonları kullanarak kamerayı yönlendirebilirsiniz:"
            url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage"
            data = {
                "chat_id": chat_id,
                "text": response_text,
                "parse_mode": "HTML",
                "reply_markup": self.build_ptz_keyboard("ptz_dis")
            }
            try:
                await self.post_with_retry(client, url, data=data)
                return
            except Exception as exc:
                response_text = f"❌ <b>Hata:</b> PTZ kontrol paneli açılamadı: {exc}"
        elif cmd == "/summary":
            await self.generate_and_send_summary(client, chat_id=chat_id)
            return
        else:
            response_text = "❌ <b>Hata:</b> Bilinmeyen komut. Tüm komutları listelemek için /help yazabilirsiniz."
             
        if response_text:
            url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage"
            data = {
                "chat_id": chat_id,
                "text": response_text,
                "parse_mode": "HTML",
            }
            try:
                await self.post_with_retry(client, url, data=data)
            except Exception as exc:
                logger.error("telegram_response_error chat_id=%s error=%s", chat_id, exc)

    async def fetch_camera_latest_frame(self, client: httpx.AsyncClient, camera: str) -> Optional[bytes]:
        """
        Fetch the latest live frame for a camera from the Frigate API.
        
        Inputs:
          client: httpx.AsyncClient - HTTP client.
          camera: str - The source camera name.
        Outputs:
          Optional[bytes] - Raw JPEG bytes if query succeeds, otherwise None.
        """
        url = f"{self.settings.frigate_api_url}/api/{camera}/latest.jpg"
        try:
            response = await client.get(url)
            if response.status_code in {404, 500, 502, 503}:
                logger.debug("camera_latest_frame_unavailable camera=%s status=%d", camera, response.status_code)
                return None
            response.raise_for_status()
            return response.content
        except Exception as exc:
            logger.debug("camera_latest_frame_error camera=%s error=%s", camera, exc)
            return None

    async def daily_summary_scheduler(self) -> None:
        """
        Background task running periodically to trigger the daily summary generation.
        Checks every 10 seconds if it is 23:59 (or later) and a summary has not yet
        been dispatched for the current date.
        
        Purpose:
          Automatically compile and dispatch the Daily AI Security Digest.
        Preconditions:
          Event loop is running.
        Postconditions:
          Summary is compiled and sent via OpenRouter to Telegram targets.
        Exceptions:
          Catches and logs any unexpected loop exceptions to maintain resilience.
        """
        logger.info("Daily summary scheduler task started.")
        while not self.is_shutting_down:
            try:
                now_dt = datetime.now()
                # Check if it is 23:59 or later
                if now_dt.hour == 23 and now_dt.minute >= 59:
                    today_str = now_dt.strftime("%Y-%m-%d")
                    if self.last_summary_date != today_str:
                        logger.info("Triggering scheduled daily security digest generation.")
                        async with httpx.AsyncClient(timeout=self.settings.http_timeout_seconds) as client:
                            await self.generate_and_send_summary(client)
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("daily_summary_scheduler_error error=%s", exc)
                await asyncio.sleep(10)

    async def generate_and_send_summary(self, client: httpx.AsyncClient, chat_id: Optional[str] = None) -> None:
        """
        Compile all events logged for the current calendar date, query OpenRouter LLM
        to produce a concise Turkish summary, and broadcast it to all authorized chats.
        
        Purpose:
          Generate the daily security status narrative.
        Preconditions:
          client: httpx.AsyncClient - Initialized HTTP client.
          chat_id: Optional[str] - Specific chat target if triggered manually.
        Postconditions:
          Turkish narrative summary dispatched via Telegram sendMessage API.
        Inputs:
          client: httpx.AsyncClient - HTTP client.
          chat_id: Optional[str] - Destination override target.
        Outputs:
          None.
        Exceptions:
          Catches and log Telegram network or JSON parse errors.
        """
        now_dt = datetime.now()
        today_str = now_dt.strftime("%Y-%m-%d")
        today_date = now_dt.date()
        
        # Filter event_log for events matching the local date
        today_events = []
        for event in self.event_log:
            try:
                event_dt = datetime.fromtimestamp(event["timestamp"])
                if event_dt.date() == today_date:
                    today_events.append(event)
            except Exception as exc:
                logger.warning("Error parsing event log entry: %s", exc)
                
        total_count = len(today_events)
        
        if total_count == 0:
            summary_text = f"📊 <b>Günlük Güvenlik Raporu ({now_dt.strftime('%d.%m.%Y')}):</b> Bugün herhangi bir olay algılanmadı. Genel durum: Güvenli."
        else:
            # Format list of events for the prompt
            events_formatted = []
            for ev in today_events:
                ev_time = datetime.fromtimestamp(ev["timestamp"]).strftime("%H:%M")
                label_tr = {"person": "İnsan", "cat": "Kedi", "bird": "Kuş", "dog": "Köpek"}.get(ev["label"], ev["label"])
                events_formatted.append(
                    f"- Saat {ev_time}'de {ev['camera']} kamerasında {label_tr} algılandı. Açıklama: {ev['description']}"
                )
            
            events_str = "\n".join(events_formatted)
            prompt = (
                f"Aşağıda bugün kaydedilen güvenlik kamerası olayları listelenmiştir:\n"
                f"Toplam Olay Sayısı: {total_count}\n"
                f"Olaylar:\n{events_str}\n\n"
                f"Bu olayları derleyerek Türkçe dilinde 3-4 cümlelik samimi ve profesyonel bir günlük güvenlik özeti oluştur.\n"
                f"Şüpheli bir durum olup olmadığını değerlendir ve genel durumu (örneğin Güvenli) belirt.\n"
                f"Rapor başlığı olarak tam olarak şunu kullan: 📊 Günlük Güvenlik Raporu ({now_dt.strftime('%d.%m.%Y')}): "
                f"Yalnızca Türkçe metin döndür. HTML formatında olmasın (başlık hariç)."
            )
            
            logger.info("Asking OpenRouter for daily summary...")
            summary_response = await self.ask_openrouter_text(client, prompt)
            if summary_response:
                summary_text = summary_response
            else:
                summary_text = (
                    f"📊 <b>Günlük Güvenlik Raporu ({now_dt.strftime('%d.%m.%Y')}):</b> Bugün toplam {total_count} olay algılandı. "
                    f"Kameralarda çeşitli hareketler kaydedildi. Genel durum: Güvenli."
                )
                
        # Send to all configured chat IDs or specific override target
        target_chat_ids = [chat_id] if chat_id else self.settings.telegram_chat_ids
        url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage"
        
        async def send_to_one(cid: str) -> None:
            data = {
                "chat_id": cid,
                "text": summary_text,
                "parse_mode": "HTML"
            }
            try:
                await self.post_with_retry(client, url, data=data)
                logger.info("telegram_summary_sent chat_id=%s", cid)
            except Exception as exc:
                logger.warning("telegram_summary_error chat_id=%s error=%s", cid, exc)

        await asyncio.gather(*(send_to_one(cid) for cid in target_chat_ids))
        
        # Mark summary sent for today and rotate old events (older than 2 days)
        if not chat_id:
            self.last_summary_date = today_str
            cutoff_time = time.time() - 2 * 86400
            self.event_log = [ev for ev in self.event_log if ev["timestamp"] > cutoff_time]
            self.state_manager.save_state(
                self.last_alert_at,
                self.active_events,
                self.camera_mutes,
                self.dynamic_cooldowns,
                self.event_log,
                self.last_summary_date
            )

    async def ask_openrouter_text(self, client: httpx.AsyncClient, prompt: str) -> Optional[str]:
        """
        Query OpenRouter API with a text-only prompt to generate summaries.
        
        Purpose:
          Fetch text completion from LLM for daily summarization.
        Preconditions:
          Settings contain a valid OpenRouter API key.
        Postconditions:
          Returns LLM text result.
        Inputs:
          client: httpx.AsyncClient - HTTP client.
          prompt: str - Raw query.
        Outputs:
          Optional[str] - Completed response content or None.
        Exceptions:
          Catches API errors or exceptions cleanly.
        """
        if not self.settings.openrouter_api_key:
            return None

        body = {
            "model": self.settings.openrouter_model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.3,
            "max_tokens": 500,
        }
        headers = {
            "Authorization": f"Bearer {self.settings.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": self.settings.openrouter_site_url,
            "X-Title": "Raspberry Pi Frigate Security",
        }

        try:
            response = await client.post("https://openrouter.ai/api/v1/chat/completions", json=body, headers=headers)
            if response.status_code in {402, 404, 408, 409, 429, 500, 502, 503, 504}:
                logger.warning("openrouter_text_backoff status=%d", response.status_code)
                return None
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            return content.strip() if content else None
        except Exception as exc:
            logger.warning("openrouter_text_error error=%s", exc)
            return None

    def build_ptz_keyboard(self, camera: str) -> str:
        """
        Construct an inline keyboard markup JSON string for PTZ camera control.
        Contains directional keys and zoom buttons.
        
        Purpose:
          Build the PTZ controller interface.
        Preconditions:
          camera: str - The PTZ target camera identifier.
        Outputs:
          str - JSON serialized inline keyboard markup.
        """
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "   ", "callback_data": "ptz_noop"},
                    {"text": "▲ Yukarı", "callback_data": f"ptz:{camera}:MOVE_UP"},
                    {"text": "   ", "callback_data": "ptz_noop"}
                ],
                [
                    {"text": "◀️ Sol", "callback_data": f"ptz:{camera}:MOVE_LEFT"},
                    {"text": "⏹️ Dur", "callback_data": f"ptz:{camera}:STOP"},
                    {"text": "▶️ Sağ", "callback_data": f"ptz:{camera}:MOVE_RIGHT"}
                ],
                [
                    {"text": "   ", "callback_data": "ptz_noop"},
                    {"text": "▼ Aşağı", "callback_data": f"ptz:{camera}:MOVE_DOWN"},
                    {"text": "   ", "callback_data": "ptz_noop"}
                ],
                [
                    {"text": "➕ Yakınlaştır", "callback_data": f"ptz:{camera}:ZOOM_IN"},
                    {"text": "➖ Uzaklaştır", "callback_data": f"ptz:{camera}:ZOOM_OUT"}
                ]
            ]
        }
        return json.dumps(keyboard)

    async def handle_telegram_callback(self, client: httpx.AsyncClient, callback_query: Dict[str, Any]) -> None:
        """
        Process an incoming Telegram callback query triggered from inline button clicks.
        Supports both quick camera mute requests and PTZ controls.
        
        Purpose:
          Interactive button click command dispatcher.
        Preconditions:
          Telegram callback query event is received.
        Postconditions:
          Camera mute state updated or MQTT camera controls sent, with update snapshots.
        Inputs:
          client: httpx.AsyncClient - HTTP client.
          callback_query: Dict[str, Any] - Telegram callback event payload.
        Exceptions:
          Logs and ignores parsing failures.
        """
        callback_id = callback_query.get("id")
        if callback_id:
            try:
                url_answer = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/answerCallbackQuery"
                await client.post(url_answer, json={"callback_query_id": callback_id})
            except Exception as exc:
                logger.error("error answering callback query: %s", exc)

        chat_id = str(callback_query.get("message", {}).get("chat", {}).get("id", ""))
        user_id = str(callback_query.get("from", {}).get("id", ""))
        if chat_id not in self.settings.telegram_chat_ids and user_id not in self.settings.telegram_chat_ids:
            logger.warning("Unauthorized callback attempt from chat_id=%s user_id=%s", chat_id, user_id)
            return

        data = callback_query.get("data", "")
        if not data:
            return

        # 1. Quick Mute handling: "mute:<camera>:<minutes>"
        if data.startswith("mute:"):
            parts = data.split(":")
            if len(parts) == 3:
                cam = parts[1]
                try:
                    mins = int(parts[2])
                    if cam in self.settings.cameras:
                        self.camera_mutes[cam] = time.time() + (mins * 60)
                        self.state_manager.save_state(self.last_alert_at, self.active_events, self.camera_mutes, self.dynamic_cooldowns, self.event_log, self.last_summary_date)
                        
                        url_msg = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage"
                        await client.post(url_msg, json={
                            "chat_id": chat_id,
                            "text": f"🔇 <b>{cam}</b> kamerası <b>{mins} dakika</b> boyunca susturuldu.",
                            "parse_mode": "HTML"
                        })
                except Exception as exc:
                    logger.error("Error processing mute callback: %s", exc)

        # 2. PTZ camera handling: "ptz:<camera>:<command>"
        elif data.startswith("ptz:"):
            parts = data.split(":")
            if len(parts) == 3:
                cam = parts[1]
                ptz_cmd = parts[2]
                if cam == "ptz_dis":
                    topic = f"frigate/{cam}/ptz"
                    if ptz_cmd == "STOP":
                        try:
                            self.mqtt_client.publish(topic, "STOP")
                            logger.info("Publishing PTZ STOP command to %s", topic)
                        except Exception as exc:
                            logger.error("Failed to publish PTZ STOP command to MQTT: %s", exc)
                    elif ptz_cmd in ("MOVE_UP", "MOVE_DOWN", "MOVE_LEFT", "MOVE_RIGHT", "ZOOM_IN", "ZOOM_OUT"):
                        logger.info("Publishing PTZ command: %s to %s", ptz_cmd, topic)
                        try:
                            self.mqtt_client.publish(topic, ptz_cmd)
                        except Exception as exc:
                            logger.error("Failed to publish PTZ command to MQTT: %s", exc)
                        
                        # Wait 0.5s for directional movement and publish STOP
                        await asyncio.sleep(0.5)
                        try:
                            self.mqtt_client.publish(topic, "STOP")
                            logger.info("Publishing PTZ STOP command to %s", topic)
                        except Exception as exc:
                            logger.error("Failed to publish PTZ STOP command to MQTT: %s", exc)
                        
                        # Let camera settle, then send updated frame
                        await asyncio.sleep(0.5)
                        snapshot_bytes = await self.fetch_camera_latest_frame(client, cam)
                        if snapshot_bytes:
                            url_photo = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendPhoto"
                            files = {"photo": ("snapshot.jpg", snapshot_bytes, "image/jpeg")}
                            payload = {
                                "chat_id": chat_id,
                                "caption": f"📷 <b>Yeni Açı Görüntüsü:</b> {cam}\n⏰ <b>Saat:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                                "parse_mode": "HTML",
                                "reply_markup": self.build_ptz_keyboard(cam)
                            }
                            try:
                                await self.post_with_retry(client, url_photo, data=payload, files=files)
                            except Exception as exc:
                                logger.error("Failed to send PTZ updated snapshot: %s", exc)

    async def printer_monitoring_loop(self) -> None:
        """
        Periodically polls the FLSun T1 printer camera snapshot URL,
        detects online/offline status changes, and analyzes printing motion.
        If printing motion stops, triggers OpenRouter visual analysis for print status.
        """
        if not self.settings.printer_enabled:
            logger.info("Printer monitoring is disabled.")
            return

        logger.info("FLSun T1 3D Printer monitoring loop initialized.")
        client = httpx.AsyncClient(timeout=self.settings.http_timeout_seconds)

        # State tracking variables
        printer_online = None  # True, False, or None (initial)
        last_frame_blurred = None
        motion_history: List[float] = []
        is_printing = False
        consecutive_no_motion_count = 0
        consecutive_motion_count = 0

        # We keep the window size for analysis
        window_size = 6  # 2 minutes at 20s polling
        
        while not self.is_shutting_down:
            try:
                # 1. Probe snapshot endpoint
                is_reachable = False
                snapshot_bytes = None
                try:
                    response = await client.get(self.settings.printer_snapshot_url)
                    if response.status_code == 200:
                        snapshot_bytes = response.content
                        is_reachable = True
                except Exception as exc:
                    logger.debug("printer_probe_failed error=%s", exc)

                # 2. Handle Online/Offline transitions
                if printer_online is None:
                    printer_online = is_reachable
                    logger.info("Initial printer online status: %s", printer_online)
                elif printer_online != is_reachable:
                    printer_online = is_reachable
                    status_str = "Çevrimiçi (Online) 🟢" if printer_online else "Çevrimdışı (Offline) 🔴"
                    msg = f"🖨️ <b>FLSun T1 Yazıcı Bağlantısı:</b> {status_str}"
                    logger.info("printer_online_change status=%s", status_str)
                    
                    for chat_id in self.settings.telegram_chat_ids:
                        await self.post_with_retry(
                            client,
                            f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage",
                            {"chat_id": chat_id, "text": msg, "parse_mode": "HTML"},
                        )

                # 3. If online, analyze motion
                if printer_online and snapshot_bytes:
                    try:
                        nparr = np.frombuffer(snapshot_bytes, np.uint8)
                        img = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
                        if img is not None:
                            img_resized = cv2.resize(img, (320, 240))
                            img_blurred = cv2.GaussianBlur(img_resized, (21, 21), 0)

                            if last_frame_blurred is not None:
                                diff = cv2.absdiff(last_frame_blurred, img_blurred)
                                _, thresh = cv2.threshold(diff, 25, 255, cv2.THRESH_BINARY)
                                non_zero = np.count_nonzero(thresh)
                                total_pixels = thresh.shape[0] * thresh.shape[1]
                                pct_changed = (non_zero / total_pixels) * 100.0

                                motion_history.append(pct_changed)
                                if len(motion_history) > window_size:
                                    motion_history.pop(0)

                                has_motion = pct_changed >= self.settings.printer_movement_threshold_pct
                                logger.debug("printer_motion_check pct_changed=%.2f%% has_motion=%s", pct_changed, has_motion)

                                if is_printing:
                                    if not has_motion:
                                        consecutive_no_motion_count += 1
                                        consecutive_motion_count = 0
                                    else:
                                        consecutive_no_motion_count = 0
                                        consecutive_motion_count += 1

                                    if consecutive_no_motion_count >= 5:
                                        is_printing = False
                                        consecutive_no_motion_count = 0
                                        logger.info("printer_print_stopped - initiating AI analysis")

                                        ai_analysis = await self.ask_openrouter_printer_status(client, snapshot_bytes)
                                        
                                        msg = (
                                            "⚠️ <b>FLSun T1 Yazıcı Bildirimi:</b> Baskı Hareketi Durdu!\n\n"
                                            f"🔍 <b>Yapay Zeka Analizi:</b>\n{ai_analysis}"
                                        )

                                        for chat_id in self.settings.telegram_chat_ids:
                                            await self.send_telegram_photo_raw(
                                                client,
                                                chat_id,
                                                snapshot_bytes,
                                                msg
                                            )
                                else:
                                    if has_motion:
                                        consecutive_motion_count += 1
                                        consecutive_no_motion_count = 0
                                    else:
                                        consecutive_motion_count = 0
                                        consecutive_no_motion_count += 1

                                    if consecutive_motion_count >= 3:
                                        is_printing = True
                                        consecutive_motion_count = 0
                                        logger.info("printer_print_started")
                                        msg = "▶️ <b>FLSun T1 Yazıcı Bildirimi:</b> Baskı başladı veya yazıcı kafası hareket halinde."
                                        for chat_id in self.settings.telegram_chat_ids:
                                            await self.post_with_retry(
                                                client,
                                                f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage",
                                                {"chat_id": chat_id, "text": msg, "parse_mode": "HTML"},
                                            )

                            last_frame_blurred = img_blurred
                    except Exception as exc:
                        logger.error("printer_image_processing_failed error=%s", exc)
                else:
                    last_frame_blurred = None
                    is_printing = False
                    consecutive_no_motion_count = 0
                    consecutive_motion_count = 0
                    motion_history.clear()

            except Exception as exc:
                logger.error("printer_monitor_loop_iteration_failed error=%s", exc)

            await asyncio.sleep(self.settings.printer_check_interval)

        await client.aclose()

    async def ask_openrouter_printer_status(
        self,
        client: httpx.AsyncClient,
        image_bytes: bytes,
    ) -> str:
        """
        Analyze 3D printer snapshot using OpenRouter vision model to check print status,
        detecting spaghetti, print detachment, or normal completion.
        """
        if not self.settings.openrouter_api_key:
            return "Açıklama alınamadı (API Anahtarı eksik)."

        try:
            encoded = base64.b64encode(image_bytes).decode("ascii")
        except Exception as exc:
            logger.error("printer_image_encoding_failed error=%s", exc)
            return "Görüntü kodlanamadı."

        prompt = (
            "Bu bir 3D yazıcı kamerası görüntüsüdür. Baskı hareketi durdu veya bitti. "
            "Lütfen görüntüyü çok dikkatli analiz et. Baskı başarıyla tamamlandı mı (baskı tablası üzerinde bitmiş, temiz bir nesne duruyor mu)? "
            "Yoksa baskı sırasında bir sorun/hata mı oluştu? "
            "(Örn: spagettileşme/ipliklenme, baskının yataktan kayması/ayrılması, filamantsiz boşta yazdırma/havada nozzle gezmesi, baskının yarıda kalması vb.) "
            "Gördüğün durumu Türkçe olarak 1-2 net ve samimi cümleyle açıkla. "
            "Cevabını JSON formatında tam olarak şu yapıda döndür: {\"analysis\": \"aciklama\"}. "
            "Başka hiçbir açıklama veya markdown ekleme, sadece saf JSON döndür."
        )
        body = {
            "model": self.settings.openrouter_model,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{encoded}"},
                        },
                    ],
                }
            ],
            "temperature": 0.1,
            "max_tokens": 120,
        }
        headers = {
            "Authorization": f"Bearer {self.settings.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": self.settings.openrouter_site_url,
            "X-Title": "Raspberry Pi 3D Printer Monitor",
        }

        try:
            response = await client.post("https://openrouter.ai/api/v1/chat/completions", json=body, headers=headers)
            if response.status_code in {402, 404, 408, 409, 429, 500, 502, 503, 504}:
                logger.warning("openrouter_printer_status_backoff status=%d", response.status_code)
                return "Yapay zeka servisi şu an meşgul, durum analiz edilemedi."
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            if content:
                match = re.search(r"\{.*\}", content.strip(), flags=re.DOTALL)
                if match:
                    parsed = json.loads(match.group(0))
                    return str(parsed.get("analysis", "Baskı durumu analiz edilemedi.")).strip()[:400]
        except Exception as exc:
            logger.warning("openrouter_printer_status_error error=%s", exc)
        
        return "Baskı durma/bitme durumu yapay zeka tarafından analiz edilemedi."

    async def send_telegram_photo_raw(
        self,
        client: httpx.AsyncClient,
        chat_id: str,
        image_bytes: bytes,
        caption: str,
    ) -> None:
        """
        Sends a raw photo with a custom caption to a specific Telegram chat.
        """
        url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendPhoto"
        files = {"photo": ("snapshot.jpg", image_bytes, "image/jpeg")}
        data = {
            "chat_id": chat_id,
            "caption": caption,
            "parse_mode": "HTML",
        }
        try:
            await self.post_with_retry(client, url, data=data, files=files)
            logger.info("telegram_photo_raw_sent chat_id=%s", chat_id)
            self.notifications_sent_count += 1
        except Exception as exc:
            logger.warning("telegram_photo_raw_error chat_id=%s error=%s", chat_id, exc)

    async def shutdown(self, sig: signal.Signals) -> None:
        """
        [REQ-100-GRACEFUL-SHUTDOWN]
        Gracefully terminate the AlertService. Saves state, closes MQTT connection,
        stops the diagnostics server, and cancels running async tasks cleanly.
        
        Inputs:
          sig: signal.Signals - Triggering signal name.
        """
        if self.is_shutting_down:
            return
            
        self.is_shutting_down = True
        logger.info("Initiating graceful shutdown on signal %s...", sig.name)
        
        # Save state atomically
        logger.info("Saving persistent state variables to disk...")
        self.state_manager.save_state(self.last_alert_at, self.active_events, self.camera_mutes, self.dynamic_cooldowns, self.event_log, self.last_summary_date)
        
        # Close MQTT loops
        if self.mqtt_client:
            logger.info("Stopping MQTT client loop...")
            self.mqtt_client.disconnect()
            self.mqtt_client.loop_stop()
            self.mqtt_connected = False
            
        # Stop Health server
        self.health_server.stop()
        
        # Cancel all running tasks (except the shutdown task itself)
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        logger.info("Canceling %d pending asynchronous tasks...", len(tasks))
        for task in tasks:
            task.cancel()
            
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Shutdown sequence completed. Exiting SCI.")
        sys.exit(0)


if __name__ == "__main__":
    try:
        asyncio.run(AlertService(Settings()).run())
    except ConfigurationError as config_exc:
        logger.critical("FATAL: Configuration verification failed. SCI terminating. details=%s", config_exc)
    except KeyboardInterrupt:
        logger.info("SCI shutdown requested. Terminating gracefully.")
    except Exception as fatal_exc:
        logger.critical("FATAL: Unexpected system failure. SCI terminating. error=%s", fatal_exc, exc_info=True)
