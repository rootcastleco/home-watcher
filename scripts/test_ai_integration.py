#!/usr/bin/env python3
# ==============================================================================
# MIL-STD-498 INTEGRATION AND DIAGNOSTIC UTILITY
# ==============================================================================
# SYSTEM:             Rootcastle Home Watcher Stack
# SUBSYSTEM:          Vision AI & Telegram Integration Verification
# FILE NAME:          test_ai_integration.py
# VERSION:            1.2.0
# DATE:               2026-06-15
# SECURITY CLASSIF:   UNCLASSIFIED
# DESCRIPTION:        Diagnostic tool that loads configuration values from .env,
#                     generates a mock camera snapshot frame, submits it to the
#                     OpenRouter Multimodal API, interprets the result, and
#                     delivers a verified test image to the Telegram alert channel.
# ==============================================================================

import os
import sys
import base64
import json
import numpy as np
import cv2
import httpx

def log(msg):
    print(f"[INFO] {msg}")

def warn(msg):
    print(f"[WARN] {msg}", file=sys.stderr)

def error(msg):
    print(f"[ERROR] {msg}", file=sys.stderr)

def load_env():
    """Manually parse .env file if present in current or parent directory."""
    env_path = ".env"
    if not os.path.exists(env_path) and os.path.exists("../.env"):
        env_path = "../.env"
    
    if os.path.exists(env_path):
        log(f"Loading environment configurations from {env_path}...")
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, val = line.split("=", 1)
                        os.environ[key.strip()] = val.strip()
    else:
        warn("No .env file found. Reading parameters directly from shell environment.")

def create_test_image():
    """Generate a dummy JPEG snapshot image using OpenCV and numpy."""
    log("Generating dummy camera snapshot frame...")
    # Create a dark blue image
    img = np.zeros((480, 640, 3), dtype=np.uint8)
    img[:] = [30, 14, 10] # Dark blue brand color

    # Draw security boundaries and test patterns
    cv2.rectangle(img, (20, 20), (620, 460), (0, 82, 255), 2) # Rootcastle blue border
    cv2.putText(img, "ROOTCASTLE HOME WATCHER", (50, 80), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
    cv2.putText(img, "INTEGRATION TEST FRAME", (50, 130), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
    cv2.putText(img, "OBJECT: A cat sitting in a secure area.", (50, 220), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (100, 200, 100), 1)

    # Draw a simple shape representing an object
    cv2.circle(img, (320, 320), 50, (0, 165, 255), -1) # Orange circle
    cv2.putText(img, "TEST OBJECT (CAT)", (230, 410), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 165, 255), 2)

    _, buffer = cv2.imencode(".jpg", img)
    return buffer.tobytes()

def test_openrouter(image_bytes, api_key, model):
    log("Submitting test image to OpenRouter Vision API...")
    url = "https://openrouter.ai/api/v1/chat/completions"
    
    base64_image = base64.b64encode(image_bytes).decode("utf-8")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    
    prompt = (
        "Identify if there is any of the following objects in the image: person, dog, cat, bird. "
        "Respond ONLY with a valid JSON array listing the detected labels (e.g. ['cat'] or ['person', 'dog']). "
        "If none of these are detected, respond with an empty array: []."
    )
    
    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/jpeg;base64,{base64_image}"
                        }
                    }
                ]
            }
        ],
        "temperature": 0.1
    }
    
    try:
        response = httpx.post(url, headers=headers, json=payload, timeout=20.0)
        if response.status_code != 200:
            error(f"OpenRouter API returned error status {response.status_code}: {response.text}")
            return None
        
        result = response.json()
        ai_response = result["choices"][0]["message"]["content"].strip()
        log(f"OpenRouter Raw AI response: {ai_response}")
        return ai_response
    except Exception as e:
        error(f"Failed to communicate with OpenRouter API: {e}")
        return None

def test_telegram(image_bytes, bot_token, chat_id, ai_result):
    log("Broadcasting test frame to Telegram alert channel...")
    url = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
    
    caption = (
        "🔔 *Rootcastle Home Watcher AI Test*\n\n"
        f"Status: *Diagnostics Completed*\n"
        f"AI Classifier Result: `{ai_result}`\n\n"
        "This is an automated integration test verifying API pathways."
    )
    
    files = {
        "photo": ("test_frame.jpg", image_bytes, "image/jpeg")
    }
    data = {
        "chat_id": chat_id,
        "caption": caption,
        "parse_mode": "Markdown"
    }
    
    try:
        response = httpx.post(url, data=data, files=files, timeout=15.0)
        if response.status_code != 200:
            error(f"Telegram API returned error status {response.status_code}: {response.text}")
            return False
        
        log("Telegram alert message delivered successfully!")
        return True
    except Exception as e:
        error(f"Failed to communicate with Telegram API: {e}")
        return False

def main():
    load_env()
    
    # Check credentials
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    model = os.getenv("OPENROUTER_MODEL", "google/gemini-2.0-flash-exp:free")
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    
    if not api_key:
        warn("OPENROUTER_API_KEY is empty. Skipping OpenRouter Vision testing.")
    if not bot_token or not chat_id:
        warn("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is empty. Skipping Telegram verification.")
        
    if not api_key and (not bot_token or not chat_id):
        error("Missing required API credentials. Configure your .env file first.")
        sys.exit(1)
        
    image_bytes = create_test_image()
    
    ai_result = "N/A (Skipped)"
    if api_key:
        ai_result = test_openrouter(image_bytes, api_key, model)
        if not ai_result:
            error("OpenRouter Vision diagnostics failed.")
            sys.exit(1)
            
    if bot_token and chat_id:
        success = test_telegram(image_bytes, bot_token, chat_id, ai_result)
        if not success:
            error("Telegram message delivery diagnostics failed.")
            sys.exit(1)
            
    log("All systems online. Diagnostics completed successfully!")

if __name__ == "__main__":
    main()
