
import os
import time
import secrets
import hmac
import re
from threading import Lock
from urllib.parse import urlparse

import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ============================================================
# Environment variables
# ============================================================

BOT_TOKEN = os.environ["BOT_TOKEN"]
MASTER_PASSWORD = os.environ["MASTER_PASSWORD"]
PUBLIC_BASE_URL = os.environ["PUBLIC_BASE_URL"].rstrip("/")

MACRODROID_WEBHOOK_URL = os.environ["MACRODROID_WEBHOOK_URL"]
STOP_MACRODROID_WEBHOOK_URL = os.environ["STOP_MACRODROID_WEBHOOK_URL"]
UNMUTE_MACRODROID_WEBHOOK_URL = os.environ["UNMUTE_MACRODROID_WEBHOOK_URL"]
LOCATION_MACRODROID_WEBHOOK_URL = os.environ["LOCATION_MACRODROID_WEBHOOK_URL"]

LOCATION_SECRET = os.environ["LOCATION_SECRET"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"].strip()

SESSION_TTL = int(os.getenv("SESSION_TTL", "300"))
MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "3"))
LOCK_TIME = int(os.getenv("LOCK_TIME", "600"))

sessions = {}
sessions_lock = Lock()

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"


# ============================================================
# Telegram helpers
# ============================================================

def telegram_send_message(chat_id, message):
    response = requests.post(
        f"{TELEGRAM_API}/sendMessage",
        json={"chat_id": chat_id, "text": message},
        timeout=15
    )
    response.raise_for_status()


def send_owner_message(message):
    telegram_send_message(TELEGRAM_CHAT_ID, message)


def set_telegram_webhook():
    response = requests.post(
        f"{TELEGRAM_API}/setWebhook",
        json={"url": f"{PUBLIC_BASE_URL}/telegram/webhook"},
        timeout=15
    )
    response.raise_for_status()
    print("Telegram webhook setup:", response.text)


# ============================================================
# MacroDroid helpers
# ============================================================

def trigger_macro(url, name):
    response = requests.get(
        url,
        headers={"User-Agent": "FindMyPhoneBot/1.0"},
        timeout=30,
        allow_redirects=True
    )

    print(f"{name} HTTP status:", response.status_code)
    print(f"{name} response:", response.text[:300])

    response.raise_for_status()
    return response


# ============================================================
# Authentication sessions
# ============================================================

def cleanup_sessions():
    now = time.time()

    with sessions_lock:
        expired = [
            token for token, data in sessions.items()
            if data["expires"] <= now
        ]

        for token in expired:
            sessions.pop(token, None)


def create_session():
    cleanup_sessions()
    token = secrets.token_urlsafe(32)

    with sessions_lock:
        sessions[token] = {
            "expires": time.time() + SESSION_TTL,
            "attempts": 0,
            "used": False,
            "locked_until": 0
        }

    return token


def get_session(token):
    cleanup_sessions()

    with sessions_lock:
        return sessions.get(token)


def verify_password(entered, actual):
    return hmac.compare_digest(entered, actual)


# ============================================================
# Authentication page
# ============================================================

HTML = """
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Find My Phone</title>
<style>
body {
    margin: 0; font-family: Arial, sans-serif;
    background: #111827; color: white;
}
.card {
    max-width: 420px; margin: 70px auto; padding: 28px;
    background: #1f2937; border-radius: 18px;
    box-sizing: border-box;
}
input, button {
    width: 100%; box-sizing: border-box; padding: 14px;
    margin: 12px 0; border-radius: 10px; font-size: 16px;
}
input {
    border: 1px solid #4b5563;
    background: #111827; color: white;
}
button {
    border: 0; background: #2563eb;
    color: white; font-weight: bold;
}
.small { color: #9ca3af; font-size: 13px; }
</style>
</head>
<body>
<div class="card">
<h2>Find My Phone</h2>
<p>Enter your master password to activate the phone alert.</p>
<form method="post">
<input type="password" name="password"
placeholder="Master password" autocomplete="current-password" required>
<button type="submit">Authenticate &amp; Activate</button>
</form>
{% if message %}<p>{{ message }}</p>{% endif %}
<p class="small">This link is temporary and can be used only once.</p>
</div>
</body>
</html>
"""


# ============================================================
# Authentication endpoint
# ============================================================

@app.route("/auth/<token>", methods=["GET", "POST"])
def auth(token):
    session = get_session(token)

    if not session:
        return "This authentication link is invalid or expired.", 410

    now = time.time()

    with sessions_lock:
        if session["used"]:
            return "This authentication link has already been used.", 410

        if session["locked_until"] > now:
            remaining = int(session["locked_until"] - now)
            return render_template_string(
                HTML,
                message=f"Too many attempts. Try again in {remaining} seconds."
            ), 429

        if session["expires"] <= now:
            sessions.pop(token, None)
            return "This authentication link has expired.", 410

        if request.method == "POST":
            entered = request.form.get("password", "")

            if verify_password(entered, MASTER_PASSWORD):
                session["used"] = True
            else:
                session["attempts"] += 1

                if session["attempts"] >= MAX_ATTEMPTS:
                    session["locked_until"] = now + LOCK_TIME
                    return render_template_string(
                        HTML,
                        message=f"Access locked for {LOCK_TIME // 60} minutes."
                    ), 429

                remaining = MAX_ATTEMPTS - session["attempts"]
                return render_template_string(
                    HTML,
                    message=f"Incorrect password. {remaining} attempt(s) remaining."
                ), 401
        else:
            return render_template_string(HTML, message=None)

    try:
        trigger_macro(MACRODROID_WEBHOOK_URL, "Find Phone")
        with sessions_lock:
            sessions.pop(token, None)

        return render_template_string(
            HTML,
            message="Authentication successful. Find Phone command sent."
        )

    except Exception as error:
        print("Find Phone MacroDroid error:", error)
        with sessions_lock:
            sessions.pop(token, None)

        return render_template_string(
            HTML,
            message="Authentication succeeded, but the phone command could not be sent."
        ), 502


# ============================================================
# Location receiver
# MacroDroid sends location=<Google Maps URL>
# and secret=<LOCATION_SECRET>.
# ============================================================

@app.route("/location", methods=["GET", "POST"])
def receive_location():
    supplied_secret = request.values.get("secret", "")
    location = request.values.get("location", "").strip()

    if not hmac.compare_digest(supplied_secret, LOCATION_SECRET):
        return {"status": "error", "message": "Unauthorized"}, 401

    if not location or len(location) > 1000:
        return {"status": "error", "message": "Location missing or too long"}, 400

    # Accept Google Maps URLs or latitude,longitude coordinates.
    parsed = urlparse(location)
    valid_maps_url = (
        parsed.scheme == "https"
        and parsed.hostname in {
            "maps.google.com",
            "www.google.com",
            "maps.app.goo.gl"
        }
        and (
            parsed.hostname != "www.google.com"
            or parsed.path.startswith("/maps")
        )
    )

    valid_coordinates = False
    match = re.fullmatch(
        r"\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*",
        location
    )

    if match:
        lat, lon = float(match.group(1)), float(match.group(2))
        valid_coordinates = -90 <= lat <= 90 and -180 <= lon <= 180

    if not (valid_maps_url or valid_coordinates):
        return {"status": "error", "message": "Invalid location format"}, 400

    maps_link = location
    if valid_coordinates:
        maps_link = f"https://www.google.com/maps?q={location}"

    try:
        send_owner_message("📍 Phone location:\n" + maps_link)
        print("Location successfully delivered to Telegram.")
        return {"status": "ok", "message": "Location sent"}, 200

    except Exception as error:
        print("Location Telegram delivery error:", error)
        return {"status": "error", "message": "Telegram delivery failed"}, 502


# ============================================================
# Home and health
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return "<h2>Find My Phone Bot</h2><p>Service is running.</p>", 200


@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}, 200


# ============================================================
# Telegram webhook and commands
# ============================================================

@app.route("/telegram/webhook", methods=["POST"])
def telegram_webhook():
    try:
        update = request.get_json(force=True) or {}
        message = update.get("message") or {}
        chat = message.get("chat") or {}

        if not chat:
            return "OK", 200

        chat_id = str(chat.get("id"))
        text = message.get("text", "").strip()
        command = text.split()[0].split("@")[0] if text else ""

        # Only the configured owner may control this phone.
        if chat_id != TELEGRAM_CHAT_ID:
            telegram_send_message(chat_id, "Unauthorized.")
            return "OK", 200

        if command == "/start":
            send_owner_message(
                "Find My Phone Bot is ready.\n\n"
                "/findphone - Secure phone alert\n"
                "/stop - Stop phone alert\n"
                "/unmute - Restore notification volume\n"
                "/location - Request phone location"
            )

        elif command == "/findphone":
            token = create_session()
            auth_url = f"{PUBLIC_BASE_URL}/auth/{token}"

            send_owner_message(
                "🔐 Secure Find Phone\n\n"
                "Open this temporary link and enter your master password:\n\n"
                f"{auth_url}\n\n"
                f"Link expires in {SESSION_TTL // 60} minutes and works once."
            )

        elif command == "/stop":
            trigger_macro(STOP_MACRODROID_WEBHOOK_URL, "Stop")
            send_owner_message("🛑 Stop command sent to MacroDroid.")

        elif command == "/unmute":
            trigger_macro(UNMUTE_MACRODROID_WEBHOOK_URL, "Unmute")
            send_owner_message("🔊 Unmute command sent to MacroDroid.")

        elif command == "/location":
            send_owner_message("📍 Requesting phone location...")

            trigger_macro(
                LOCATION_MACRODROID_WEBHOOK_URL,
                "Location"
            )

            send_owner_message(
                "✅ Location macro triggered. Waiting for the location link."
            )

        else:
            send_owner_message(
                "Unknown command.\nUse /start to see available commands."
            )

        return "OK", 200

    except Exception as error:
        print("Telegram webhook error:", error)
        return "Webhook error", 500


# ============================================================
# Register Telegram webhook on startup
# ============================================================

try:
    set_telegram_webhook()
except Exception as error:
    print("Telegram webhook registration failed:", error)
