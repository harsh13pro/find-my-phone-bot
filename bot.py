
import os
import time
import secrets
import hmac
from threading import Lock

import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ============================================================
# Environment Variables
# ============================================================

BOT_TOKEN = os.environ["BOT_TOKEN"]
MASTER_PASSWORD = os.environ["MASTER_PASSWORD"]
PUBLIC_BASE_URL = os.environ["PUBLIC_BASE_URL"].rstrip("/")

MACRODROID_WEBHOOK_URL = os.environ["MACRODROID_WEBHOOK_URL"]
STOP_MACRODROID_WEBHOOK_URL = os.environ["STOP_MACRODROID_WEBHOOK_URL"]
UNMUTE_MACRODROID_WEBHOOK_URL = os.environ["UNMUTE_MACRODROID_WEBHOOK_URL"]
LOCATION_SECRET = os.environ["LOCATION_SECRET"]

# Your private Telegram chat ID
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

SESSION_TTL = int(os.getenv("SESSION_TTL", "300"))
MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "3"))
LOCK_TIME = int(os.getenv("LOCK_TIME", "600"))

sessions = {}
sessions_lock = Lock()

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"


# ============================================================
# Telegram Helpers
# ============================================================

def telegram_send_message(chat_id, message):
    response = requests.post(
        f"{TELEGRAM_API}/sendMessage",
        json={"chat_id": chat_id, "text": message},
        timeout=15
    )
    response.raise_for_status()


def send_to_owner(message):
    if not TELEGRAM_CHAT_ID:
        raise RuntimeError("TELEGRAM_CHAT_ID is not configured")

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
# MacroDroid Helpers
# ============================================================

def trigger_url(url):
    response = requests.get(
        url,
        headers={"User-Agent": "FindMyPhoneBot/1.0"},
        timeout=30,
        allow_redirects=True
    )
    print("MacroDroid HTTP status:", response.status_code)
    response.raise_for_status()
    return response


def trigger_findphone():
    return trigger_url(MACRODROID_WEBHOOK_URL)


def trigger_stop():
    return trigger_url(STOP_MACRODROID_WEBHOOK_URL)


def trigger_unmute():
    return trigger_url(UNMUTE_MACRODROID_WEBHOOK_URL)


# ============================================================
# Authentication Sessions
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
# Authentication Page
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
    border: 0; background: #2563eb; color: white;
    font-weight: bold;
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
{% if message %}
<p>{{ message }}</p>
{% endif %}
<p class="small">This link is temporary and can be used only once.</p>
</div>
</body>
</html>
"""


# ============================================================
# Authentication Endpoint
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

    try:
        trigger_findphone()
        with sessions_lock:
            sessions.pop(token, None)

        return render_template_string(
            HTML, message="Authentication successful. Find Phone command sent."
        )

    except Exception as error:
        print("MacroDroid error:", error)
        with sessions_lock:
            sessions.pop(token, None)

        return render_template_string(
            HTML, message="Authentication succeeded, but the phone command could not be sent."
        ), 502


# ============================================================
# Location Receiver
# MacroDroid sends a Google Maps link in the "location" parameter.
# ============================================================

@app.route("/location", methods=["GET", "POST"])
def receive_location():
    supplied_secret = request.values.get("secret", "")
    location = request.values.get("location", "").strip()

    if not hmac.compare_digest(supplied_secret, LOCATION_SECRET):
        return {"status": "error", "message": "Unauthorized"}, 401

    if not location:
        return {
            "status": "error",
            "message": "Missing location parameter"
        }, 400

    # Accept only a Google Maps URL or coordinate pair.
    valid_maps_url = (
        location.startswith("https://maps.google.com/")
        or location.startswith("https://www.google.com/maps")
        or location.startswith("https://maps.app.goo.gl/")
    )
    valid_coordinates = False

    if "," in location and len(location) < 100:
        parts = location.split(",")
        if len(parts) == 2:
            try:
                lat = float(parts[0].strip())
                lon = float(parts[1].strip())
                valid_coordinates = -90 <= lat <= 90 and -180 <= lon <= 180
            except ValueError:
                pass

    if not (valid_maps_url or valid_coordinates):
        return {"status": "error", "message": "Invalid location format"}, 400

    if not TELEGRAM_CHAT_ID:
        return {"status": "error", "message": "TELEGRAM_CHAT_ID is not configured"}, 503

    try:
        telegram_send_message(
            TELEGRAM_CHAT_ID,
            "📍 Phone location received:\n" + location
        )
        return {"status": "ok", "message": "Location sent to Telegram"}, 200

    except Exception as error:
        print("Telegram location delivery error:", error)
        return {"status": "error", "message": "Telegram delivery failed"}, 502


# ============================================================
# Home and Health
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return "<h2>Find My Phone Bot</h2><p>Service is running.</p>", 200


@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}, 200


# ============================================================
# Telegram Commands
# ============================================================

@app.route("/telegram/webhook", methods=["POST"])
def telegram_webhook():
    try:
        update = request.get_json(force=True) or {}
        message = update.get("message") or {}
        chat = message.get("chat") or {}

        if not chat:
            return "OK", 200

        chat_id = chat.get("id")
        text = message.get("text", "").strip()

        # Only the configured owner can control the phone.
        if TELEGRAM_CHAT_ID and str(chat_id) != TELEGRAM_CHAT_ID:
            telegram_send_message(chat_id, "Unauthorized.")
            return "OK", 200

        command = text.split()[0].split("@")[0] if text else ""

        if command == "/start":
            telegram_send_message(
                chat_id,
                "Find My Phone Bot is ready.\n\n"
                "/findphone - Secure phone alert\n"
                "/stop - Stop phone alert\n"
                "/unmute - Restore notification volume\n"
                "/location - Request phone location"
            )

        elif command == "/findphone":
            token = create_session()
            auth_url = f"{PUBLIC_BASE_URL}/auth/{token}"

            telegram_send_message(
                chat_id,
                "🔐 Secure Find Phone\n\n"
                "Open this temporary link and enter your master password:\n\n"
                f"{auth_url}\n\n"
                f"Link expires in {SESSION_TTL // 60} minutes and works once."
            )

        elif command == "/stop":
            trigger_stop()
            telegram_send_message(chat_id, "🛑 Stop command sent to MacroDroid.")

        elif command == "/unmute":
            trigger_unmute()
            telegram_send_message(chat_id, "🔊 Unmute command sent to MacroDroid.")

        elif command == "/location":
            trigger_url(os.environ["LOCATION_MACRODROID_WEBHOOK_URL"])
            telegram_send_message(
                chat_id,
                "📍 Location request sent. Waiting for MacroDroid to send the location."
            )

        else:
            telegram_send_message(
                chat_id,
                "Unknown command.\nUse /start to see available commands."
            )

        return "OK", 200

    except Exception as error:
        print("Telegram webhook error:", error)
        return "Webhook error", 500


# ============================================================
# Register Telegram Webhook
# ============================================================

try:
    set_telegram_webhook()
except Exception as error:
    print("Telegram webhook registration failed:", error)
