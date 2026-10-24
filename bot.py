import os
import time
import secrets
import hmac
import re
import logging
from threading import Lock, Thread
from urllib.parse import urlparse, urlunparse

import requests
from flask import Flask, request, render_template_string

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("find-my-phone-bot")
app = Flask(__name__)

# Required Render environment variables
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
LOCATION_MESSAGE_TTL = int(os.getenv("LOCATION_MESSAGE_TTL", "300"))

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"
sessions = {}
sessions_lock = Lock()

# Each location result goes to the private chat that requested it.
pending_location_requests = []
pending_location_lock = Lock()

PROTECTED_ACTIONS = {
    "/findphone": {
        "label": "Find Phone alert",
        "url": MACRODROID_WEBHOOK_URL,
        "macro_name": "Find Phone",
    },
    "/location": {
        "label": "Phone location request",
        "url": LOCATION_MACRODROID_WEBHOOK_URL,
        "macro_name": "Location",
    },
    "/unmute": {
        "label": "Unmute",
        "url": UNMUTE_MACRODROID_WEBHOOK_URL,
        "macro_name": "Unmute",
    },
}


def telegram_api_call(method, payload):
    response = requests.post(
        f"{TELEGRAM_API}/{method}",
        json=payload,
        timeout=(3, 10),
    )
    response.raise_for_status()
    data = response.json()
    if not data.get("ok"):
        raise RuntimeError(f"Telegram API {method} failed")
    return data.get("result")


def telegram_send_message(chat_id, message):
    return telegram_api_call(
        "sendMessage",
        {"chat_id": chat_id, "text": message},
    )


def send_owner_message(message):
    return telegram_send_message(TELEGRAM_CHAT_ID, message)


def delete_message_later(chat_id, message_id, delay):
    def worker():
        time.sleep(max(1, delay))
        try:
            telegram_api_call(
                "deleteMessage",
                {"chat_id": chat_id, "message_id": message_id},
            )
            logger.info("Expired location message deleted")
        except Exception:
            logger.exception("Could not delete expired location message")

    Thread(target=worker, daemon=True).start()


def send_temporary_location(chat_id, maps_link):
    result = telegram_api_call(
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": (
                "📍 Phone location (this message is scheduled to delete "
                "in 5 minutes):\n" + maps_link
            ),
        },
    )
    delete_message_later(
        chat_id,
        result["message_id"],
        LOCATION_MESSAGE_TTL,
    )


def set_telegram_webhook():
    response = requests.post(
        f"{TELEGRAM_API}/setWebhook",
        json={"url": f"{PUBLIC_BASE_URL}/telegram/webhook"},
        timeout=(3, 10),
    )
    response.raise_for_status()
    logger.info("Telegram webhook setup result: %s", response.text)


def trigger_macro(url, name):
    if not url:
        raise ValueError(f"{name} MacroDroid webhook URL is empty")

    response = requests.get(
        url,
        headers={"User-Agent": "FindMyPhoneBot/1.0"},
        timeout=(3, 8),
        allow_redirects=True,
    )
    logger.info("%s MacroDroid HTTP status: %s", name, response.status_code)
    logger.info("%s MacroDroid response: %s", name, response.text[:200])
    response.raise_for_status()
    return response


def cleanup_sessions():
    now = time.time()
    with sessions_lock:
        expired = [
            token for token, data in sessions.items()
            if data["expires"] <= now or data["used"]
        ]
        for token in expired:
            sessions.pop(token, None)


def create_session(action, requester_chat_id):
    cleanup_sessions()
    token = secrets.token_urlsafe(32)
    with sessions_lock:
        sessions[token] = {
            "expires": time.time() + SESSION_TTL,
            "attempts": 0,
            "used": False,
            "locked_until": 0,
            "action": action,
            "requester_chat_id": str(requester_chat_id),
        }
    return token


def get_session(token):
    cleanup_sessions()
    with sessions_lock:
        return sessions.get(token)


def verify_password(entered, actual):
    return hmac.compare_digest(entered, actual)


HTML = """
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Find My Phone - Verify</title>
<style>
body { margin:0; font-family:Arial,sans-serif; background:#111827; color:white; }
.card { max-width:420px; margin:50px auto; padding:28px; background:#1f2937;
        border-radius:18px; box-sizing:border-box; }
input,button { width:100%; box-sizing:border-box; padding:14px; margin:12px 0;
               border-radius:10px; font-size:16px; }
input { border:1px solid #4b5563; background:#111827; color:white; }
button { border:0; background:#2563eb; color:white; font-weight:bold; }
.small { color:#9ca3af; font-size:13px; }
</style>
</head>
<body>
<div class="card">
<h2>Find My Phone</h2>
<p>Verify the master password to authorize:
<strong>{{ action_label }}</strong>.</p>
<form method="post">
<input type="password" name="password" placeholder="Master password"
       autocomplete="current-password" required autofocus>
<button type="submit">Verify &amp; Run Command</button>
</form>
{% if message %}<p>{{ message }}</p>{% endif %}
<p class="small">This one-time link expires in {{ ttl }} seconds.
Never share it with anyone else.</p>
</div>
</body>
</html>
"""


@app.route("/auth/<token>", methods=["GET", "POST"])
def auth(token):
    session = get_session(token)
    if not session:
        return "This authentication link is invalid, expired, or already used.", 410

    with sessions_lock:
        if session["used"]:
            return "This authentication link has already been used.", 410

        if session["expires"] <= time.time():
            sessions.pop(token, None)
            return "This authentication link has expired.", 410

        if session["locked_until"] > time.time():
            remaining = int(session["locked_until"] - time.time())
            return render_template_string(
                HTML,
                action_label=PROTECTED_ACTIONS[session["action"]]["label"],
                ttl=SESSION_TTL,
                message=f"Too many attempts. Try again in {remaining} seconds.",
            ), 429

        if request.method == "GET":
            return render_template_string(
                HTML,
                action_label=PROTECTED_ACTIONS[session["action"]]["label"],
                ttl=SESSION_TTL,
                message=None,
            )

        entered = request.form.get("password", "")
        if not verify_password(entered, MASTER_PASSWORD):
            session["attempts"] += 1

            if session["attempts"] >= MAX_ATTEMPTS:
                session["locked_until"] = time.time() + LOCK_TIME
                return render_template_string(
                    HTML,
                    action_label=PROTECTED_ACTIONS[session["action"]]["label"],
                    ttl=SESSION_TTL,
                    message=f"Access locked for {LOCK_TIME // 60} minutes.",
                ), 429

            remaining = MAX_ATTEMPTS - session["attempts"]
            return render_template_string(
                HTML,
                action_label=PROTECTED_ACTIONS[session["action"]]["label"],
                ttl=SESSION_TTL,
                message=f"Incorrect password. {remaining} attempt(s) remaining.",
            ), 401

        # A successful one-time link cannot be replayed.
        session["used"] = True
        action = session["action"]
        requester_chat_id = session["requester_chat_id"]

    try:
        if action == "/location":
            # Register the requesting chat before triggering MacroDroid.
            with pending_location_lock:
                pending_location_requests.append({
                    "chat_id": requester_chat_id,
                    "expires": time.time() + SESSION_TTL,
                })

            telegram_send_message(
                requester_chat_id,
                "📍 Password verified. Requesting phone location...",
            )

        config = PROTECTED_ACTIONS[action]
        trigger_macro(config["url"], config["macro_name"])

        with sessions_lock:
            sessions.pop(token, None)

        if action == "/location":
            telegram_send_message(
                requester_chat_id,
                "✅ Location macro triggered. The Google Maps link will be sent to this chat when received.",
            )
        else:
            telegram_send_message(
                requester_chat_id,
                f"✅ Password verified. {config['label']} command sent to MacroDroid.",
            )

        return render_template_string(
            HTML,
            action_label=config["label"],
            ttl=SESSION_TTL,
            message="Password verified. Command sent successfully. You can close this page.",
        ), 200

    except Exception:
        logger.exception("Authenticated command execution failed")
        with sessions_lock:
            sessions.pop(token, None)

        if action == "/location":
            with pending_location_lock:
                pending_location_requests[:] = [
                    item for item in pending_location_requests
                    if item["chat_id"] != requester_chat_id
                ]

        try:
            telegram_send_message(
                requester_chat_id,
                "⚠️ Password was accepted, but the command could not be sent. Check the bot service logs.",
            )
        except Exception:
            logger.exception("Could not notify command requester")

        return render_template_string(
            HTML,
            action_label=PROTECTED_ACTIONS[action]["label"],
            ttl=SESSION_TTL,
            message="Password accepted, but the command could not be sent. Please try again.",
        ), 502


@app.route("/location", methods=["GET", "POST"])
def receive_location():
    supplied_secret = request.values.get("secret", "")
    location = request.values.get("location", "").strip()

    if not hmac.compare_digest(supplied_secret, LOCATION_SECRET):
        logger.warning("Rejected location request: invalid secret")
        return {"status": "error", "message": "Unauthorized"}, 401

    if not location or len(location) > 1000:
        return {"status": "error", "message": "Location missing or too long"}, 400

    parsed = urlparse(location)
    valid_maps_url = (
        parsed.scheme in {"http", "https"}
        and parsed.hostname in {
            "maps.google.com",
            "www.google.com",
            "maps.app.goo.gl",
        }
        and (
            parsed.hostname != "www.google.com"
            or parsed.path.startswith("/maps")
        )
    )

    match = re.fullmatch(
        r"\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*",
        location,
    )
    valid_coordinates = False

    if match:
        lat, lon = float(match.group(1)), float(match.group(2))
        valid_coordinates = -90 <= lat <= 90 and -180 <= lon <= 180

    if not (valid_maps_url or valid_coordinates):
        return {"status": "error", "message": "Invalid location format"}, 400

    if valid_coordinates:
        maps_link = f"https://www.google.com/maps?q={location}"
    elif parsed.hostname == "maps.google.com" and parsed.scheme == "http":
        maps_link = urlunparse(parsed._replace(scheme="https"))
    else:
        maps_link = location

    # Route the location callback to the private chat that requested it.
    now = time.time()
    with pending_location_lock:
        pending_location_requests[:] = [
            item for item in pending_location_requests
            if item["expires"] > now
        ]
        target = (
            pending_location_requests.pop(0)
            if pending_location_requests
            else None
        )

    if not target:
        logger.warning("Location received with no active requesting chat")
        return {"status": "error", "message": "No active location request"}, 410

    try:
        send_temporary_location(target["chat_id"], maps_link)
        logger.info("Location successfully delivered to requesting Telegram chat")
        return {"status": "ok", "message": "Location sent"}, 200
    except Exception:
        logger.exception("Location Telegram delivery error")
        return {"status": "error", "message": "Telegram delivery failed"}, 502


@app.route("/", methods=["GET"])
def home():
    return "<h2>Find My Phone Bot</h2><p>Service is running.</p>", 200


@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}, 200


def process_telegram_update(update):
    try:
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        if not chat:
            return

        chat_id = str(chat.get("id"))
        chat_type = chat.get("type", "")
        text = message.get("text", "").strip()
        command = text.split()[0].split("@")[0] if text else ""

        if not command.startswith("/"):
            return

        if command == "/start":
            telegram_send_message(
                chat_id,
                "Find My Phone Bot is ready.\n\n"
                "/findphone - Password required\n"
                "/location - Password required; result goes to this chat\n"
                "/unmute - Password required\n"
                "/stop - No password, owner chat only",
            )
            return

        if command == "/stop":
            # Password-free, but restricted to the owner's private chat.
            if chat_id != TELEGRAM_CHAT_ID or chat_type != "private":
                telegram_send_message(
                    chat_id,
                    "⛔ /stop is password-free but can only be used from the owner's private Telegram chat.",
                )
                return

            try:
                trigger_macro(STOP_MACRODROID_WEBHOOK_URL, "Stop")
                telegram_send_message(
                    chat_id,
                    "🛑 Stop command sent to MacroDroid.",
                )
            except Exception:
                logger.exception("Stop MacroDroid command failed")
                telegram_send_message(
                    chat_id,
                    "⚠️ Stop command could not reach MacroDroid. Check the service logs.",
                )
            return

        if command in PROTECTED_ACTIONS:
            if chat_type != "private":
                telegram_send_message(
                    chat_id,
                    "Please use this bot in a private chat, not a group.",
                )
                return

            token = create_session(command, chat_id)
            auth_url = f"{PUBLIC_BASE_URL}/auth/{token}"

            telegram_send_message(
                chat_id,
                "🔐 Password required\n\n"
                f"Command: {PROTECTED_ACTIONS[command]['label']}\n"
                "Open this one-time verification link and enter the master password:\n\n"
                f"{auth_url}\n\n"
                f"Link expires in {SESSION_TTL // 60} minute(s), "
                f"allows {MAX_ATTEMPTS} attempts, and works once.",
            )
            return

        telegram_send_message(
            chat_id,
            "Unknown command. Use /start to see available commands.",
        )

    except Exception:
        logger.exception("Telegram update processing error")


@app.route("/telegram/webhook", methods=["POST"])
def telegram_webhook():
    update = request.get_json(silent=True) or {}
    Thread(
        target=process_telegram_update,
        args=(update,),
        daemon=True,
    ).start()
    return "OK", 200


try:
    set_telegram_webhook()
except Exception:
    logger.exception("Telegram webhook registration failed")
