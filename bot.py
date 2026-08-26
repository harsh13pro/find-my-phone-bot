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
MACRODROID_WEBHOOK_URL = os.environ["MACRODROID_WEBHOOK_URL"]
MASTER_PASSWORD = os.environ["MASTER_PASSWORD"]
PUBLIC_BASE_URL = os.environ["PUBLIC_BASE_URL"].rstrip("/")

SESSION_TTL = int(os.getenv("SESSION_TTL", "300"))
MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "3"))
LOCK_TIME = int(os.getenv("LOCK_TIME", "600"))

sessions = {}
sessions_lock = Lock()


# ============================================================
# Telegram API
# ============================================================

TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}"


def telegram_send_message(chat_id, text):
    response = requests.post(
        f"{TELEGRAM_API}/sendMessage",
        json={
            "chat_id": chat_id,
            "text": text
        },
        timeout=15
    )

    response.raise_for_status()


def set_telegram_webhook():
    webhook_url = f"{PUBLIC_BASE_URL}/telegram/webhook"

    response = requests.post(
        f"{TELEGRAM_API}/setWebhook",
        json={
            "url": webhook_url
        },
        timeout=15
    )

    print("Telegram webhook setup:", response.text)


# ============================================================
# Session Management
# ============================================================

def cleanup_sessions():
    now = time.time()

    with sessions_lock:
        expired = [
            token
            for token, data in sessions.items()
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
# MacroDroid
# ============================================================

def trigger_macrodroid():
    response = requests.get(
        MACRODROID_WEBHOOK_URL,
        timeout=15
    )

    response.raise_for_status()


# ============================================================
# Authentication Page
# ============================================================

HTML = """
<!doctype html>

<html>

<head>

<meta name="viewport"
      content="width=device-width, initial-scale=1">

<title>Find My Phone</title>

<style>

body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: #111827;
    color: white;
}

.card {
    max-width: 420px;
    margin: 70px auto;
    padding: 28px;
    background: #1f2937;
    border-radius: 18px;
    box-sizing: border-box;
}

h2 {
    margin-top: 0;
}

input {
    width: 100%;
    box-sizing: border-box;
    padding: 14px;
    margin: 12px 0;
    border-radius: 10px;
    border: 1px solid #4b5563;
    background: #111827;
    color: white;
    font-size: 16px;
}

button {
    width: 100%;
    padding: 14px;
    border: 0;
    border-radius: 10px;
    background: #2563eb;
    color: white;
    font-size: 16px;
    font-weight: bold;
}

.msg {
    margin-top: 16px;
}

.small {
    color: #9ca3af;
    font-size: 13px;
}

</style>

</head>

<body>

<div class="card">

<h2>Find My Phone</h2>

<p>
Enter your master password to activate the phone alert.
</p>

<form method="post">

<input
    type="password"
    name="password"
    placeholder="Master password"
    autocomplete="current-password"
    required
>

<button type="submit">
Authenticate & Activate
</button>

</form>

{% if message %}

<p class="msg">
{{ message }}
</p>

{% endif %}

<p class="small">
This link is temporary and can be used only once.
</p>

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

            remaining = int(
                session["locked_until"] - now
            )

            return render_template_string(
                HTML,
                message=(
                    "Too many incorrect attempts. "
                    f"Try again in about {remaining} seconds."
                )
            ), 429

        if session["expires"] <= now:

            sessions.pop(token, None)

            return "This authentication link has expired.", 410

        if request.method == "POST":

            entered = request.form.get(
                "password",
                ""
            )

            if verify_password(
                entered,
                MASTER_PASSWORD
            ):

                session["used"] = True

                try:

                    trigger_macrodroid()

                    sessions.pop(token, None)

                    return render_template_string(
                        HTML,
                        message=(
                            "Authentication successful. "
                            "Find Phone command sent."
                        )
                    )

                except Exception as error:

                    print(
                        "MacroDroid error:",
                        error
                    )

                    sessions.pop(token, None)

                    return render_template_string(
                        HTML,
                        message=(
                            "Authentication succeeded, "
                            "but the phone command "
                            "could not be sent."
                        )
                    ), 502

            session["attempts"] += 1

            if session["attempts"] >= MAX_ATTEMPTS:

                session["locked_until"] = (
                    now + LOCK_TIME
                )

                return render_template_string(
                    HTML,
                    message=(
                        "Incorrect password. "
                        f"Access locked for "
                        f"{LOCK_TIME // 60} minutes."
                    )
                ), 429

            remaining = (
                MAX_ATTEMPTS -
                session["attempts"]
            )

            return render_template_string(
                HTML,
                message=(
                    "Incorrect password. "
                    f"{remaining} attempt(s) remaining."
                )
            ), 401

    return render_template_string(
        HTML,
        message=None
    )


# ============================================================
# Home
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return """
    <h2>Find My Phone Bot</h2>
    <p>Service is running.</p>
    """, 200


# ============================================================
# Health Check
# ============================================================

@app.route("/health", methods=["GET"])
def health():

    return {
        "status": "ok"
    }, 200


# ============================================================
# Telegram Webhook
# ============================================================

@app.route("/telegram/webhook", methods=["POST"])
def telegram_webhook():

    try:

        update = request.get_json(
            force=True
        )

        if not update:
            return "OK", 200

        message = update.get("message")

        if not message:
            return "OK", 200

        chat = message.get("chat")

        if not chat:
            return "OK", 200

        chat_id = chat.get("id")

        text = message.get(
            "text",
            ""
        ).strip()

        # /start
        if text == "/start":

            telegram_send_message(
                chat_id,
                "Find My Phone Bot is ready.\n\n"
                "Use /findphone to start "
                "secure authentication."
            )

        # /findphone
        elif text == "/findphone":

            token = create_session()

            auth_url = (
                f"{PUBLIC_BASE_URL}/auth/{token}"
            )

            telegram_send_message(
                chat_id,
                "🔐 Secure Find Phone\n\n"
                "Open this temporary link "
                "and enter your master password:\n\n"
                f"{auth_url}\n\n"
                f"Link expires in "
                f"{SESSION_TTL // 60} minutes "
                "and works only once."
            )

        else:

            telegram_send_message(
                chat_id,
                "Unknown command.\n\n"
                "Use /start or /findphone."
            )

        return "OK", 200

    except Exception as error:

        print(
            "Telegram webhook error:",
            error
        )

        return "Webhook error", 500


# ============================================================
# Register Telegram Webhook
#
# Gunicorn imports this file, so this executes when
# the Render service starts.
# ============================================================

try:

    set_telegram_webhook()

except Exception as error:

    print(
        "Telegram webhook registration failed:",
        error
    )
