import os
import time
import secrets
import hashlib
import hmac
from threading import Lock

import requests
from flask import Flask, request, render_template_string
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

# ============================================================
# Find My Phone Bot
# Architecture:
# Telegram /findphone -> one-time secure web page
#                     -> master password (max 3 attempts)
#                     -> MacroDroid webhook
#
# IMPORTANT:
# Never put Telegram token, MacroDroid URL, or password in this file.
# Set them as environment variables on the hosting service.
# ============================================================

app = Flask(__name__)

BOT_TOKEN = os.environ["BOT_TOKEN"]
MACRODROID_WEBHOOK_URL = os.environ["MACRODROID_WEBHOOK_URL"]
MASTER_PASSWORD = os.environ["MASTER_PASSWORD"]

# Link validity and temporary lock settings
SESSION_TTL = int(os.getenv("SESSION_TTL", "300"))       # 5 minutes
MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "3"))
LOCK_TIME = int(os.getenv("LOCK_TIME", "600"))           # 10 minutes

sessions = {}
sessions_lock = Lock()


def cleanup_sessions():
    now = time.time()
    with sessions_lock:
        expired = [
            token for token, data in sessions.items()
            if data["expires"] <= now or data.get("locked_until", 0) <= now and data.get("used")
        ]
        for token in expired:
            sessions.pop(token, None)


def create_session():
    cleanup_sessions()
    token = secrets.token_urlsafe(32)
    with sessions_lock:
        sessions[token] = {
            "created": time.time(),
            "expires": time.time() + SESSION_TTL,
            "attempts": 0,
            "used": False,
            "locked_until": 0,
        }
    return token


def get_session(token):
    cleanup_sessions()
    with sessions_lock:
        return sessions.get(token)


def verify_password(entered, actual):
    # Constant-time comparison.
    return hmac.compare_digest(entered, actual)


def trigger_macrodroid():
    # The webhook URL itself is kept secret in the hosting environment.
    response = requests.get(MACRODROID_WEBHOOK_URL, timeout=15)
    response.raise_for_status()
    return response


HTML = """
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Find My Phone - Secure Access</title>
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
h2 { margin-top: 0; }
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
.msg { margin-top: 16px; }
.small { color: #9ca3af; font-size: 13px; }
</style>
</head>
<body>
<div class="card">
    <h2>Find My Phone</h2>
    <p>Enter your master password to activate the phone alert.</p>
    <form method="post">
        <input type="password" name="password" placeholder="Master password"
               autocomplete="current-password" required>
        <button type="submit">Authenticate & Activate</button>
    </form>
    {% if message %}
        <p class="msg">{{ message }}</p>
    {% endif %}
    <p class="small">This link is temporary and can be used only once.</p>
</div>
</body>
</html>
"""


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
                message=f"Too many incorrect attempts. Try again in about {remaining} seconds."
            ), 429

        if session["expires"] <= now:
            sessions.pop(token, None)
            return "This authentication link has expired.", 410

        if request.method == "POST":
            entered = request.form.get("password", "")

            if verify_password(entered, MASTER_PASSWORD):
                session["used"] = True

                try:
                    trigger_macrodroid()
                    sessions.pop(token, None)
                    return render_template_string(
                        HTML,
                        message="Authentication successful. Find Phone command sent."
                    )
                except Exception:
                    sessions.pop(token, None)
                    return render_template_string(
                        HTML,
                        message="Authentication succeeded, but the phone command could not be sent."
                    ), 502

            session["attempts"] += 1

            if session["attempts"] >= MAX_ATTEMPTS:
                session["locked_until"] = now + LOCK_TIME
                return render_template_string(
                    HTML,
                    message=f"Incorrect password. Access locked for {LOCK_TIME // 60} minutes."
                ), 429

            remaining_attempts = MAX_ATTEMPTS - session["attempts"]
            return render_template_string(
                HTML,
                message=f"Incorrect password. {remaining_attempts} attempt(s) remaining."
            ), 401

    return render_template_string(HTML, message=None)


@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}, 200


# Telegram command
async def findphone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    token = create_session()

    # Render/other host must provide PUBLIC_BASE_URL, e.g.
    # https://your-service.onrender.com
    base_url = os.environ["PUBLIC_BASE_URL"].rstrip("/")
    auth_url = f"{base_url}/auth/{token}"

    await update.message.reply_text(
        "🔐 Secure Find Phone\n\n"
        "Open this temporary link and enter your master password:\n"
        f"{auth_url}\n\n"
        f"Link expires in {SESSION_TTL // 60} minutes and works once."
    )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Find My Phone Bot is ready.\n\n"
        "Use /findphone to start secure authentication."
    )


def create_telegram_app():
    telegram_app = Application.builder().token(BOT_TOKEN).build()
    telegram_app.add_handler(CommandHandler("start", start))
    telegram_app.add_handler(CommandHandler("findphone", findphone))
    return telegram_app


@app.route("/telegram/webhook", methods=["POST"])
def telegram_webhook():
    telegram_app = create_telegram_app()

    update = Update.de_json(request.get_json(force=True), telegram_app.bot)

    # Process the update synchronously through the async application.
    import asyncio

    async def process():
        await telegram_app.initialize()
        await telegram_app.process_update(update)
        await telegram_app.shutdown()

    asyncio.run(process())
    return "OK", 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
