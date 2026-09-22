"""
TOTP-based Authentication Module
---------------------------------
Implements a full signup -> QR enrollment -> verified login flow using
Time-based One-Time Passwords (RFC 6238), on top of a normal
username/password first factor.

Flow:
1. /register   -> user picks username + password (hashed with PBKDF2)
                  a random Base32 TOTP secret is generated
2. /enroll     -> shows QR code (otpauth:// URI) for the user to scan
                  in Google Authenticator / Authy / etc. User must enter
                  one valid 6-digit code to confirm enrollment (proves
                  they actually scanned it) before the account goes live.
3. /login      -> username + password (factor 1) then, if correct,
                  redirected to /login/otp for the 6-digit TOTP code
                  (factor 2). Session flags track partial vs full auth.
4. /dashboard  -> protected route, only reachable after both factors pass.

Storage: a local JSON "database" (users.json) for demo purposes.
Swap `db.py` for a real DB (SQLite/Postgres) in production.
"""

import base64
import hashlib
import io
import json
import os
import secrets
import time
from datetime import datetime, timezone

import pyotp
import qrcode
from flask import (Flask, flash, redirect, render_template, request,
                    session, url_for, send_file)

APP_NAME = "Aegis"          # Shown inside the authenticator app
DB_FILE = os.path.join(os.path.dirname(__file__), "users.json")
HISTORY_FILE = os.path.join(os.path.dirname(__file__), "history.json")
PBKDF2_ITERATIONS = 200_000

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


# --------------------------------------------------------------------------
# Tiny JSON "database" helpers
# --------------------------------------------------------------------------
def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)


def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return base64.b64encode(salt).decode(), base64.b64encode(dk).decode()


def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    salt = base64.b64decode(salt_b64)
    _, new_hash = hash_password(password, salt)
    return secrets.compare_digest(new_hash, hash_b64)


# --------------------------------------------------------------------------
# Security event log (backs the dashboard's stats + activity feed)
# --------------------------------------------------------------------------
def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r") as f:
        return json.load(f)


def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def log_event(username: str, event: str, status: str):
    """status: 'success' | 'failed' | 'info'"""
    history = load_history()
    history.append({
        "username": username,
        "event": event,
        "status": status,
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ip": request.remote_addr,
    })
    save_history(history)


def user_history(username: str, limit: int = 8):
    events = [e for e in load_history() if e["username"] == username]
    return list(reversed(events))[:limit]


def user_stats(username: str):
    events = [e for e in load_history() if e["username"] == username]
    successful_logins = sum(1 for e in events if e["event"] == "Login Successful" and e["status"] == "success")
    failed_attempts = sum(1 for e in events if e["status"] == "failed")
    last_login = next((e["time"] for e in reversed(events) if e["event"] == "Login Successful"), None)
    return {
        "successful_logins": successful_logins,
        "failed_attempts": failed_attempts,
        "last_login": last_login,
    }


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("home.html", user=session.get("user"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db = load_db()
        if username in db:
            flash("Username already exists.", "error")
            return redirect(url_for("register"))

        salt, pw_hash = hash_password(password)
        secret = pyotp.random_base32()  # 160-bit shared secret

        db[username] = {
            "salt": salt,
            "password_hash": pw_hash,
            "totp_secret": secret,
            "totp_confirmed": False,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        save_db(db)
        log_event(username, "Account Registered", "info")

        # stash username to carry into the enrollment step
        session["pending_enroll"] = username
        return redirect(url_for("enroll"))

    return render_template("register.html")


@app.route("/enroll", methods=["GET", "POST"])
def enroll():
    username = session.get("pending_enroll")
    if not username:
        return redirect(url_for("register"))

    db = load_db()
    user = db.get(username)
    if not user:
        return redirect(url_for("register"))

    if request.method == "POST":
        code = request.form["code"].strip()
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(code, valid_window=1):  # +/- 30s clock drift
            user["totp_confirmed"] = True
            save_db(db)
            log_event(username, "Two-Factor Authentication Enabled", "success")
            session.pop("pending_enroll", None)
            flash("Two-factor authentication enabled. Please log in.", "success")
            return redirect(url_for("login"))
        else:
            log_event(username, "2FA Enrollment - Invalid Code", "failed")
            flash("Invalid code, try again.", "error")

    uri = pyotp.totp.TOTP(user["totp_secret"]).provisioning_uri(
        name=username, issuer_name=APP_NAME
    )
    return render_template("enroll.html", uri=uri, secret=user["totp_secret"])


@app.route("/qr")
def qr():
    """Serves the QR code image for the pending enrollment."""
    username = session.get("pending_enroll")
    db = load_db()
    user = db.get(username)
    if not user:
        return "", 404

    uri = pyotp.totp.TOTP(user["totp_secret"]).provisioning_uri(
        name=username, issuer_name=APP_NAME
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db = load_db()
        user = db.get(username)
        if not user or not verify_password(password, user["salt"], user["password_hash"]):
            if user:  # avoid logging noise for made-up usernames
                log_event(username, "Login Attempt - Wrong Password", "failed")
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        if not user["totp_confirmed"]:
            flash("2FA not set up for this account.", "error")
            return redirect(url_for("login"))

        # Factor 1 passed -> stage for factor 2, do NOT fully authenticate yet
        session["awaiting_otp"] = username
        return redirect(url_for("login_otp"))

    return render_template("login.html")


@app.route("/login/otp", methods=["GET", "POST"])
def login_otp():
    username = session.get("awaiting_otp")
    if not username:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form["code"].strip()
        db = load_db()
        user = db.get(username)
        totp = pyotp.TOTP(user["totp_secret"])

        if totp.verify(code, valid_window=1):
            session.pop("awaiting_otp", None)
            session["user"] = username  # fully authenticated
            log_event(username, "Login Successful", "success")
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            log_event(username, "Login Attempt - Invalid OTP", "failed")
            flash("Invalid or expired code.", "error")

    return render_template("login_otp.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    username = session["user"]
    db = load_db()
    user = db.get(username, {})
    stats = user_stats(username)
    activity = user_history(username, limit=8)

    created_at = user.get("created_at")
    account_age_days = None
    if created_at:
        created_dt = datetime.fromisoformat(created_at)
        account_age_days = (datetime.now(timezone.utc) - created_dt).days

    return render_template(
        "dashboard.html",
        user=username,
        stats=stats,
        activity=activity,
        account_age_days=account_age_days,
        created_at=created_at,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
