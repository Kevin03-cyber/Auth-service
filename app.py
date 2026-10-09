import jwt
import datetime
import io
import base64
import sqlite3
import time
import bcrypt
import pyotp
import qrcode
import os
import secrets
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
# read from an environment variable; random fallback for local use
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
# signs the tokens; set JWT_SECRET in the environment so tokens survive restarts
JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
DB = "users.db"

MAX_FAILED = 5
LOCK_SECONDS = 300       # set to 60 while testing
PRE_2FA_SECONDS = 300    # time allowed to type the code after the password

limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until REAL NOT NULL DEFAULT 0,
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0
        )
    """)
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)")]
    if "failed_attempts" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
    if "locked_until" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN locked_until REAL NOT NULL DEFAULT 0")
    if "totp_secret" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    if "totp_enabled" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", need_login=1))
        return f(*args, **kwargs)
    return wrapper

def make_token(user, minutes=30, purpose="access"):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "purpose": purpose,          # "access" = full login, "2fa" = half-finished login
        "iat": now,
        "exp": now + datetime.timedelta(minutes=minutes),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def read_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:   # bad signature, expired, malformed
        return None


@app.errorhandler(429)
def too_many_requests(e):
    return render_template(
        "login.html",
        message="Too many attempts from your device. Wait a minute and try again."
    ), 429


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def register():
    message = None
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if not email or "@" not in email:
            message = "Enter a valid email."
        elif len(password) < 8:
            message = "Password must be at least 8 characters."
        else:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            conn = get_db()
            try:
                conn.execute(
                    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                    (email, hashed),
                )
                conn.commit()
                return redirect(url_for("login", registered=1))
            except sqlite3.IntegrityError:
                message = "That email is already registered."
            finally:
                conn.close()
    return render_template("register.html", message=message)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    message = None
    if request.args.get("registered"):
        message = "Account created. Please log in."
    elif request.args.get("need_login"):
        message = "Please log in first."
    elif request.args.get("loggedout"):
        message = "You have been logged out."
    elif request.args.get("locked"):
        message = "Too many failed attempts. Account locked for a few minutes."

    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        now = time.time()

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user and user["locked_until"] > now:
            minutes_left = int((user["locked_until"] - now) // 60) + 1
            message = f"Account locked. Try again in {minutes_left} minute(s)."

        elif user and bcrypt.checkpw(password.encode(), user["password_hash"]):
            if user["totp_enabled"]:
                # password is right, but the code is still needed.
                # do NOT reset failed_attempts here, only after the code passes
                conn.close()
                session.clear()
                session["pre_2fa_user_id"] = user["id"]
                session["pre_2fa_time"] = now
                return redirect(url_for("login_2fa"))

            # no 2FA on this account: finish the login
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?",
                (user["id"],),
            )
            conn.commit()
            conn.close()
            session.clear()
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))

        else:
            message = "Invalid email or password."
            if user:
                failed = user["failed_attempts"] + 1
                if failed >= MAX_FAILED:
                    conn.execute(
                        "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                        (now + LOCK_SECONDS, user["id"]),
                    )
                    message = "Too many failed attempts. Account locked for a few minutes."
                else:
                    conn.execute(
                        "UPDATE users SET failed_attempts = ? WHERE id = ?",
                        (failed, user["id"]),
                    )
                conn.commit()
        conn.close()
    return render_template("login.html", message=message)


@app.route("/login-2fa", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login_2fa():
    user_id = session.get("pre_2fa_user_id")
    started = session.get("pre_2fa_time", 0)
    now = time.time()

    # no password step done, or it took too long
    if not user_id or now - started > PRE_2FA_SECONDS:
        session.clear()
        return redirect(url_for("login", need_login=1))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        conn.close()
        session.clear()
        return redirect(url_for("login", need_login=1))

    message = None

    if user["locked_until"] > now:
        conn.close()
        session.clear()
        return redirect(url_for("login", locked=1))

    if request.method == "POST":
        code = request.form["code"].strip()

        if pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            # fully logged in now
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?",
                (user["id"],),
            )
            conn.commit()
            conn.close()
            session.clear()
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))

        # wrong code counts toward the same lockout
        failed = user["failed_attempts"] + 1
        if failed >= MAX_FAILED:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                (now + LOCK_SECONDS, user["id"]),
            )
            conn.commit()
            conn.close()
            session.clear()
            return redirect(url_for("login", locked=1))
        conn.execute(
            "UPDATE users SET failed_attempts = ? WHERE id = ?",
            (failed, user["id"]),
        )
        conn.commit()
        message = "Wrong code. Try the latest 6-digit code from your app."

    conn.close()
    return render_template("login_2fa.html", message=message)


@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    user = conn.execute(
        "SELECT totp_enabled FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    conn.close()
    return render_template(
        "dashboard.html",
        email=session["email"],
        twofa=bool(user["totp_enabled"]),
        just_enabled=request.args.get("twofa"),
    )


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def setup_2fa():
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()

    if user["totp_enabled"]:
        conn.close()
        return redirect(url_for("dashboard"))

    if "pending_secret" not in session:
        session["pending_secret"] = pyotp.random_base32()
    secret = session["pending_secret"]
    totp = pyotp.TOTP(secret)

    message = None
    if request.method == "POST":
        code = request.form["code"].strip()
        if totp.verify(code, valid_window=1):
            conn.execute(
                "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
                (secret, user["id"]),
            )
            conn.commit()
            conn.close()
            session.pop("pending_secret", None)
            return redirect(url_for("dashboard", twofa=1))
        message = "Wrong code. Use the latest 6-digit code from your app."
    conn.close()

    uri = totp.provisioning_uri(name=user["email"], issuer_name="Kevin Auth")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template("setup_2fa.html", qr=qr_b64, secret=secret, message=message)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login", loggedout=1))

@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per minute")
def api_register():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or "@" not in email:
        return jsonify(error="Enter a valid email."), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, hashed),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="That email is already registered."), 409
    finally:
        conn.close()
    return jsonify(message="Account created."), 201


@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute")
def api_login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    now = time.time()

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()

    if user and user["locked_until"] > now:
        conn.close()
        return jsonify(error="Account locked. Try again later."), 423

    if user and bcrypt.checkpw(password.encode(), user["password_hash"]):
        if user["totp_enabled"]:
            # password is right, but the code is still needed.
            # do NOT reset failed_attempts here, only after the code passes
                 conn.close()
                 return jsonify(
                    two_factor_required=True,
                    temp_token=make_token(user, minutes=5, purpose="2fa"),
            )
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?",
            (user["id"],),
        )
        conn.commit()
        conn.close()
        return jsonify(token=make_token(user))

    # wrong email or password: same lockout rules as the web login
    if user:
        failed = user["failed_attempts"] + 1
        if failed >= MAX_FAILED:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                (now + LOCK_SECONDS, user["id"]),
            )
        else:
            conn.execute(
                "UPDATE users SET failed_attempts = ? WHERE id = ?",
                (failed, user["id"]),
            )
        conn.commit()
    conn.close()
    return jsonify(error="Invalid email or password."), 401

@app.route("/api/login/2fa", methods=["POST"])
@limiter.limit("10 per minute")
def api_login_2fa():
    data = request.get_json(silent=True) or {}
    temp_token = str(data.get("temp_token", ""))
    code = str(data.get("code", "")).strip()
    now = time.time()

    claims = read_token(temp_token)
    if not claims or claims.get("purpose") != "2fa":
        return jsonify(error="Invalid or expired temporary token. Log in again."), 401

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (int(claims["sub"]),)
    ).fetchone()

    if not user or not user["totp_enabled"]:
        conn.close()
        return jsonify(error="Invalid or expired temporary token. Log in again."), 401

    if user["locked_until"] > now:
        conn.close()
        return jsonify(error="Account locked. Try again later."), 423

    if pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?",
            (user["id"],),
        )
        conn.commit()
        conn.close()
        return jsonify(token=make_token(user))   # the real token, purpose "access"

    # wrong code counts toward the same lockout as wrong passwords
    failed = user["failed_attempts"] + 1
    if failed >= MAX_FAILED:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
            (now + LOCK_SECONDS, user["id"]),
        )
    else:
        conn.execute(
            "UPDATE users SET failed_attempts = ? WHERE id = ?",
            (failed, user["id"]),
        )
    conn.commit()
    conn.close()
    return jsonify(error="Wrong code."), 401

@app.route("/api/verify", methods=["GET"])
def api_verify():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return jsonify(valid=False, error="Missing token."), 401

    claims = read_token(header[7:])
    if not claims or claims.get("purpose") != "access":
        return jsonify(valid=False, error="Invalid or expired token."), 401

    return jsonify(valid=True, user_id=claims["sub"], email=claims["email"])
if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=5001)