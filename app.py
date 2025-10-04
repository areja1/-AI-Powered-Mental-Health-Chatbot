import sys
import os
import pathlib

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

# ---------- OpenAI (v1.x) ----------
# Make sure requirements include: openai>=1.40.0
from openai import OpenAI, APIConnectionError, APIStatusError, AuthenticationError

# Load .env BEFORE reading any environment variables
load_dotenv()

# ---- App + security flags ----
app = Flask(__name__, template_folder="templates", static_folder="static")

BASE_DIR = pathlib.Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)

# Cookie flags (set SESSION_COOKIE_SECURE=1 in production)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
app.config["REMEMBER_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"

# --- Testing mode (used by CI/unit tests) ---
# Set TESTING=1 in CI so imports don’t fail without OPENAI_API_KEY.
app.config["TESTING"] = os.getenv("TESTING", "0") == "1"

# --- Config (production-safe defaults & DB url normalization) ---
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-not-secure")
app.config["WTF_CSRF_TIME_LIMIT"] = None  # avoid token expiry during quick tests
app.config["WTF_CSRF_SSL_STRICT"] = False  # don't require HTTPS Referer header (token still validated)
app.config["WTF_CSRF_TRUSTED_ORIGINS"] = [
    "ai-powered-mental-health-chatbot.onrender.com",
    "localhost",
    "127.0.0.1",
]

db_url = os.getenv("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    # SQLAlchemy expects "postgresql://"
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# On Vercel, deployment FS is read-only; only /tmp is writable.
# If no DATABASE_URL is provided, use SQLite in /tmp.
if not db_url:
    if os.getenv("VERCEL") == "1":
        sqlite_uri = "sqlite:////tmp/users.db"
    else:
        sqlite_uri = f"sqlite:///{(INSTANCE_DIR / 'users.db').as_posix()}"
    app.config["SQLALCHEMY_DATABASE_URI"] = sqlite_uri
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# CSRF for all unsafe methods
csrf = CSRFProtect(app)

# Make {{ csrf_token() }} available in templates without FlaskForm
@app.context_processor
def inject_csrf():
    return {"csrf_token": generate_csrf}

# Security headers (basic, safe defaults)
@app.after_request
def set_security_headers(resp):
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    # Allow same-origin Referer so Flask-WTF can validate CSRF correctly
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    # Keep CSP simple; we serve only our own JS/CSS.
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';"
    )
    # Prevent caching of sensitive auth pages (stops BFCache/memory cache)
    try:
        ep = request.endpoint or ""
    except Exception:
        ep = ""
    if ep in {"login", "signup"}:
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp

# Error handler for nice logs on CSRF failures
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    app.logger.error(f"CSRF error: {e.description}")
    return render_template("login.html", error=e.description), 400

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ---------- Database Models ----------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- OpenAI client ----------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY and not app.config["TESTING"]:
    # In production, we require a real key.
    raise ValueError("The OpenAI API key was not found. Set OPENAI_API_KEY in your environment.")
# In tests (TESTING=1), allow client to be None. Routes must guard before use.
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# ---------- Health ----------
@app.get("/health")
def health():
    return jsonify({"ok": True})

# ---------- Routes ----------
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    import re
    # If already signed in, show an interstitial instead of redirecting
    if request.method == "GET" and current_user.is_authenticated:
        return render_template("signed_in_gate.html", user=current_user)

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""

        # Basic required checks
        if not username or not email or not password or not confirm:
            flash("All fields are required.", "danger")
            return redirect(url_for("signup"))

        # Username rules
        if len(username) < 3 or len(username) > 150:
            flash("Username must be between 3 and 150 characters.", "danger")
            return redirect(url_for("signup"))

        # Email format (server-side)
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Please enter a valid email address.", "danger")
            return redirect(url_for("signup"))

        # Password rules
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("signup"))
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("signup"))

        # Duplicates
        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "danger")
            return redirect(url_for("signup"))
        if User.query.filter_by(username=username).first():
            flash("That username is already taken.", "danger")
            return redirect(url_for("signup"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Redirect to login with a success modal
        flash("Account created successfully!", "success")
        return redirect(url_for("login", registered=1))

    # Always return the template on GET
    return render_template("signup.html")

# Lightweight auth state probe for back/forward cache handling
@app.get("/auth/state")
def auth_state():
    return jsonify({"authenticated": bool(current_user.is_authenticated)})

@app.route("/login", methods=["GET", "POST"])
def login():
    # If already signed in, show an interstitial instead of redirecting
    if request.method == "GET" and current_user.is_authenticated:
        return render_template("signed_in_gate.html", user=current_user)

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("chat"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("login"))

@app.route("/chat", methods=["GET"])
@login_required
def chat():
    return render_template("chat.html", user=current_user)

@app.route("/chatbot", methods=["POST"])
@login_required
def chatbot():
    data = request.get_json(silent=True) or {}
    user_input = (data.get("message") or "").strip()
    if not user_input:
        return jsonify({"reply": "I didn't receive any input.", "crisis": False})

    # Crisis keywords (simple substring checks)
    CRISIS_KEYWORDS = ["suicide", "hurt myself", "kill myself", "depressed", "self-harm"]
    if any(kw in user_input.lower() for kw in CRISIS_KEYWORDS):
        crisis_response = (
            "It sounds like you might be in a crisis. Please reach out to a trusted person "
            "or contact your local emergency number. In the U.S., you can call or text 988 "
            "to reach the Suicide & Crisis Lifeline. You can also speak with a licensed mental health professional."
        )
        return jsonify({"reply": crisis_response, "crisis": True})

    # If we don't have a client (TESTING mode), return a stub response
    if client is None:
        return jsonify({
            "reply": "Test mode: OpenAI client not initialized. (Set OPENAI_API_KEY in production.)",
            "crisis": False
        }), 200

    try:
        # Modern OpenAI API call (v1.x)
        response = client.chat.completions.create(
            model="gpt-4o",  # or "gpt-4o-mini" for faster/cheaper
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a supportive, empathetic mental health assistant. "
                        "Offer gentle guidance and coping strategies, but do not provide medical diagnosis."
                    ),
                },
                {"role": "user", "content": user_input},
            ],
            temperature=0.7,
            max_tokens=200,
        )
        assistant_reply = (response.choices[0].message.content or "").strip()
        if not assistant_reply:
            assistant_reply = "I'm here with you. Could you share a bit more about how you're feeling?"
        return jsonify({"reply": assistant_reply, "crisis": False})

    except AuthenticationError:
        return jsonify({"reply": "Authentication with the AI service failed. Please check server API keys.", "crisis": False}), 500
    except APIConnectionError:
        return jsonify({"reply": "I’m having trouble reaching the AI service. Please try again in a moment.", "crisis": False}), 502
    except APIStatusError as e:
        return jsonify({"reply": f"The AI service returned an error ({e.status_code}). Please try again later.", "crisis": False}), 502
    except Exception as e:
        # Log the error server-side; return a generic message to the client
        print("Chatbot error:", repr(e))
        return jsonify({"reply": "Sorry, I’m having trouble processing that request right now.", "crisis": False}), 500

# ---------------- Entry Point (local dev only) ----------------
def _run_tests_before_server():
    """
    Discover and run tests from ./tests or ./test using unittest.
    Prints PASS/FAIL to console. Returns True if all pass, else False.
    """
    import unittest
    print("\n================= Running test suite =================")
    root_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(root_dir)
    candidates = ["tests", "test"]
    start = next((c for c in candidates if os.path.isdir(os.path.join(root_dir, c))), None)
    if not start:
        print(f"No tests/ or test/ directory found at: {root_dir} — skipping tests.")
        print("======================================================\n")
        return True
    suite = unittest.defaultTestLoader.discover(start_dir=start, pattern="test_*.py")
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    print("======================================================\n")
    return result.wasSuccessful()

if __name__ == "__main__":
    # Automatically run tests; skip with --skip-tests or SKIP_TESTS=1.
    skip = "--skip-tests" in sys.argv or os.getenv("SKIP_TESTS") == "1"
    is_reloader = os.getenv("WERKZEUG_RUN_MAIN") == "true"
    force_every_start = os.getenv("RUN_TESTS_EVERY_START") == "1"

    if skip:
        print("⚠️  Skipping tests (--skip-tests or SKIP_TESTS=1). Starting the server...\n")
    elif is_reloader and not force_every_start:
        print("⏩ Dev reloader cycle detected — skipping tests this time.\n")
    else:
        ok = _run_tests_before_server()
        if not ok:
            print("❌ Tests failed. Not starting the server.")
            sys.exit(1)
        print("✅ All tests passed. Starting the server...\n")

    with app.app_context():
        db.create_all()

    # Local development server (use Gunicorn on Render / Serverless on Vercel)
    app.run(debug=True)
