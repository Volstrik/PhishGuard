# app.py
import base64
import time
import requests
from flask import (
    Flask, render_template, request,
    jsonify, redirect, url_for,
    flash, session
)
from flask_login import (
    LoginManager, UserMixin,
    login_user, logout_user,
    login_required, current_user
)
from functools import wraps
from config import Config
from database import (
    init_db, save_scan,
    get_all_scans, get_user_scans,
    get_stats, get_top_threats,
    get_user_by_username, get_user_by_id,
    create_user, get_all_users,
    delete_scan, get_admin_stats,
    verify_password
)
from osint import extract_domain, get_whois_info, get_ssl_info, calculate_osint_risk_modifier
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# ── FLASK-LOGIN SETUP ────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view       = "login"
login_manager.login_message    = "Please log in to access PhishGuard."

class User(UserMixin):
    def __init__(self, row):
        self.id       = row["id"]
        self.username = row["username"]
        self.email    = row["email"]
        self.is_admin = bool(row["is_admin"])

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    row = get_user_by_id(int(user_id))
    return User(row) if row else None


# ── ADMIN DECORATOR ──────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# ── INIT DB ─────────────────────────────────────────────────────
with app.app_context():
    init_db()


# ════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # Validation
        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("auth/register.html")

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
            return render_template("auth/register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("auth/register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("auth/register.html")

        success, msg = create_user(username, email, password, is_admin=False)

        if success:
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash(msg, "error")

    return render_template("auth/register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username     = request.form.get("username", "").strip()
        password     = request.form.get("password", "")
        admin_key    = request.form.get("admin_key", "").strip()
        remember_me  = request.form.get("remember_me") == "on"
        is_admin_attempt = bool(admin_key)

        # Get user from DB
        row = get_user_by_username(username)

        if not row or not verify_password(password, row["password_hash"]):
            flash("Invalid username or password.", "error")
            return render_template("auth/login.html")

        user = User(row)

        # Admin access attempt
        if is_admin_attempt:
            if admin_key != Config.ADMIN_SECRET_KEY:
                flash("Invalid admin key.", "error")
                return render_template("auth/login.html")
            if not user.is_admin:
                flash("This account does not have admin privileges.", "error")
                return render_template("auth/login.html")
            login_user(user, remember=remember_me)
            return redirect(url_for("admin_dashboard"))

        # Normal user login
        login_user(user, remember=remember_me)
        next_page = request.args.get("next")
        return redirect(next_page or url_for("dashboard"))

    return render_template("auth/login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ════════════════════════════════════════════════════════════════
# USER ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def dashboard():
    user_id = current_user.id
    stats       = get_stats(user_id=user_id)
    top_threats = get_top_threats(user_id=user_id)
    scans       = get_user_scans(user_id=user_id)

    trend_scores = [row["score"] for row in scans[:20]]
    trend_scores.reverse()

    return render_template(
        "dashboard.html",
        stats=stats,
        top_threats=top_threats,
        trend_scores=trend_scores
    )


@app.route("/scanner")
@login_required
def scanner():
    return render_template("scanner.html")


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    data = request.get_json()
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    result, error = scan_url_virustotal(url)

    if error:
        return jsonify({"error": error}), 500

    # ── OSINT ENRICHMENT ──────────────────────────────────────
    try:
        domain     = extract_domain(url)
        whois_data = get_whois_info(domain)
        ssl_data   = get_ssl_info(domain)

        osint_modifier, osint_warnings = calculate_osint_risk_modifier(whois_data, ssl_data)
    except Exception:
        domain          = extract_domain(url)
        whois_data      = {"available": False, "registrar": "Unavailable", "created_date": "Unavailable", "age_days": None, "age_label": "Could not retrieve", "is_new_domain": False}
        ssl_data        = {"available": False, "has_ssl": False, "issuer": None, "valid_from": None, "valid_until": None, "is_valid": False, "days_left": None, "expiring_soon": False}
        osint_modifier  = 0
        osint_warnings  = []
    # Blend OSINT signal into the final score (capped at 100)
    adjusted_score = min(result["score"] + osint_modifier, 100)

    # Re-evaluate risk level if OSINT pushed the score into a new band
    if adjusted_score == 0:
        adjusted_risk = "Safe"
    elif adjusted_score <= 30:
        adjusted_risk = "Suspicious"
    elif adjusted_score <= 60:
        adjusted_risk = "High Risk"
    else:
        adjusted_risk = "Malicious"

    result["score"]      = adjusted_score
    result["risk_level"] = adjusted_risk
    result["domain"]     = domain
    result["whois"]      = whois_data
    result["ssl"]        = ssl_data
    result["osint_warnings"] = osint_warnings

    save_scan(
        url        = result["url"],
        score      = result["score"],
        risk_level = result["risk_level"],
        safe       = result["safe"],
        malicious  = result["malicious"],
        suspicious = result["suspicious"],
        undetected = result["undetected"],
        user_id    = current_user.id
    )

    return jsonify(result), 200

@app.route("/history")
@login_required
def history():
    scans = get_user_scans(current_user.id)
    return render_template("history.html", scans=scans)


@app.route("/reports")
@login_required
def reports():
    stats = get_stats(user_id=current_user.id)
    scans = get_user_scans(current_user.id)
    return render_template("reports.html", stats=stats, scans=scans)


# ════════════════════════════════════════════════════════════════
# ADMIN ROUTES
# ════════════════════════════════════════════════════════════════

@app.route("/admin/dashboard")
@login_required
@admin_required
def admin_dashboard():
    stats       = get_stats()
    top_threats = get_top_threats(limit=10)
    all_scans   = get_all_scans()
    all_users   = get_all_users()
    admin_stats = get_admin_stats()

    trend_scores = [row["score"] for row in all_scans[:20]]
    trend_scores.reverse()

    return render_template(
        "admin/dashboard.html",
        stats       = stats,
        top_threats = top_threats,
        all_scans   = all_scans,
        all_users   = all_users,
        admin_stats = admin_stats,
        trend_scores= trend_scores
    )


@app.route("/admin/delete-scan/<int:scan_id>", methods=["POST"])
@login_required
@admin_required
def admin_delete_scan(scan_id):
    delete_scan(scan_id)
    return jsonify({"success": True}), 200


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users = get_all_users()
    return render_template("admin/users.html", users=users)


# ════════════════════════════════════════════════════════════════
# VIRUSTOTAL HELPERS
# ════════════════════════════════════════════════════════════════

def calculate_risk(malicious, suspicious, total_engines):
    if total_engines == 0:
        return 0, "Safe"
    raw   = ((malicious * 2) + suspicious) / (total_engines * 2) * 100
    score = min(int(raw), 100)
    if score == 0:        risk_level = "Safe"
    elif score <= 30:     risk_level = "Suspicious"
    elif score <= 60:     risk_level = "High Risk"
    else:                 risk_level = "Malicious"
    return score, risk_level

def scan_url_virustotal(url):
    headers = {
        "x-apikey": Config.VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # ── Step 1: Submit URL ────────────────────────────────────
    try:
        submit = requests.post(
            Config.VIRUSTOTAL_URL,
            headers=headers,
            data=f"url={url}",
            timeout=10  # hard cap — was missing before
        )
    except requests.exceptions.RequestException:
        return None, "Could not reach VirusTotal. Check your internet connection."

    if submit.status_code != 200:
        return None, f"Failed to submit URL to VirusTotal (status {submit.status_code})"

    analysis_id = submit.json().get("data", {}).get("id")
    if not analysis_id:
        return None, "No analysis ID returned"

    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

  # ── Step 2: Poll for result ────────────────────────────────
    max_attempts = 8
    poll_interval = 5  # was 3 — fewer requests per minute

    for attempt in range(max_attempts):
        time.sleep(poll_interval)

        try:
            res = requests.get(
                analysis_url,
                headers=headers,
                timeout=10
            )
        except requests.exceptions.RequestException:
            continue

        # ── Rate limit hit — surface this clearly instead of silent retry ──
        if res.status_code == 429:
            return None, "VirusTotal rate limit reached. Please wait a minute before scanning again."

        if res.status_code != 200:
            continue

        data   = res.json()
        status = data.get("data", {}).get("attributes", {}).get("status")

        if status == "completed":
            s          = data["data"]["attributes"]["stats"]
            malicious  = s.get("malicious",  0)
            suspicious = s.get("suspicious", 0)
            safe       = s.get("harmless",   0)
            undetected = s.get("undetected", 0)
            total      = malicious + suspicious + safe + undetected
            score, risk_level = calculate_risk(malicious, suspicious, total)
            return {
                "url":           url,
                "score":         score,
                "risk_level":    risk_level,
                "malicious":     malicious,
                "suspicious":    suspicious,
                "safe":          safe,
                "undetected":    undetected,
                "total_engines": total
            }, None

    return None, "Analysis timed out after multiple attempts. Please try again."

# ════════════════════════════════════════════════════════════════
# RUN
# ════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app.run(debug=True)
    