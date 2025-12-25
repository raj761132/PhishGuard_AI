import os
<<<<<<< HEAD
import random
import datetime
<<<<<<< HEAD
import psutil
import requests
import socket
import uuid  # Added for generating Case IDs
from urllib.parse import urlparse
=======
import socket
import datetime
import socket

from flask_login import UserMixin
from mongoengine import Document, StringField, BooleanField
from mongoengine import StringField
>>>>>>> 032d40b28ea50efd0478bb8f2882f5af5a0fe468

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, jsonify, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from flask_mongoengine import MongoEngine
from flask_mail import Mail, Message
=======
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
<<<<<<< HEAD

# Import your existing ML logic
# Ensure this file exists in services/final_verdict.py
try:
    from services.final_verdict import final_verdict
except ImportError:
    # Fallback for testing if file is missing
    def final_verdict(url):
        return {
            "url": url,
            "final_verdict": "SUSPICIOUS (Demo)",
            "risk_level": "High",
            "score": 85,
            "ssl": {"risk": "High", "reason": "Self-signed"},
            "url_analysis": {"risk": "Malicious"},
            "brand": {"impersonation": True, "brand": "DemoBank"},
            "signals": ["Typosquatting detected"]
        }

# --- IMPORT DATABASE LOGIC ---
# Ensure db.py is in the same folder
from db import db, User

# ==========================================
# 1. LOAD ENV & APP INIT
# ==========================================
=======
from services.final_verdict import final_verdict
from routes.org_routes.org_bp import org_bp
>>>>>>> 032d40b28ea50efd0478bb8f2882f5af5a0fe468

load_dotenv()

app = Flask(__name__)
<<<<<<< HEAD
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")
=======
app.register_blueprint(org_bp)
app.secret_key = os.getenv("SECRET_KEY")
>>>>>>> 032d40b28ea50efd0478bb8f2882f5af5a0fe468

<<<<<<< HEAD
UPLOAD_FOLDER = "static/uploads/kyc_docs"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
=======
# --- FILE UPLOAD CONFIG ---
UPLOAD_FOLDER = 'static/uploads/kyc_docs'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

mail = Mail(app)

app.config["MONGODB_SETTINGS"] = {
    "host": os.getenv("MONGO_URI", "mongodb://localhost:27017/phishguard") # Added default local fallback
}

<<<<<<< HEAD
db = MongoEngine()
db.init_app(app)
 
with app.app_context():
    try:
        db.connection.server_info()
        print("✅ MongoDB connected successfully")
    except Exception as e:
        print("❌ MongoDB connection failed")
        print(e)
=======
# --- INITIALIZE DB ---
db.init_app(app)
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c

<<<<<<< HEAD
# TEST CONNECTION SAFELY
with app.app_context():
    try:
        db.connection.server_info()
        print("✅ MongoDB connected successfully")
    except Exception as e:
        print("❌ MongoDB connection failed")
        print(e)

<<<<<<< HEAD
# ==========================================
# 5. DB MODELS
# ==========================================
=======
#USER MODEL
>>>>>>> 032d40b28ea50efd0478bb8f2882f5af5a0fe468

class User(db.Document, UserMixin):
    meta = {"collection": "users", "strict": False}

    # Common (ALL users)
    email = db.StringField(required=True, unique=True)
    password_hash = db.StringField(required=True)
    role = db.StringField(required=True)  # citizen | org | admin
    created_at = db.DateTimeField(default=datetime.datetime.utcnow)

    # Verification / approval (used for org/admin only)
    is_verified = db.BooleanField(default=True)
    is_approved = db.BooleanField(default=False)

    # Citizen fields
    full_name = db.StringField()
    phone = db.StringField()

    # Organization fields
    org_name = db.StringField()
    category = db.StringField()
    cin = db.StringField()
    designation = db.StringField()
    domain = db.StringField()

    # Documents
    auth_doc_path = db.StringField()
    incorp_doc_path = db.StringField()

    # OTP (org only)
    otp_code = db.StringField()
    otp_expiry = db.DateTimeField()

    def get_id(self):
        return str(self.id)

# Stats Model (For real-time dashboard data)
class SystemStats(db.Document):
    meta = {"collection": "system_stats", "strict": False}
    total_scans = db.IntField(default=0)
    threats_blocked = db.IntField(default=0)
    last_updated = db.DateTimeField(default=datetime.datetime.utcnow)

# NEW: Case Model for Reporting
class Case(db.Document):
    meta = {"collection": "cases", "strict": False}
    case_id = db.StringField(required=True, unique=True)
    target = db.StringField(required=True)
    report_data = db.DictField() # Store the full scan result
    reported_by = db.StringField() # Email of user who reported
    status = db.StringField(default="Pending") # Pending, Investigating, Resolved
    timestamp = db.DateTimeField(default=datetime.datetime.utcnow)

# ==========================================
# 6. HELPER FUNCTIONS
# ==========================================

def get_ip_details(url):
    """
    Resolves domain to IP and fetches Geo-Location + LAT/LON
    """
    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not domain:
            domain = url.split('/')[0]

        try:
            ip_address = socket.gethostbyname(domain)
        except:
            return {"ip": "0.0.0.0", "country": "Unknown", "isp": "Unknown", "lat": 0, "lon": 0}

        # Requesting status, country, countryCode, isp, lat, lon
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,isp,lat,lon", timeout=5)
        data = response.json()

        if data.get('status') == 'success':
            return {
                "ip": ip_address,
                "country": data.get('countryCode', 'Unknown'),
                "country_full": data.get('country', 'Unknown'),
                "isp": data.get('isp', 'Unknown'),
                "lat": data.get('lat', 0),   # Latitude
                "lon": data.get('lon', 0)    # Longitude
            }
        else:
            return {"ip": ip_address, "country": "Unknown", "country_full": "Unknown", "isp": "Unknown", "lat": 0, "lon": 0}

    except Exception as e:
        print(f"Geo-IP Lookup Failed: {e}")
        return {"ip": "0.0.0.0", "country": "Unknown", "isp": "Hidden", "lat": 0, "lon": 0}

# ==========================================
# 7. LOGIN MANAGER
# ==========================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_citizen"

=======
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c
@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()

def verify_domain(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False

# ==========================================
<<<<<<< HEAD
# 8. ROUTES
=======
# 2. ROUTES & LOGIC
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")

# ---------------- CITIZEN (NO OTP) ------------------

@app.route("/register-citizen", methods=["GET", "POST"])
def register_citizen():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = 'citizen'

        existing_user = User.objects(email=email).first()
        if existing_user:
            flash('Email already registered. Please login.', 'danger')
            return redirect(url_for('login_citizen'))

        User(
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            otp_code=otp,
            otp_expiry=expiry,
            is_verified=False,
            full_name=request.form.get('full_name'),
            phone=request.form.get('phone')
        )

        try:
            new_user.save()
            
            msg = Message('Your OTP Verification Code', 
                          sender='noreply@cyberportal.gov', 
                          recipients=[email])
            msg.body = f"Your Code: {otp}"
            mail.send(msg)
            
            session['email_to_verify'] = email
            flash('Registration successful! Please verify OTP.', 'info')
            return redirect(url_for('verify_otp'))
            
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('register_citizen'))

    return render_template("citizen-register.html")

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        email = session.get('email_to_verify')

        if not email:
            flash('Session expired. Please register again.', 'danger')
            return redirect(url_for('register_citizen'))

        user = User.objects(email=email).first()

        if user and user.otp_code == entered_otp:
            user.is_verified = True
            user.otp_code = None
            user.save()
            session.pop('email_to_verify', None)
            flash('Account Verified! Please login.', 'success')
            return redirect(url_for('login_citizen'))
        else:
            flash('Invalid or Expired OTP', 'danger')

    return render_template('otp-verify.html')

@app.route('/login', methods=['GET', 'POST'])
def login_citizen():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.objects(email=email, role="citizen").first()

        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login_citizen"))

        login_user(user)
        return redirect(url_for("dashboard"))

    return render_template("login-citizen.html")

<<<<<<< HEAD
# ---------------- ORGANIZATION (OTP KEPT) ------------------

@app.route("/register-org")
=======
# ---------------------------------------------------
#  B. ORGANIZATION ROUTES
# ---------------------------------------------------

@app.route('/register-org')
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c
def register_org():
    return render_template("org-register.html")

<<<<<<< HEAD
@app.route("/send-otp-org", methods=["POST"])
=======
@app.route('/send-otp-org', methods=['POST'])
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c
def send_otp_org():
    email = request.json.get("email")

    if User.objects(email=email).first():
        return jsonify({"success": False, "message": "Email already registered."})

    otp = str(random.randint(100000, 999999))
    session["org_otp"] = otp
    session["org_email"] = email

<<<<<<< HEAD
    # Note: Ensure you have configured SMTP environment variables for this to work
    try:
        msg = Message("Organization OTP", recipients=[email])
        msg.body = f"OTP: {otp}"
        mail.send(msg)
        return jsonify({"success": True})
    except Exception as e:
        print(f"Mail Error: {e}")
        return jsonify({"success": False, "message": "Failed to send OTP. Check logs."})
=======
    msg = Message("Organization OTP", recipients=[email])
    msg.body = f"OTP: {otp}"
    mail.send(msg)
    
    flash(
    "Application submitted successfully. You will receive an email once approved.",
    "success"
        )  
    return jsonify({"success": True})
>>>>>>> 032d40b28ea50efd0478bb8f2882f5af5a0fe468

<<<<<<< HEAD
@app.route("/verify-otp-org", methods=["POST"])
=======
@app.route('/verify-otp-org', methods=['POST'])
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c
def verify_otp_org():
    if (
        session.get("org_otp") == request.json.get("otp")
        and session.get("org_email") == request.json.get("email")
    ):
        session["org_verified"] = True
        return jsonify({"success": True})

    return jsonify({"success": False})

<<<<<<< HEAD
@app.route("/register-org", methods=["POST"])
=======
@app.route('/register-org', methods=['POST'])
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c
def register_org_submit():
    if not session.get("org_verified"):
        return jsonify({"error": "OTP required"}), 400

<<<<<<< HEAD
    domain = request.form.get("domain")
    if not domain or not verify_domain(domain):
        return jsonify({"error": "Invalid domain"}), 400

    auth_file = request.files.get("auth_letter")
    incorp_file = request.files.get("incorp_cert")
=======
    try:
        org_name = request.form.get('org_name')
        category = request.form.get('category')
        cin = request.form.get('cin')
        officer_name = request.form.get('officer_name')
        designation = request.form.get('designation')
        email = request.form.get('email')
        password = request.form.get('password')

        auth_file = request.files.get('auth_letter')
        incorp_file = request.files.get('incorp_cert')
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    auth_path = incorp_path = None

    if auth_file:
        auth_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(auth_file.filename))
        auth_file.save(auth_path)

<<<<<<< HEAD
    if incorp_file:
        incorp_path = os.path.join(app.config["UPLOAD_FOLDER"], secure_filename(incorp_file.filename))
        incorp_file.save(incorp_path)

    User(
        email=request.form.get("email"),
        password_hash=generate_password_hash(request.form.get("password")),
        role="org",
        org_name=request.form.get("org_name"),
        category=request.form.get("category"),
        cin=request.form.get("cin"),
        designation=request.form.get("designation"),
        domain=domain,
        auth_doc_path=auth_path,
        incorp_doc_path=incorp_path,
        is_verified=True,
        is_approved=False
    ).save()
=======
        new_org = User(
            email=email,
            password_hash=generate_password_hash(password),
            role='org',
            full_name=officer_name,
            org_name=org_name,
            category=category,
            cin=cin,
            designation=designation,
            auth_doc_path=auth_path,
            incorp_doc_path=incorp_path,
            is_verified=True, 
            is_approved=False 
        )
        new_org.save()

        session.pop('org_otp', None)
        session.pop('org_email', None)
        session.pop('org_verified', None)
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c

    session.clear()
    return jsonify({"success": True})

# ---------------- OFFICIAL LOGIN ------------------

@app.route("/official-login", methods=["GET", "POST"])
def login_official():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        #Only organization accounts allowed here
        user = User.objects(email=email, role="org").first()

        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login_official"))

        #Block until admin approval
        if not user.is_approved:
            flash(
                "Your organization account is pending CERT-IN approval. "
                "You will receive an email once approved.",
                "warning"
            )
            return redirect(url_for("login_official"))

        #Login allowed
        login_user(user)
        flash("Login successful.", "success")
        return redirect(url_for("org_dashboard"))

    return render_template("login-official.html")

<<<<<<< HEAD
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "org":
        return redirect(url_for("org_dashboard"))
<<<<<<< HEAD
    # Pass user to template for header display
    return render_template("userdashboard.html", current_user=current_user)
=======
    return render_template("userdashboard.html")
=======
# ---------------------------------------------------
#  C. ADMIN & APPROVAL ROUTES (CRITICAL FIXES HERE)
# ---------------------------------------------------

@app.route('/admin-login', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        # NOTE: Add actual password logic here if needed
        flash('Admin Dashboard access granted.', 'success')
        return redirect(url_for('admin_dashboard'))
        
    return render_template('login-admin.html')

@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    # 1. Fetch only organizations that are NOT approved yet
    pending_orgs = User.objects(role='org', is_approved=False)
    
    # 2. Pass this list to the HTML file
    return render_template('admin_dashboard.html', pending_orgs=pending_orgs)

@app.route('/approve-org/<user_id>')
@login_required
def approve_org(user_id):
    # Find user by ID
    user = User.objects(pk=user_id).first()
    
    if user:
        user.is_approved = True
        user.save()
        
        # Optional: Send approval email
        try:
            msg = Message('Account Approved', sender='noreply@cyberportal.gov', recipients=[user.email])
            msg.body = "Your organization account has been approved. You may now login."
            mail.send(msg)
        except Exception:
            pass # Continue even if email fails
            
        flash(f'Organization {user.org_name} has been approved!', 'success')
    else:
        flash('User not found.', 'danger')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/reject-org/<user_id>')
@login_required
def reject_org(user_id):
    user = User.objects(pk=user_id).first()
    if user:
        user.delete() # Simply delete the request
        flash('Organization request rejected/deleted.', 'warning')
    return redirect(url_for('admin_dashboard'))

# ---------------------------------------------------
#  D. SHARED ROUTES
# ---------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    # Smart Redirection based on role
    if current_user.role == 'org':
        return redirect(url_for('org_dashboard'))
    
    # If you have a way to identify admin role in DB, add it here:
    # if current_user.role == 'admin':
    #     return redirect(url_for('admin_dashboard'))
        
    return render_template('userdashboard.html', user=current_user)
>>>>>>> 0809c800094ce22e3a6b9035c6b64701ff587a7c

@app.route("/api/scan-url", methods=["POST"])
@login_required
def scan_url_api():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        report = final_verdict(url)

        return jsonify({
            # Core
            "url": report["url"],
            "final_verdict": report["final_verdict"],
            "risk_level": report["risk_level"],
            "score": report["score"],

            # ML
            "ml": {
                "prediction": report["ml"]["prediction"],
                "confidence": report["ml"]["confidence"]
            },

            # SSL
            "ssl": report.get("ssl"),

            # IP & Hosting
            "ip": report.get("ip"),

            # URL structure
            "url_analysis": report.get("url_analysis"),

            # Brand check
            "brand": report.get("brand"),

            # Signals
            "signals": report["signals"]
        })

    except Exception as e:
        return jsonify({
            "error": "Analysis failed",
            "details": str(e)
        }), 500
        
#Domain Verification of Organization
@app.route("/verify-domain", methods=["POST"])
def verify_domain_api():
    data = request.get_json()
    domain = data.get("domain")

    return jsonify(valid=verify_domain(domain))

>>>>>>> 032d40b28ea50efd0478bb8f2882f5af5a0fe468

@app.route("/org-dashboard")
@login_required
def org_dashboard():
    return render_template("organizationdashboard.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

<<<<<<< HEAD
# ==========================================
# 9. SCANNING API (UPDATED WITH REPORTING)
# ==========================================

@app.route("/api/scan-url", methods=["POST"])
@login_required
def scan_url_api():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        # 1. Get Base Analysis (ML, Heuristics)
        report = final_verdict(url)
        
        # 2. Get Real Geo-Location Data
        geo_data = get_ip_details(url)
        
        # 3. Update Database Stats (Increment Scan Count)
        stats = SystemStats.objects.first()
        if not stats:
            stats = SystemStats(total_scans=0, threats_blocked=0)
        
        stats.total_scans += 1
        if report.get("final_verdict", "").upper() != "SAFE":
            stats.threats_blocked += 1
        stats.save()

        # 4. Construct Final Response
        # IMPORTANT: Added 'lat', 'lon', 'country_full' for Map & Popups
        return jsonify({
            # Core
            "url": report.get("url", url),
            "final_verdict": report.get("final_verdict", "UNKNOWN"),
            "risk_level": report.get("risk_level", "UNKNOWN"),
            "score": report.get("score", 0),

            # Geo-Location
            "ip": {
                "ip": geo_data["ip"],
                "country": geo_data["country"], 
                "country_full": geo_data.get("country_full", "Unknown"), # Added for popup
                "isp": geo_data["isp"],
                "lat": geo_data.get("lat", 0),  # Added for Map
                "lon": geo_data.get("lon", 0)   # Added for Map
            },

            # SSL
            "ssl": report.get("ssl", {"risk": "UNKNOWN", "reason": "Scan pending"}),

            # URL Analysis
            "url_analysis": report.get("url_analysis", {"risk": "UNKNOWN"}),

            # Brand Check
            "brand": report.get("brand", {"impersonation": False, "brand": None}),

            # Signals
            "signals": report.get("signals", [])
        })

    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({
            "error": "Analysis failed",
            "details": str(e)
        }), 500

# ==========================================
# 10. REPORT CASE API (NEW)
# ==========================================

@app.route("/api/report-case", methods=["POST"])
@login_required
def report_case():
    try:
        data = request.get_json()
        target = data.get("target")
        scan_data = data.get("data")
        
        if not target or not scan_data:
            return jsonify({"error": "Missing case data"}), 400

        # Generate unique ID
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        
        # Save to MongoDB
        Case(
            case_id=case_id,
            target=target,
            report_data=scan_data,
            reported_by=current_user.email,
            status="Pending"
        ).save()
        
        print(f"✅ New Case Filed: {case_id}")

        return jsonify({
            "status": "success",
            "message": "Report filed successfully",
            "case_id": case_id
        }), 200

    except Exception as e:
        print(f"Report Error: {e}")
        return jsonify({"error": "Failed to file report"}), 500

# ==========================================
# 11. SYSTEM STATS API
# ==========================================

@app.route('/api/stats')
def api_stats():
    # 1. Measure Real CPU (Non-blocking)
    cpu_usage = psutil.cpu_percent(interval=None) 
    
    # 2. Get Real Database Counts
    try:
        stats = SystemStats.objects.first()
        
        if stats:
            real_scans = stats.total_scans
            real_threats = stats.threats_blocked
            log_msg = f"System Optimal. Active Threads: {psutil.cpu_count()}"
        else:
            # Initialize if empty
            new_stats = SystemStats(total_scans=0, threats_blocked=0)
            new_stats.save()
            real_scans = 0
            real_threats = 0
            log_msg = "Database Initialized."
            
    except Exception as e:
        real_scans = 0
        real_threats = 0
        log_msg = "Database Offline - Reconnecting..."

    return jsonify({
        "scans": real_scans,
        "threats": real_threats,
        "server_load": cpu_usage,
        "log": log_msg
    })

=======
>>>>>>> 032d40b28ea50efd0478bb8f2882f5af5a0fe468
if __name__ == "__main__":
    app.run(debug=True, port=5000)