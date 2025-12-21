import os
import random
import datetime

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, jsonify
)
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from flask_mongoengine import MongoEngine
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from services.final_verdict import final_verdict

# ==========================================
# 1. LOAD ENV & APP INIT
# ==========================================

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# ==========================================
# 2. FILE UPLOAD CONFIG
# ==========================================

UPLOAD_FOLDER = "static/uploads/kyc_docs"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==========================================
# 3. MAIL CONFIG
# ==========================================

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

mail = Mail(app)

# ==========================================
# 4. MONGODB ATLAS CONFIG
# ==========================================

app.config["MONGODB_SETTINGS"] = {
    "host": os.getenv("MONGO_URI")
}

db = MongoEngine()
db.init_app(app)

# ==========================================
# 5. USER MODEL
# ==========================================

class User(UserMixin, db.Document):
    meta = {"collection": "users", "strict": False}

    email = db.StringField(required=True, unique=True)
    password_hash = db.StringField(required=True)
    role = db.StringField(required=True)  # citizen | org | admin

    created_at = db.DateTimeField(default=datetime.datetime.utcnow)
    is_verified = db.BooleanField(default=False)
    is_approved = db.BooleanField(default=False) 

    # Citizen
    full_name = db.StringField()
    phone = db.StringField()

    # Organization
    org_name = db.StringField()
    category = db.StringField()
    cin = db.StringField()
    designation = db.StringField()

    # Documents
    auth_doc_path = db.StringField()
    incorp_doc_path = db.StringField()

    # OTP (ORG ONLY)
    otp_code = db.StringField()
    otp_expiry = db.DateTimeField()

    def get_id(self):
        return str(self.id)

# ==========================================
# 6. LOGIN MANAGER
# ==========================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_citizen"

@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()

# ==========================================
# 7. ROUTES
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")

# ---------------------------------------------------
#  A. CITIZEN ROUTES
# ---------------------------------------------------

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

# ---------------- ORGANIZATION (OTP KEPT) ------------------

@app.route("/register-org")
def register_org():
    return render_template("org-register.html")

@app.route("/send-otp-org", methods=["POST"])
def send_otp_org():
    email = request.json.get("email")

    if User.objects(email=email).first():
        return jsonify({"success": False, "message": "Email already registered."})

    otp = str(random.randint(100000, 999999))
    session["org_otp"] = otp
    session["org_email"] = email

    msg = Message("Organization OTP", recipients=[email])
    msg.body = f"OTP: {otp}"
    mail.send(msg)

    return jsonify({"success": True})

@app.route("/verify-otp-org", methods=["POST"])
def verify_otp_org():
    if (
        session.get("org_otp") == request.json.get("otp")
        and session.get("org_email") == request.json.get("email")
    ):
        session["org_verified"] = True
        return jsonify({"success": True})

    return jsonify({"success": False})

@app.route("/register-org", methods=["POST"])
def register_org_submit():
    if not session.get("org_verified"):
        return jsonify({"error": "OTP required"}), 400

    auth_file = request.files.get("auth_letter")
    incorp_file = request.files.get("incorp_cert")

    auth_path = incorp_path = None

    if auth_file:
        auth_path = os.path.join(app.config["UPLOAD_FOLDER"], auth_file.filename)
        auth_file.save(auth_path)

    if incorp_file:
        incorp_path = os.path.join(app.config["UPLOAD_FOLDER"], incorp_file.filename)
        incorp_file.save(incorp_path)

    User(
        email=request.form.get("email"),
        password_hash=generate_password_hash(request.form.get("password")),
        role="org",
        org_name=request.form.get("org_name"),
        category=request.form.get("category"),
        cin=request.form.get("cin"),
        designation=request.form.get("designation"),
        auth_doc_path=auth_path,
        incorp_doc_path=incorp_path,
        is_verified=True,
        is_approved=False
    ).save()

    session.clear()
    return jsonify({"success": True})

# ---------------- OFFICIAL LOGIN ------------------

@app.route("/official-login", methods=["GET", "POST"])
def login_official():
    if request.method == "POST":
        user = User.objects(email=request.form.get("email"), role="org").first()

        if not user or not check_password_hash(user.password_hash, request.form.get("password")):
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login_official"))

        if not user.is_approved:
            flash("Account pending admin approval.", "info")
            return redirect(url_for("login_official"))

        login_user(user)
        return redirect(url_for("org_dashboard"))

    return render_template("login-official.html")

# ---------------- ADMIN LOGIN ------------------

@app.route("/admin-login", methods=["GET", "POST"])
def login_admin():
    if request.method == "POST":
        user = User.objects(email=request.form.get("email"), role="admin").first()

        if not user or not check_password_hash(user.password_hash, request.form.get("password")):
            flash("Invalid admin credentials.", "danger")
            return redirect(url_for("login_admin"))

        login_user(user)
        return redirect(url_for("dashboard"))

    return render_template("login-admin.html")

# ---------------- DASHBOARDS ------------------

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "org":
        return redirect(url_for("org_dashboard"))
    return render_template("userdashboard.html")

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


@app.route("/ORG-dashboard")
@login_required
def org_dashboard():
    return render_template("organizationdashboard.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# ==========================================
# 8. RUN
# ==========================================

if __name__ == "__main__":
    app.run(debug=True)
