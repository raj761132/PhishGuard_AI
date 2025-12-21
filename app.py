import os
import random
import datetime
import socket
import datetime
import socket

from flask_login import UserMixin
from mongoengine import Document, StringField, BooleanField
from mongoengine import StringField

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
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from services.final_verdict import final_verdict
from routes.org_routes.org_bp import org_bp

load_dotenv()

app = Flask(__name__)
app.register_blueprint(org_bp)
app.secret_key = os.getenv("SECRET_KEY")

UPLOAD_FOLDER = "static/uploads/kyc_docs"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")

mail = Mail(app)

app.config["MONGODB_SETTINGS"] = {
    "host": os.getenv("MONGO_URI")
}

db = MongoEngine()
db.init_app(app)
 
with app.app_context():
    try:
        db.connection.server_info()
        print("✅ MongoDB connected successfully")
    except Exception as e:
        print("❌ MongoDB connection failed")
        print(e)

#USER MODEL

class User(db.Document, UserMixin):
    meta = {"collection": "users", "strict": False}

    # Common (ALL users)
    email = db.StringField(required=True, unique=True)
    password_hash = db.StringField(required=True)
    role = db.StringField(required=True)  # citizen | org | admin
    created_at = db.DateTimeField(default=datetime.datetime.utcnow)

    # Status
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

# ==========================================
# 6. LOGIN MANAGER
# ==========================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_citizen"

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
# 7. ROUTES
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")

#----------------ADMIN-------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        #Hardcoded admin credentials
        if email == "admin@phishguard.gov.in" and password == "Admin@123":
            admin = User.objects(email=email).first()

            if not admin:
                admin = User(
                    email=email,
                    password_hash=generate_password_hash(password),
                    role="admin",
                    is_verified=True,
                    is_approved=True
                )
                admin.save()

            login_user(admin)
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin credentials", "danger")
        return redirect(url_for("admin_login"))

    return render_template("admin_login.html")

def send_approval_email(org):
    msg = Message(
        subject="Organization Approved – PhishGuard AI",
        recipients=[org.email]
    )
    msg.body = f"""
Hello {org.org_name},

Your organization has been approved by CERT-IN.

You can now log in using your registered email.

Regards,
PhishGuard AI – CERT-IN
"""
    mail.send(msg)


@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        abort(403)

    return render_template("admindashboard.html")

@app.route("/admin/org-requests")
@login_required
def org_requests():
    if current_user.role != "admin":
        abort(403)

    pending_orgs = User.objects(
        role="org",
        is_approved=False
    )

    return render_template(
        "org-requests.html",
        orgs=pending_orgs
    )
    
@app.route("/admin/approve-org/<user_id>")
@login_required
def approve_org(user_id):
    if current_user.role != "admin":
        abort(403)

    org = User.objects(id=user_id).first()
    if not org:
        abort(404)

    org.is_approved = True
    org.save()

    send_approval_email(org)

    flash("Organization approved successfully", "success")
    return redirect(url_for("org_requests"))

@app.route("/admin/organizations")
@login_required
def admin_organizations():
    if current_user.role != "admin":
        abort(403)

    approved_orgs = User.objects(
        role="org",
        is_approved=True
    )

    return render_template(
        "admin-organizations.html",
        orgs=approved_orgs
    )




# ---------------- CITIZEN (NO OTP) ------------------

@app.route("/register-citizen", methods=["GET", "POST"])
def register_citizen():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if User.objects(email=email).first():
            flash("Email already registered. Please login.", "danger")
            return redirect(url_for("login_citizen"))

        User(
            email=email,
            password_hash=generate_password_hash(password),
            role="citizen",
            full_name=request.form.get("full_name"),
            phone=request.form.get("phone"),
            is_verified=True
        ).save()

        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login_citizen"))

    return render_template("citizen-register.html")

@app.route("/login", methods=["GET", "POST"])
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
    
    flash(
    "Application submitted successfully. You will receive an email once approved.",
    "success"
        )  
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

    domain = request.form.get("domain")
    if not domain or not verify_domain(domain):
        return jsonify({"error": "Invalid domain"}), 400

    auth_file = request.files.get("auth_letter")
    incorp_file = request.files.get("incorp_cert")

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

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
        domain=domain,
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
        
#Domain Verification of Organization
@app.route("/verify-domain", methods=["POST"])
def verify_domain_api():
    data = request.get_json()
    domain = data.get("domain")

    return jsonify(valid=verify_domain(domain))


@app.route("/org-dashboard")
@login_required
def org_dashboard():
    return render_template("organizationdashboard.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
