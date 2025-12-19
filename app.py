import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mongoengine import MongoEngine
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import datetime
from datetime import timedelta
import random

# ==========================================
# 1. SETUP & CONFIGURATION
# ==========================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'hackathon-secret-key-change-this'

# --- FILE UPLOAD CONFIG ---
# Ensure this folder exists or the code will create it
UPLOAD_FOLDER = 'static/uploads/kyc_docs'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 

# --- EMAIL CONFIG ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'abcdaxhy1234@gmail.com'  # <--- YOUR EMAIL
app.config['MAIL_PASSWORD'] = 'nign ypfh yrrb whwu'   # <--- YOUR PASSWORD

mail = Mail(app)

# --- MONGODB CONFIG ---
app.config['MONGODB_SETTINGS'] = {
    'db': 'cybersecurity_db',
    'host': 'localhost',
    'port': 27017
}

db = MongoEngine(app)

# --- LOGIN MANAGER ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_citizen'

# ==========================================
# 2. DATABASE MODEL (FIXED)
# ==========================================
class User(UserMixin, db.Document):
    meta = {
        'collection': 'users',
        'strict': False  # <--- CRITICAL FIX: Ignores old/unknown fields in DB to prevent crashes
    }

    email = db.StringField(required=True, unique=True)
    password_hash = db.StringField(required=True)
    role = db.StringField(required=True) # 'citizen', 'org', 'admin'
    created_at = db.DateTimeField(default=datetime.datetime.utcnow)
    is_verified = db.BooleanField(default=False)
    is_approved = db.BooleanField(default=False) 

    # Citizen Fields
    full_name = db.StringField()
    phone = db.StringField()

    # Organization Fields
    org_name = db.StringField()
    category = db.StringField()
    cin = db.StringField()
    designation = db.StringField()
    
    # KYC Documents (File Paths)
    auth_doc_path = db.StringField()
    incorp_doc_path = db.StringField()

    # Legacy Fields (Kept to prevent errors if they exist in DB)
    access_level = db.IntField(default=1) 
    company_domain = db.StringField()
    department_name = db.StringField()

    # OTP Logic
    otp_code = db.StringField(max_length=6)
    otp_expiry = db.DateTimeField()

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()

# ==========================================
# 3. ROUTES & LOGIC
# ==========================================

@app.route('/')
def home():
    return render_template('index.html')

# ---------------------------------------------------
#  A. CITIZEN ROUTES
# ---------------------------------------------------

@app.route('/register-citizen', methods=['GET', 'POST'])
def register_citizen():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = 'citizen'

        existing_user = User.objects(email=email).first()
        if existing_user:
            flash('Email already registered. Please login.', 'danger')
            return redirect(url_for('login_citizen'))

        otp = str(random.randint(100000, 999999))
        expiry = datetime.datetime.utcnow() + timedelta(minutes=10)

        new_user = User(
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

    return render_template('citizen-register.html')

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
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.objects(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            if user.role != 'citizen':
                flash('This portal is for Citizens only.', 'warning')
                return redirect(url_for('login_citizen'))
                
            if user.is_verified == False:
                 flash('Please verify your email first.', 'warning')
                 session['email_to_verify'] = email
                 return redirect(url_for('verify_otp'))

            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login-citizen.html')

# ---------------------------------------------------
#  B. ORGANIZATION ROUTES (FIXED ENDPOINTS)
# ---------------------------------------------------

# FIXED: Renamed function to 'register_org' to match url_for('register_org') in index.html
@app.route('/register-org')
def register_org():
    return render_template('org-register.html')

# 1. AJAX: Send OTP to Organization Email
@app.route('/send-otp-org', methods=['POST'])
def send_otp_org():
    data = request.get_json()
    email = data.get('email')

    if User.objects(email=email).first():
        return jsonify({'success': False, 'message': 'Email already registered.'})

    otp = str(random.randint(100000, 999999))
    session['org_otp'] = otp
    session['org_email'] = email
    
    try:
        msg = Message('Official Organization OTP', sender='noreply@cyberportal.gov', recipients=[email])
        msg.body = f"Your Verification Code is: {otp}"
        mail.send(msg)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# 2. AJAX: Verify OTP
@app.route('/verify-otp-org', methods=['POST'])
def verify_otp_org():
    data = request.get_json()
    entered_otp = data.get('otp')
    email = data.get('email')

    if 'org_otp' in session and session['org_otp'] == entered_otp and session['org_email'] == email:
        session['org_verified'] = True
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Invalid OTP'})

# 3. AJAX: Final Registration Submission
# Note: This shares the URL /register-org but uses POST method
@app.route('/register-org', methods=['POST'])
def register_org_submit():
    if not session.get('org_verified'):
        return jsonify({'error': 'Email verification required'}), 400

    try:
        # Get Form Data
        org_name = request.form.get('org_name')
        category = request.form.get('category')
        cin = request.form.get('cin')
        officer_name = request.form.get('officer_name')
        designation = request.form.get('designation')
        email = request.form.get('email')
        password = request.form.get('password')

        # Handle File Uploads
        auth_file = request.files.get('auth_letter')
        incorp_file = request.files.get('incorp_cert')

        auth_path = None
        incorp_path = None

        if auth_file:
            filename = secure_filename(auth_file.filename)
            auth_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{cin}_auth_{filename}")
            auth_file.save(auth_path)

        if incorp_file:
            filename = secure_filename(incorp_file.filename)
            incorp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{cin}_incorp_{filename}")
            incorp_file.save(incorp_path)

        # Create User
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

        # Clean session
        session.pop('org_otp', None)
        session.pop('org_email', None)
        session.pop('org_verified', None)

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/official-login', methods=['GET', 'POST'])
def login_official():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.objects(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            if user.role != 'org':
                flash('This portal is for Organization officials only.', 'warning')
                return redirect(url_for('login_official'))

            if not user.is_verified:
                 flash('Email not verified.', 'warning')
                 return redirect(url_for('login_official'))
            
            if not user.is_approved:
                flash('Your account is pending approval by the Central Admin.', 'info')
                return redirect(url_for('login_official'))

            login_user(user)
            flash('Organization login successful.', 'success')
            return redirect(url_for('org_dashboard'))
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login-official.html')

# ---------------------------------------------------
#  C. SHARED & ADMIN ROUTES
# ---------------------------------------------------

@app.route('/admin-login', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        flash('Admin Dashboard access granted (Mock).', 'success')
        return redirect(url_for('dashboard'))
    return render_template('login-admin.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('userdashboard.html', user=current_user)

@app.route('/ORG-dashboard')
@login_required
def org_dashboard():
    if current_user.role != 'org':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('organizationdashboard.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)