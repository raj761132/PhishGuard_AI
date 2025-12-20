import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
import datetime
from datetime import timedelta
import random

# --- IMPORT DATABASE LOGIC ---
# Ensure db.py is in the same folder
from db import db, User

# ==========================================
# 1. SETUP & CONFIGURATION
# ==========================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'hackathon-secret-key-change-this'

# --- FILE UPLOAD CONFIG ---
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

# --- INITIALIZE DB ---
db.init_app(app)

# --- LOGIN MANAGER ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_citizen'

@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()

# ==========================================
# 2. ROUTES & LOGIC
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
#  B. ORGANIZATION ROUTES
# ---------------------------------------------------

@app.route('/register-org')
def register_org():
    return render_template('org-register.html')

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

@app.route('/register-org', methods=['POST'])
def register_org_submit():
    if not session.get('org_verified'):
        return jsonify({'error': 'Email verification required'}), 400

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