from flask_mongoengine import MongoEngine
from flask_login import UserMixin
import datetime

# Initialize the database object
db = MongoEngine()

class User(UserMixin, db.Document):
    meta = {
        'collection': 'users',
        'strict': False  # Prevents crashes if DB has old/unknown fields
    }

    email = db.StringField(required=True, unique=True)
    password_hash = db.StringField(required=True)
    role = db.StringField(required=True)  # 'citizen', 'org', 'admin'
    created_at = db.DateTimeField(default=datetime.datetime.utcnow)
    is_verified = db.BooleanField(default=False)
    is_approved = db.BooleanField(default=False) 

    # Citizen Fields
    full_name = db.StringField()
    phone = db.StringField()

    # Organization Fields
    org_name = db.StringField()
    category = db.StringField()
    cin = db.StringField()  # Corporate Identity Number
    designation = db.StringField()
    
    # KYC Documents (File Paths)
    auth_doc_path = db.StringField()
    incorp_doc_path = db.StringField()

    # Legacy / Optional Fields (Restored to prevent errors)
    access_level = db.IntField(default=1) 
    company_domain = db.StringField()
    department_name = db.StringField()

    # OTP Logic
    otp_code = db.StringField(max_length=6)
    otp_expiry = db.DateTimeField()

    def get_id(self):
        return str(self.id)