from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    keys = db.relationship('KeyRecord', backref='owner', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)

class KeyRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key_name = db.Column(db.String(120), nullable=False)
    algorithm = db.Column(db.String(20), nullable=False)
    key_size = db.Column(db.String(20), nullable=True) # E.g., '2048' or 'secp256r1'
    fingerprint = db.Column(db.String(128), unique=True, nullable=False)
    public_pem = db.Column(db.Text, nullable=False)
    private_pem = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Null if anonymous (e.g., public verification)
    action = db.Column(db.String(50), nullable=False) # 'GENERATE_KEY', 'SIGN', 'VERIFY', 'TAMPER_DETECTED'
    status = db.Column(db.String(20), nullable=False) # 'SUCCESS', 'FAILED'
    file_name = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
