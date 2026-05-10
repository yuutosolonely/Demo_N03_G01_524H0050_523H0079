"""
Digital Signature Tool - Flask Application
==========================================
Web-based PDF file-signing utility with Sender, Receiver, and Attacker Demo interfaces.
"""

import os
import json
import re
from flask import (
    Flask, render_template, request, jsonify,
    send_file, redirect, url_for, Response, flash
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

from models import db, User, KeyRecord, AuditLog
from crypto_engine.key_manager import (
    generate_rsa_keypair, generate_ecdsa_keypair,
    delete_key
)
from crypto_engine.signer import sign_file
from crypto_engine.verifier import verify_bundle, tamper_bundle, generate_audit_report


app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB max upload

database_url = os.environ.get('DATABASE_URL')
if database_url:
    # SQLAlchemy 1.4+ yêu cầu URL bắt đầu bằng postgresql:// thay vì postgres://
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
elif os.path.exists('/app/data'):
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////app/data/app.db"
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Init extensions
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if os.path.exists('/app/data'):
    UPLOAD_DIR = os.path.join('/app/data', "uploads")
    SIGNED_DIR = os.path.join('/app/data', "signed_files")
    REPORTS_DIR = os.path.join('/app/data', "reports")
else:
    UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
    SIGNED_DIR = os.path.join(BASE_DIR, "signed_files")
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

with app.app_context():
    db.create_all()

# ─── Auth Routes ────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Password validation
        if len(password) < 8:
            flash("Password must be at least 8 characters long", "danger")
            return redirect(url_for("register"))
        if not re.search(r"[A-Z]", password):
            flash("Password must contain at least one uppercase letter", "danger")
            return redirect(url_for("register"))
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            flash("Password must contain at least one special character", "danger")
            return redirect(url_for("register"))
            
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return redirect(url_for("register"))
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid username or password", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", keys=current_user.keys, audit_logs=current_user.audit_logs)

# ─── Page Routes ────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/sender")
@login_required
def sender():
    keys = current_user.keys
    keys_list = [
        {
            "key_name": k.key_name,
            "algorithm": k.algorithm,
            "key_size": k.key_size,
            "fingerprint": k.fingerprint,
        } for k in keys
    ]
    return render_template("sender.html", keys=keys_list)

@app.route("/receiver")
def receiver():
    return render_template("receiver.html")

@app.route("/demo")
def demo():
    return render_template("demo.html")

# ─── API Routes ─────────────────────────────────────────────────

@app.route("/api/keys", methods=["GET"])
@login_required
def api_list_keys():
    keys = current_user.keys
    keys_list = [
        {
            "key_name": k.key_name,
            "algorithm": k.algorithm,
            "key_size": k.key_size,
            "fingerprint": k.fingerprint,
        } for k in keys
    ]
    return jsonify({"keys": keys_list})

@app.route("/sender/generate-keys", methods=["POST"])
@login_required
def api_generate_keys():
    try:
        data = request.get_json()
        algorithm = data.get("algorithm", "RSA")
        key_name = data.get("key_name", None)

        if algorithm == "RSA":
            key_size = int(data.get("key_size", 2048))
            metadata = generate_rsa_keypair(current_user.id, key_size=key_size, key_name=key_name)
        elif algorithm == "ECDSA":
            curve = data.get("curve", "secp256r1")
            metadata = generate_ecdsa_keypair(current_user.id, curve_name=curve, key_name=key_name)
        else:
            return jsonify({"error": "Unsupported algorithm"}), 400

        # Log audit
        audit = AuditLog(
            user_id=current_user.id,
            action="GENERATE_KEY",
            status="SUCCESS",
            details=f"Generated {algorithm} key '{metadata['key_name']}'"
        )
        db.session.add(audit)
        db.session.commit()

        return jsonify({"success": True, "key": metadata})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/sender/sign", methods=["POST"])
@login_required
def api_sign_file():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        key_name = request.form.get("key_name")
        if not key_name:
            return jsonify({"error": "No key selected"}), 400

        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_DIR, filename)
        file.save(file_path)

        result = sign_file(file_path, key_name, current_user.id)

        # Log audit
        audit = AuditLog(
            user_id=current_user.id,
            action="SIGN",
            status="SUCCESS",
            file_name=filename,
            details=f"Signed with {result['algorithm']} key '{key_name}'"
        )
        db.session.add(audit)
        db.session.commit()

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/sender/download/<bundle_name>")
def download_bundle(bundle_name):
    bundle_path = os.path.join(SIGNED_DIR, secure_filename(bundle_name))
    if os.path.exists(bundle_path):
        return send_file(bundle_path, as_attachment=True)
    return jsonify({"error": "Bundle not found"}), 404

@app.route("/receiver/verify", methods=["POST"])
def api_verify_bundle():
    try:
        if "bundle" not in request.files:
            return jsonify({"error": "No bundle file uploaded"}), 400

        bundle = request.files["bundle"]
        if bundle.filename == "":
            return jsonify({"error": "No file selected"}), 400

        filename = secure_filename(bundle.filename)
        bundle_path = os.path.join(UPLOAD_DIR, filename)
        bundle.save(bundle_path)

        result = verify_bundle(bundle_path)

        # Log audit
        uid = current_user.id if current_user.is_authenticated else None
        status = "SUCCESS" if result.get("signature_valid") else "FAILED"
        audit = AuditLog(
            user_id=uid,
            action="VERIFY",
            status=status,
            file_name=result.get("file_name", filename),
            details=f"Verification {'successful' if status == 'SUCCESS' else 'failed'}"
        )
        db.session.add(audit)
        db.session.commit()

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/receiver/report", methods=["POST"])
def api_download_report():
    try:
        verification_data = request.get_json()
        if not verification_data:
            return jsonify({"error": "No verification data provided"}), 400

        report_text = generate_audit_report(verification_data)
        file_name = verification_data.get("file_name", "unknown")
        base_name = os.path.splitext(file_name)[0]
        status = "VALID" if verification_data.get("signature_valid") else "INVALID"
        report_filename = f"verification_report_{base_name}_{status}.txt"

        report_path = os.path.join(REPORTS_DIR, report_filename)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        return Response(
            report_text,
            mimetype="text/plain",
            headers={
                "Content-Disposition": f"attachment; filename={report_filename}"
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/demo/tamper", methods=["POST"])
def api_tamper_bundle():
    try:
        if "bundle" not in request.files:
            return jsonify({"error": "No bundle file uploaded"}), 400

        bundle = request.files["bundle"]
        tamper_type = request.form.get("tamper_type", "modify_byte")

        filename = secure_filename(bundle.filename)
        bundle_path = os.path.join(UPLOAD_DIR, filename)
        bundle.save(bundle_path)

        original_result = verify_bundle(bundle_path)
        tamper_result = tamper_bundle(bundle_path, tamper_type=tamper_type)

        # Log audit
        uid = current_user.id if current_user.is_authenticated else None
        audit = AuditLog(
            user_id=uid,
            action="TAMPER_DETECTED",
            status="FAILED",
            file_name=filename,
            details=f"Simulated attack: {tamper_type}. Detection successful."
        )
        db.session.add(audit)
        db.session.commit()

        return jsonify({
            "original_verification": original_result,
            "tamper_result": tamper_result,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/keys/<key_name>", methods=["DELETE"])
@login_required
def api_delete_key(key_name):
    try:
        delete_key(key_name, current_user.id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
