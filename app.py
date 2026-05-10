"""
Digital Signature Tool - Flask Application
==========================================
Web-based PDF file-signing utility with Sender, Receiver, and Attacker Demo interfaces.

Routes:
    /                       - Landing page
    /sender                 - Signing interface
    /sender/generate-keys   - Generate new RSA/ECDSA key pair
    /sender/sign            - Sign a PDF file
    /receiver               - Verification interface
    /receiver/verify        - Verify a .sigbundle
    /receiver/report        - Download verification audit report
    /demo                   - Attacker demo page
    /demo/tamper            - Tamper a signed bundle
    /api/keys               - List available key pairs
"""

import os
import io
import json
from flask import (
    Flask, render_template, request, jsonify,
    send_file, redirect, url_for, Response
)
from werkzeug.utils import secure_filename

from crypto_engine.key_manager import (
    generate_rsa_keypair, generate_ecdsa_keypair,
    list_keys, delete_key
)
from crypto_engine.signer import sign_file
from crypto_engine.verifier import verify_bundle, tamper_bundle, generate_audit_report


app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB max upload

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
SIGNED_DIR = os.path.join(BASE_DIR, "signed_files")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


# ─── Page Routes ────────────────────────────────────────────────

@app.route("/")
def index():
    """Landing page with project overview."""
    return render_template("index.html")


@app.route("/sender")
def sender():
    """Sender signing interface."""
    keys = list_keys()
    return render_template("sender.html", keys=keys)


@app.route("/receiver")
def receiver():
    """Receiver verification interface."""
    return render_template("receiver.html")


@app.route("/demo")
def demo():
    """Attacker demo page."""
    return render_template("demo.html")


# ─── API Routes ─────────────────────────────────────────────────

@app.route("/api/keys", methods=["GET"])
def api_list_keys():
    """List all available key pairs."""
    keys = list_keys()
    return jsonify({"keys": keys})


@app.route("/sender/generate-keys", methods=["POST"])
def api_generate_keys():
    """Generate a new RSA or ECDSA key pair."""
    try:
        data = request.get_json()
        algorithm = data.get("algorithm", "RSA")
        key_name = data.get("key_name", None)

        if algorithm == "RSA":
            key_size = int(data.get("key_size", 2048))
            metadata = generate_rsa_keypair(key_size=key_size, key_name=key_name)
        elif algorithm == "ECDSA":
            curve = data.get("curve", "secp256r1")
            metadata = generate_ecdsa_keypair(curve_name=curve, key_name=key_name)
        else:
            return jsonify({"error": "Unsupported algorithm"}), 400

        return jsonify({"success": True, "key": metadata})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/sender/sign", methods=["POST"])
def api_sign_file():
    """Sign an uploaded PDF file."""
    try:
        # Check for uploaded file
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        key_name = request.form.get("key_name")
        if not key_name:
            return jsonify({"error": "No key selected"}), 400

        # Save uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_DIR, filename)
        file.save(file_path)

        # Sign the file
        result = sign_file(file_path, key_name)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/sender/download/<bundle_name>")
def download_bundle(bundle_name):
    """Download a signed bundle."""
    bundle_path = os.path.join(SIGNED_DIR, secure_filename(bundle_name))
    if os.path.exists(bundle_path):
        return send_file(bundle_path, as_attachment=True)
    return jsonify({"error": "Bundle not found"}), 404


@app.route("/receiver/verify", methods=["POST"])
def api_verify_bundle():
    """Verify an uploaded .sigbundle file."""
    try:
        if "bundle" not in request.files:
            return jsonify({"error": "No bundle file uploaded"}), 400

        bundle = request.files["bundle"]
        if bundle.filename == "":
            return jsonify({"error": "No file selected"}), 400

        # Save uploaded bundle
        filename = secure_filename(bundle.filename)
        bundle_path = os.path.join(UPLOAD_DIR, filename)
        bundle.save(bundle_path)

        # Verify the bundle
        result = verify_bundle(bundle_path)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/receiver/report", methods=["POST"])
def api_download_report():
    """
    Generate and download a verification audit report.

    Expects JSON body with the verification result data.
    Returns a downloadable .txt report file.
    """
    try:
        verification_data = request.get_json()
        if not verification_data:
            return jsonify({"error": "No verification data provided"}), 400

        # Generate the report text
        report_text = generate_audit_report(verification_data)

        # Create a filename based on the verified file
        file_name = verification_data.get("file_name", "unknown")
        base_name = os.path.splitext(file_name)[0]
        status = "VALID" if verification_data.get("signature_valid") else "INVALID"
        report_filename = f"verification_report_{base_name}_{status}.txt"

        # Save report to reports directory for archival
        report_path = os.path.join(REPORTS_DIR, report_filename)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_text)

        # Return as downloadable file
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
    """
    Tamper a signed bundle for demonstration.
    Supports: modify_byte, signature_reuse, tamper_metadata
    """
    try:
        if "bundle" not in request.files:
            return jsonify({"error": "No bundle file uploaded"}), 400

        bundle = request.files["bundle"]
        tamper_type = request.form.get("tamper_type", "modify_byte")

        # Save uploaded bundle
        filename = secure_filename(bundle.filename)
        bundle_path = os.path.join(UPLOAD_DIR, filename)
        bundle.save(bundle_path)

        # First verify the original (should be valid)
        original_result = verify_bundle(bundle_path)

        # Then tamper and verify (should be invalid)
        tamper_result = tamper_bundle(bundle_path, tamper_type=tamper_type)

        return jsonify({
            "original_verification": original_result,
            "tamper_result": tamper_result,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/keys/<key_name>", methods=["DELETE"])
def api_delete_key(key_name):
    """Delete a key pair."""
    try:
        delete_key(key_name)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Run ────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
