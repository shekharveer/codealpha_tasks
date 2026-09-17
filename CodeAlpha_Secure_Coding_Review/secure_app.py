import ipaddress
import json
from pathlib import Path
import sqlite3
import subprocess

from flask import Flask, jsonify, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
DB_PATH = "app.db"

# 1. BASE_DIR updated for Windows local project folder
BASE_DIR = Path("docs").resolve()


# 1. SQL Injection - Fixed
@app.route("/api/user", methods=["GET"])
def get_user():
    username = request.args.get("username", "")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Secure: parameterized SQL query
    cursor.execute(
        "SELECT id, username, email FROM users WHERE username = ?",
        (username,)
    )

    record = cursor.fetchone()
    conn.close()

    return jsonify({"user": record})


# 2. Path Traversal - Fixed
@app.route("/api/view-doc", methods=["GET"])
def view_document():
    raw_filename = request.args.get("file", "")

    # Sanitize filename
    safe_name = secure_filename(raw_filename)

    if not safe_name:
        return jsonify({"error": "Invalid filename"}), 400

    target_path = (BASE_DIR / safe_name).resolve()

    # Make sure file stays inside BASE_DIR
    if not target_path.is_relative_to(BASE_DIR):
        return jsonify({"error": "Access denied"}), 403

    if not target_path.is_file():
        return jsonify({"error": "File not found"}), 404

    return send_file(target_path)


# 3. Command Injection - Fixed
@app.route("/api/ping", methods=["POST"])
def ping_host():
    data = request.get_json(silent=True) or {}
    host_input = data.get("host", "")

    try:
        # Only allow valid IP addresses
        ip = str(ipaddress.ip_address(host_input))
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    # 2. Ping command updated for Windows (-n count, -w timeout in ms)
    result = subprocess.run(
        ["ping", "-n", "1", "-w", "2000", ip],
        capture_output=True,
        text=True,
        check=False
    )

    return jsonify({
        "exit_code": result.returncode,
        "stdout": result.stdout
    })


# 4. Insecure Deserialization - Fixed
@app.route("/api/load-session", methods=["POST"])
def load_session():
    try:
        data = json.loads(request.get_data(as_text=True))

        if not isinstance(data, dict):
            return jsonify({"error": "Payload must be a JSON object"}), 400

    except (ValueError, json.JSONDecodeError):
        return jsonify({"error": "Invalid JSON data"}), 400

    return jsonify({"session": data})


if __name__ == "__main__":
    # Ensure the docs folder exists before running
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    # 3. Debug mode disabled to resolve Bandit B201
    app.run(debug=False)