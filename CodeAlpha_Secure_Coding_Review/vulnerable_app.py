import os
import sqlite3
import pickle
import subprocess

from flask import Flask, request, jsonify, send_file

app = Flask(__name__)
DB_PATH = "app.db"


# 1. SQL Injection
@app.route("/api/user", methods=["GET"])
def get_user():
    username = request.args.get("username")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Vulnerable: user input directly inserted into SQL query
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"

    cursor.execute(query)
    record = cursor.fetchone()
    conn.close()

    return jsonify({"user": record})


# 2. Path Traversal
@app.route("/api/view-doc", methods=["GET"])
def view_document():
    filename = request.args.get("file")
    base_dir = "/var/data/docs"

    # Vulnerable: user controls the file path
    filepath = os.path.join(base_dir, filename)

    return send_file(filepath)


# 3. Command Injection
@app.route("/api/ping", methods=["POST"])
def ping_host():
    host = request.json.get("host")

    # Vulnerable: user input passed to shell
    cmd = f"ping -c 1 {host}"

    output = subprocess.check_output(cmd, shell=True)

    return jsonify({"result": output.decode()})


# 4. Insecure Deserialization
@app.route("/api/load-session", methods=["POST"])
def load_session():
    raw_data = request.data

    # Vulnerable: pickle can execute malicious code
    session_data = pickle.loads(raw_data)

    return jsonify({"session": session_data})


if __name__ == "__main__":
    app.run(debug=True)