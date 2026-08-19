"""Intentionally vulnerable Flask app — main routes."""

import sqlite3
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

DB_PATH = "/opt/vuln-labs/appsec-lab/users.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


@app.route("/setup")
def setup():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@corp.local', 'admin')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (2, 'user1', 'password1', 'user1@corp.local', 'user')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (3, 'guest', 'guest', 'guest@corp.local', 'guest')"
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "database initialized"})


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # VULN: SQL Injection via f-string
    conn = get_db()
    query = (
        f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    )
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify({"status": "logged in", "user": user[1]})
    return jsonify({"status": "invalid credentials"}), 401


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # VULN: SQL Injection via string concatenation
    conn = get_db()
    query = "SELECT * FROM users WHERE username LIKE '%" + term + "%'"
    cursor = conn.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify({"results": results})


@app.route("/user/<user_id>")
def get_user(user_id):
    conn = get_db()
    # VULN: SQL Injection via direct interpolation
    cursor = conn.execute("SELECT * FROM users WHERE id = " + user_id)
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify({"user": {"id": user[0], "username": user[1], "email": user[3]}})
    return jsonify({"error": "not found"}), 404


@app.route("/delete", methods=["POST"])
def delete_user():
    user_id = request.form.get("id", "")
    conn = get_db()
    # VULN: SQL Injection via f-string in DELETE
    conn.execute(f"DELETE FROM users WHERE id = '{user_id}'")
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})


@app.route("/profile")
def profile():
    name = request.args.get("name", "")
    # VULN: XSS — reflected user input directly in response HTML
    html = f"<html><body><h1>Welcome, {name}</h1></body></html>"
    return render_template_string(html)


@app.route("/greet")
def greet():
    msg = request.args.get("msg", "Hello")
    # VULN: XSS — unescaped variable in template string
    template = "<html><body><p>" + msg + "</p></body></html>"
    return render_template_string(template)


if __name__ == "__main__":
    # VULN: Flask debug mode enabled in production
    app.run(host="0.0.0.0", port=5000, debug=True)
