"""File handling — path traversal and unrestricted upload."""

import os
from flask import request, jsonify, send_file

UPLOAD_DIR = "/opt/vuln-labs/appsec-lab/uploads"
DATA_DIR = "/opt/vuln-labs/appsec-lab/data"


def read_file(filename):
    # VULN: Path traversal — unsanitized os.path.join
    filepath = os.path.join(DATA_DIR, filename)
    with open(filepath, "r") as f:
        return f.read()


def download_file():
    filename = request.args.get("file", "")
    # VULN: Path traversal — user-controlled path in open()
    path = os.path.join(UPLOAD_DIR, filename)
    return send_file(open(path, "rb"), as_attachment=True)


def upload_file():
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error": "no file"}), 400
    # VULN: Unrestricted file upload — no extension/type validation
    save_path = os.path.join(UPLOAD_DIR, uploaded.filename)
    uploaded.save(save_path)
    return jsonify({"status": "uploaded", "path": save_path})
