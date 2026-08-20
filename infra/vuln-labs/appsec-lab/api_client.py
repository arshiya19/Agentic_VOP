"""External API client — SSRF and command injection."""

import os
import subprocess
import urllib.request
import requests
from flask import request, jsonify


def fetch_url():
    target_url = request.args.get("url", "")
    # VULN: SSRF — user-controlled URL passed to requests.get
    response = requests.get(target_url)
    return jsonify({"status": response.status_code, "length": len(response.text)})


def fetch_metadata():
    endpoint = request.args.get("endpoint", "")
    # VULN: SSRF — user-controlled URL passed to urllib
    resp = urllib.request.urlopen(endpoint)
    return resp.read().decode()


def ping_host():
    host = request.args.get("host", "")
    # VULN: Command injection — os.system with user input
    os.system("ping -c 1 " + host)
    return jsonify({"status": "pinged"})


def run_diagnostic():
    cmd = request.args.get("cmd", "echo ok")
    # VULN: Command injection — subprocess with shell=True
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return jsonify({"stdout": result.stdout, "stderr": result.stderr})
