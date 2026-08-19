"""Utility functions — insecure deserialization, weak random, eval."""

import pickle
import random
import base64
from flask import request, jsonify


def deserialize_session():
    data = request.args.get("session", "")
    # VULN: Insecure deserialization — pickle.loads on user data
    decoded = base64.b64decode(data)
    session_obj = pickle.loads(decoded)
    return jsonify({"session": str(session_obj)})


def generate_reset_token(user_id):
    # VULN: Weak random — random module for security token
    token = random.randint(100000, 999999)
    return f"{user_id}-{token}"


def calculate():
    expression = request.args.get("expr", "0")
    # VULN: Dangerous eval — eval() on user input
    result = eval(expression)
    return jsonify({"result": result})
