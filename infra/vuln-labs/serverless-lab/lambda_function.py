"""Intentionally vulnerable AWS Lambda handler — serverless scan target.

This function contains planted security vulnerabilities for Semgrep SAST scanning.
It simulates a real-world Lambda that processes API Gateway events.
"""

import json
import logging
import os
import pickle
import random
import base64

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# VULN: Hardcoded AWS credentials (should use IAM role / environment)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULN: Hardcoded API key
THIRD_PARTY_API_KEY = "sk-live-51JGxf4RABCDEfghIJKLMnop"


def lambda_handler(event, context):
    """Main Lambda entry point — routes based on path."""
    path = event.get("rawPath", "/")

    # VULN: Logging sensitive data — full event body logged verbatim
    logger.info(f"Received event: {json.dumps(event)}")

    try:
        if path == "/query":
            return handle_query(event)
        elif path == "/fetch":
            return handle_fetch(event)
        elif path == "/process":
            return handle_process(event)
        elif path == "/execute":
            return handle_execute(event)
        elif path == "/token":
            return handle_token(event)
        else:
            return {"statusCode": 404, "body": json.dumps({"error": "not found"})}
    except:  # noqa: E722
        # VULN: Overly broad exception handling — bare except
        return {"statusCode": 500, "body": json.dumps({"error": "internal error"})}


def handle_query(event):
    """Query DynamoDB — vulnerable to injection."""
    params = event.get("queryStringParameters") or {}
    user_id = params.get("user_id", "")

    # VULN: No input validation on event parameters
    dynamodb = boto3.client(
        "dynamodb", region_name=os.environ.get("AWS_REGION", "us-east-1")
    )

    # VULN: SQL-style injection via PartiQL with f-string
    query = f"SELECT * FROM \"users\" WHERE user_id = '{user_id}'"
    response = dynamodb.execute_statement(Statement=query)

    return {
        "statusCode": 200,
        "body": json.dumps({"items": response.get("Items", [])}),
    }


def handle_fetch(event):
    """Fetch external URL — vulnerable to SSRF."""
    import requests

    params = event.get("queryStringParameters") or {}
    target_url = params.get("url", "")

    # VULN: SSRF — user-controlled URL passed to requests.get
    response = requests.get(target_url)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {"status": response.status_code, "length": len(response.text)}
        ),
    }


def handle_process(event):
    """Process serialized data — vulnerable to insecure deserialization."""
    body = event.get("body", "")

    # VULN: Insecure deserialization — pickle.loads on user-supplied data
    decoded = base64.b64decode(body)
    data = pickle.loads(decoded)

    return {
        "statusCode": 200,
        "body": json.dumps({"processed": str(data)}),
    }


def handle_execute(event):
    """Execute system command — vulnerable to command injection."""
    params = event.get("queryStringParameters") or {}
    filename = params.get("file", "")

    # VULN: Command injection — os.system with user input
    os.system("cat /tmp/" + filename)

    return {
        "statusCode": 200,
        "body": json.dumps({"status": "executed"}),
    }


def handle_token(event):
    """Generate a session token — uses weak randomness."""
    params = event.get("queryStringParameters") or {}
    user_id = params.get("user_id", "anonymous")

    # VULN: Weak random — random module for security token generation
    token = random.randint(100000, 999999)

    return {
        "statusCode": 200,
        "body": json.dumps({"token": f"{user_id}-{token}"}),
    }
