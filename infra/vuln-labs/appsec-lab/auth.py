"""Authentication module — hardcoded secrets and weak hashing."""

import hashlib
import hmac

# VULN: Hardcoded secret key
SECRET_KEY = "super-secret-key-12345"

# VULN: Hardcoded API token
API_TOKEN = "ghp_a1b2c3d4e5f6g7h8i9j0klmnopqrstuvwx"

# VULN: Hardcoded database password
DB_PASSWORD = "postgres_admin_P@ss!"


def hash_password(password):
    # VULN: Weak hash — MD5 for password storage
    return hashlib.md5(password.encode()).hexdigest()


def generate_token(user_id):
    # VULN: Weak hash — SHA1 for token generation
    data = f"{user_id}:{SECRET_KEY}"
    return hashlib.sha1(data.encode()).hexdigest()


def verify_token(token, user_id):
    expected = generate_token(user_id)
    return hmac.compare_digest(token, expected)


def authenticate(username, password):
    hashed = hash_password(password)
    # In real app this would check DB
    return hashed is not None
