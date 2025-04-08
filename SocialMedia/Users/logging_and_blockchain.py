import logging
import hashlib
import json
import requests
import os

logger = logging.getLogger(__name__)
BLOCKCHAIN_API_URL = "http://127.0.0.1:5000/add_message"
LATEST_LOG_FILE = "latest_log.json"

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR", "Unknown")

def hash_message(msg):
    return hashlib.sha256(msg.encode()).hexdigest()

def save_latest_log(log_str):
    with open(LATEST_LOG_FILE, "w") as f:
        f.write(log_str)

def load_latest_log():
    if not os.path.exists(LATEST_LOG_FILE):
        return None
    with open(LATEST_LOG_FILE, "r") as f:
        return f.read()

def log_request(request):
    try:
        log_data = {
            "method": request.method,
            "path": request.path,
            "full_path": request.get_full_path(),
            "query_params": dict(request.GET),
            "post_data": dict(request.POST),
            "ip_address": get_client_ip(request),
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            "referer": request.META.get("HTTP_REFERER", ""),
            "cookies": request.COOKIES,
            "user": request.user.username if request.user.is_authenticated else "Anonymous",
        }

        json_log = json.dumps(log_data, sort_keys=True)
        last_log = load_latest_log()

        if last_log:
            expected_prev_hash = hash_message(last_log)

            # Include previous log hash in new message
            file_hash = expected_prev_hash
        else:
            file_hash = None

        # Send log with optional file_hash to blockchain
        response = requests.post(BLOCKCHAIN_API_URL, json={
            "sender": log_data["user"],
            "message": json_log,
            "file_hash": file_hash
        })

        response.raise_for_status()
        logger.info(f"Logged to blockchain: {response.json()}")

        # Store current log as latest
        save_latest_log(json_log)

    except Exception as e:
        logger.error(f"Blockchain log failed: {e}")

    return log_data