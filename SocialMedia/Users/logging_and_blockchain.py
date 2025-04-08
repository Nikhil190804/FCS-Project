import logging
import hashlib
import json
import requests

logger = logging.getLogger(__name__)
BLOCKCHAIN_API_URL = "http://127.0.0.1:5000/add_message"

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0]
    return request.META.get("REMOTE_ADDR", "Unknown")

def log_request(request):
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

    logger.info(f"Request Log: {log_data}")

    # Send log to blockchain
    try:
        json_log = json.dumps(log_data, sort_keys=True)
        response = requests.post(BLOCKCHAIN_API_URL, json={
            "sender": log_data["user"],
            "message": json_log
        })
        response.raise_for_status()
        logger.info(f"Logged to blockchain: {response.json()}")
    except Exception as e:
        logger.error(f"Blockchain log failed: {e}")

    return log_data
