from flask import Flask, request, jsonify, Response
import requests
import logging
from datetime import datetime
import json
import uuid
import os
from neo4j import GraphDatabase   # still optional but unused now

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler('/logs/gateway.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


### --------------------------------------------------------
### URLs for services
### --------------------------------------------------------
MODSECURITY_URL = "http://modsecurity:80"
ML_API_URL = "http://ml_api:8080/analyze"
BWAPP_URL = "http://bwapp:80"
NORMALIZER_URL = "http://normalizer:9000/raw"


### --------------------------------------------------------
### PAYLOAD EXTRACTION
### --------------------------------------------------------
def extract_payload_string(request_data):
    payloads = []

    path = request_data.get("path", "")
    if path and not path.endswith((".php", ".html", ".css", ".js", ".png", ".jpg", ".gif")):
        payloads.append(path)

    if request_data.get("query_params"):
        for key, value in request_data["query_params"].items():
            payloads.append(str(value))

    if request_data.get("body"):
        body = request_data["body"]
        if isinstance(body, dict):
            for key, value in body.items():
                if key.lower() in ["csrf_token", "token", "_token"]:
                    continue
                payloads.append(str(value))
        elif isinstance(body, str):
            payloads.append(body)

    return " ".join(payloads)


### --------------------------------------------------------
### ML CHECK  (NEW CONTRACT)
### ML API returns: 
#   { "is_malicious": bool, "confidence": float, "detected_patterns": [] }
### --------------------------------------------------------
def check_ml_detection(request_data):
    try:
        payload_string = extract_payload_string(request_data)

        if not payload_string.strip():
            return False, {"is_malicious": False, "reason": "Empty payload"}

        logger.info(f"ML API checking payload: {payload_string[:100]}...")

        response = requests.post(
            ML_API_URL,
            json={"payload": payload_string},
            timeout=5
        )

        if response.status_code != 200:
            return False, {"error": "ML API failure"}

        result = response.json()
        is_malicious = result.get("is_malicious", False)
        confidence = result.get("confidence", 0)

        logger.info(f"ML API RESULT → malicious={is_malicious}, confidence={confidence}")

        return is_malicious, result

    except Exception as e:
        logger.error(f"ML detection error: {e}")
        return False, {"error": str(e)}


### --------------------------------------------------------
### MODSECURITY CHECK
### --------------------------------------------------------
def check_modsecurity(method, path, headers, data=None, params=None):
    try:
        url = f"{MODSECURITY_URL}{path}"
        response = requests.request(
            method=method,
            url=url,
            headers=dict(headers),
            data=data,
            params=params,
            allow_redirects=False,
            timeout=60
        )
        is_blocked = response.status_code == 403
        return is_blocked, {
            "is_malicious": is_blocked,
            "status_code": response.status_code,
            "detected_patterns": ["modsecurity_block"] if is_blocked else []
        }

    except Exception as e:
        logger.error(f"ModSecurity check error: {e}")
        return False, {"error": str(e)}


### --------------------------------------------------------
### SEND TO NORMALIZER → NEO4J
### --------------------------------------------------------
def send_log_to_normalizer(raw_data):
    try:
        logger.info("Sending log to normalizer")
        response = requests.post(NORMALIZER_URL, json=raw_data, timeout=3)
        logger.info(f"Normalizer response: {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send log to normalizer: {e}")


### --------------------------------------------------------
### BLOCK RESPONSE HANDLER
### --------------------------------------------------------
def deny_request(block_source, detection_data, request_id, path):
    logger.warning(f"Request {request_id} BLOCKED by {block_source}")

    log_record = {
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request_id,
        "method": request.method,
        "endpoint": path,
        "source_ip": request.remote_addr,
        "blocked": True,
        "blocked_by": block_source,
        "attack_type": "xss",
        "payload": detection_data.get("raw_payload", "N/A"),
        "normalized_payload": detection_data.get("normalized_payload", "N/A"),
        "decoded_versions": detection_data.get("decoded_versions", []),
        "detected_patterns": detection_data.get("detected_patterns", []),
        "confidence": detection_data.get("confidence", 0),
        "labels": ["AttackEvent", "BlockedRequest"]
    }

    send_log_to_normalizer(log_record)

    return jsonify({
        "request_id": request_id,
        "blocked_by": block_source,
        "message": "Your request was identified as malicious and was blocked."
    }), 403



### --------------------------------------------------------
### FORWARD SAFE REQUEST TO BWAPP
### --------------------------------------------------------
def process_request(path, request_body):
    try:
        url = f"{BWAPP_URL}{path}"
        response = requests.request(
            method=request.method,
            url=url,
            headers={k: v for k, v in request.headers if k.lower() != 'host'},
            data=request_body,
            params=request.args,
            allow_redirects=False,
            timeout=60
        )
        excluded = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(n, v) for (n, v) in response.raw.headers.items() if n.lower() not in excluded]

        return Response(response.content, response.status_code, headers)

    except Exception as e:
        logger.error(f"Error forwarding to bWAPP: {e}")
        return jsonify({"error": "backend error"}), 502


### --------------------------------------------------------
### MAIN GATEWAY ROUTE
### --------------------------------------------------------
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def gateway(path):
    request_id = str(uuid.uuid4())
    path = "/" + path if not path.startswith("/") else path

    logger.info(f"[{request_id}] Incoming {request.method} {path}")

    # Parse body
    try:
        raw_body = request.get_data()
        body_text = raw_body.decode("utf-8", errors="ignore")
    except:
        raw_body = b""
        body_text = ""

    try:
        body_dict = json.loads(body_text) if body_text else {}
    except:
        body_dict = {"raw": body_text}

    ### 1) CHECK MODSECURITY FIRST
    waf_blocked, waf_result = check_modsecurity(
        request.method, path, request.headers, raw_body, request.args
    )

    if waf_blocked:
        return deny_request("WAF", waf_result, request_id, path)

    ### 2) IF WAF ALLOWED → CHECK ML API
    ml_data = {
        "method": request.method,
        "path": path,
        "query_params": dict(request.args),
        "body": body_dict
    }
    ml_blocked, ml_result = check_ml_detection(ml_data)

    if ml_blocked:
        return deny_request("ML", ml_result, request_id, path)

    ### 3) REQUEST IS SAFE → LOG + FORWARD
    safe_log = {
    "timestamp": datetime.utcnow().isoformat(),
    "request_id": request_id,
    "method": request.method,
    "endpoint": path,
    "source_ip": request.remote_addr,

    "blocked": False,
    "blocked_by": None,
    "attack_type": "none",
    "payload": extract_payload_string(ml_data),
    "normalized_payload": extract_payload_string(ml_data), 
    "decoded_versions": [],

    "detected_patterns": [],
    "confidence": 0.0,
    "labels": ["NormalRequest"]
    }
    send_log_to_normalizer(safe_log)

    return process_request(path, raw_body)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
