from flask import Flask, request, jsonify, Response
import requests
import logging
from datetime import datetime
import json
import uuid
from elasticsearch import Elasticsearch
from neo4j import GraphDatabase
import os

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/logs/gateway.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

MODSECURITY_URL = "http://modsecurity:80"
ML_API_URL = "http://xss_detection_api:5001"
BWAPP_URL = "http://bwapp:80"

try:
    es = Elasticsearch(['http://elasticsearch:9200'])
    logger.info("Gateway connected to Elasticsearch")
except Exception as e:
    logger.error(f"Elasticsearch connection error: {e}")
    es = None

try:
    neo4j_uri = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
    neo4j_user = os.getenv('NEO4J_USER', 'neo4j')
    neo4j_password = os.getenv('NEO4J_PASSWORD', 'SecureGCPPassword123!')
    neo4j_driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    logger.info("Gateway connected to Neo4j")
except Exception as e:
    logger.error(f"Neo4j connection error: {e}")
    neo4j_driver = None


def extract_payload_string(request_data):
    """
    Extract only the VALUES from user input (not field names).
    This prevents false positives from field names like 'password', 'script', etc.
    """
    payloads = []
    
    # Check path for suspicious patterns (but not common pages)
    path = request_data.get('path', '')
    if path and not path.endswith(('.php', '.html', '.css', '.js', '.png', '.jpg', '.gif')):
        payloads.append(path)
    
    # Only check the VALUES of query parameters (not the keys)
    if request_data.get('query_params'):
        for key, value in request_data['query_params'].items():
            # Skip common safe field names, only add the value
            payloads.append(str(value))
    
    # Only check the VALUES of body data (not the keys)
    if request_data.get('body'):
        body = request_data['body']
        if isinstance(body, dict):
            for key, value in body.items():
                # Skip common form fields that won't contain attacks
                if key.lower() in ['csrf_token', 'token', '_token']:
                    continue
                # Only add the value, not the key
                payloads.append(str(value))
        elif isinstance(body, str):
            payloads.append(body)
    
    # Combine all payloads with space
    combined_payload = " ".join(payloads)
    return combined_payload


def check_ml_detection(request_data):
    """Send request to ML API for detection"""
    try:
        payload_string = extract_payload_string(request_data)
        
        # Skip ML detection for very short/simple payloads
        if not payload_string.strip() or len(payload_string) < 5:
            return False, {"is_malicious": False, "reason": "Payload too short"}
        
        logger.info(f"ML API checking payload: {payload_string[:100]}...")
        
        response = requests.post(
            f"{ML_API_URL}/detect",
            json={"payload": payload_string, "source": f"{request_data.get('method', 'UNKNOWN')} {request_data.get('path', '/')}"},
            timeout=5
        )
        
        if response.status_code == 200:
            result = response.json()
            is_malicious = result.get('blocked', False) or result.get('is_malicious', False)
            confidence = result.get('ml_detection', {}).get('confidence', 0)
            
            # Only block if confidence is very high (> 0.8)
            if is_malicious and confidence < 0.8:
                logger.info(f"ML API detected potential threat but confidence too low ({confidence}), allowing request")
                is_malicious = False
            
            logger.info(f"ML API result: malicious={is_malicious}, confidence={confidence}")
            return is_malicious, result
        else:
            logger.error(f"ML API returned status {response.status_code}")
            return False, {"error": "ML API unavailable"}
    except Exception as e:
        logger.error(f"ML detection error: {e}")
        return False, {"error": str(e)}


def check_modsecurity(method, path, headers, data=None, params=None):
    """Send request through ModSecurity for WAF checking"""
    try:
        url = f"{MODSECURITY_URL}{path}"
        response = requests.request(method=method, url=url, headers=dict(headers), data=data, params=params, allow_redirects=False, timeout=60)
        is_blocked = response.status_code == 403
        return is_blocked, {"blocked": is_blocked, "status_code": response.status_code}
    except Exception as e:
        logger.error(f"ModSecurity check error: {e}")
        return False, {"error": str(e)}


def log_blocked_request(request_data, detection_results):
    """Log blocked request to Elasticsearch and Neo4j"""
    if es:
        try:
            index_name = f"blocked-requests-{datetime.now().strftime('%Y.%m.%d')}"
            log_entry = {**request_data, "detection_results": detection_results, "timestamp": datetime.now().isoformat()}
            es.index(index=index_name, document=log_entry)
            logger.info(f"Logged to Elasticsearch: {request_data.get('request_id')}")
        except Exception as e:
            logger.error(f"Elasticsearch logging error: {e}")
    
    if neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                session.run("CREATE (r:BlockedRequest {id: $id, timestamp: datetime($timestamp), method: $method, path: $path, source_ip: $source_ip, blocked_by: $blocked_by})",
                    id=request_data['request_id'], timestamp=request_data['timestamp'], method=request_data['method'], path=request_data['path'], source_ip=request_data['source_ip'], blocked_by=request_data.get('blocked_by', 'unknown'))
            logger.info(f"Logged to Neo4j: {request_data.get('request_id')}")
        except Exception as e:
            logger.error(f"Neo4j logging error: {e}")


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def gateway(path):
    request_id = str(uuid.uuid4())
    if path and not path.startswith('/'):
        path = '/' + path
    elif not path:
        path = '/'
    
    logger.info(f"Request {request_id}: {request.method} {path}")
    
    try:
        request_body = request.get_data()
        request_body_text = request_body.decode('utf-8', errors='ignore')
    except:
        request_body = b''
        request_body_text = ''
    
    body_dict = {}
    if request_body_text:
        try:
            body_dict = json.loads(request_body_text)
        except:
            try:
                from urllib.parse import parse_qs
                parsed = parse_qs(request_body_text)
                body_dict = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
            except:
                body_dict = {"raw": request_body_text}
    
    ml_request_data = {"method": request.method, "path": path, "query_params": dict(request.args), "body": body_dict}
    
    logger.info(f"Request {request_id}: Checking with ModSecurity")
    waf_blocked, waf_result = check_modsecurity(request.method, path, request.headers, request_body, request.args)
    
    logger.info(f"Request {request_id}: Checking with ML API")
    ml_blocked, ml_result = check_ml_detection(ml_request_data)
    
    if waf_blocked or ml_blocked:
        blocked_by = "WAF" if waf_blocked else "ML"
        logger.warning(f"Request {request_id}: BLOCKED by {blocked_by}")
        log_data = {"request_id": request_id, "timestamp": datetime.now().isoformat(), "method": request.method, "path": path, "source_ip": request.remote_addr, "blocked_by": blocked_by}
        log_blocked_request(log_data, {"waf": waf_result, "ml": ml_result})
        return jsonify({"request_id": request_id, "blocked_by": blocked_by, "message": "Your request was identified as potentially malicious and has been blocked."}), 403
    
    logger.info(f"Request {request_id}: ALLOWED - Forwarding to bWAPP")
    try:
        url = f"{BWAPP_URL}{path}"
        response = requests.request(method=request.method, url=url, headers={key: value for key, value in request.headers if key.lower() != 'host'}, data=request_body, params=request.args, allow_redirects=False, timeout=60)
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in response.raw.headers.items() if name.lower() not in excluded_headers]
        return Response(response.content, response.status_code, headers)
    except Exception as e:
        logger.error(f"Error forwarding to bWAPP: {e}")
        return jsonify({"error": "Backend error", "message": "Unable to process request"}), 502


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
