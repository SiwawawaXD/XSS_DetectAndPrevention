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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/logs/gateway.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Service URLs
MODSECURITY_URL = "http://modsecurity:80"
ML_API_URL = "http://xss_detection_api:5001"
BWAPP_URL = "http://bwapp:80"

# Elasticsearch connection
try:
    es = Elasticsearch(['http://elasticsearch:9200'])
    logger.info("Gateway connected to Elasticsearch")
except Exception as e:
    logger.error(f"Elasticsearch connection error: {e}")
    es = None

# Neo4j connection
try:
    neo4j_uri = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
    neo4j_user = os.getenv('NEO4J_USER', 'neo4j')
    neo4j_password = os.getenv('NEO4J_PASSWORD', 'SecureGCPPassword123!')
    
    neo4j_driver = GraphDatabase.driver(
        neo4j_uri,
        auth=(neo4j_user, neo4j_password)
    )
    logger.info("Gateway connected to Neo4j")
except Exception as e:
    logger.error(f"Neo4j connection error: {e}")
    neo4j_driver = None


def check_ml_detection(payload_data):
    """Send request to ML API for detection"""
    try:
        response = requests.post(
            f"{ML_API_URL}/detect",
            json=payload_data,
            timeout=5
        )
        if response.status_code == 200:
            result = response.json()
            return result.get('is_malicious', False), result
        else:
            logger.error(f"ML API returned status {response.status_code}")
            return False, {"error": "ML API unavailable"}
    except Exception as e:
        logger.error(f"ML detection error: {e}")
        return False, {"error": str(e)}


def check_modsecurity(method, path, headers, data=None, params=None):
    """Send request through ModSecurity for WAF checking"""
    try:
        # Forward the request to ModSecurity
        url = f"{MODSECURITY_URL}{path}"
        
        response = requests.request(
            method=method,
            url=url,
            headers=dict(headers),
            data=data,
            params=params,
            allow_redirects=False,
            timeout=10
        )
        
        # ModSecurity returns 403 when it blocks a request
        is_blocked = response.status_code == 403
        
        return is_blocked, {
            "blocked": is_blocked,
            "status_code": response.status_code,
            "response": response.text[:500] if is_blocked else None
        }
    except Exception as e:
        logger.error(f"ModSecurity check error: {e}")
        return False, {"error": str(e)}


def log_blocked_request(request_data, detection_results):
    """Log blocked request to Elasticsearch and Neo4j"""
    log_entry = {
        "request_id": request_data['request_id'],
        "timestamp": datetime.now().isoformat(),
        "blocked": True,
        "ip_address": request_data['ip_address'],
        "method": request_data['method'],
        "path": request_data['path'],
        "user_agent": request_data['user_agent'],
        "payload": request_data['payload'],
        "modsecurity_result": detection_results.get('modsecurity', {}),
        "ml_result": detection_results.get('ml', {}),
        "blocked_by": detection_results.get('blocked_by', [])
    }
    
    # Log to Elasticsearch
    if es:
        try:
            es.index(
                index=f"blocked-requests-{datetime.now().strftime('%Y.%m.%d')}",
                document=log_entry
            )
            logger.info(f"Logged blocked request to Elasticsearch: {request_data['request_id']}")
        except Exception as e:
            logger.error(f"Elasticsearch logging error: {e}")
    
    # Log to Neo4j
    if neo4j_driver:
        try:
            with neo4j_driver.session() as session:
                query = """
                CREATE (r:BlockedRequest {
                    id: $id,
                    timestamp: datetime($timestamp),
                    ip_address: $ip_address,
                    method: $method,
                    path: $path,
                    payload: $payload,
                    blocked_by: $blocked_by,
                    modsecurity_blocked: $modsecurity_blocked,
                    ml_blocked: $ml_blocked
                })
                RETURN r
                """
                
                session.run(query, {
                    'id': log_entry['request_id'],
                    'timestamp': log_entry['timestamp'],
                    'ip_address': log_entry['ip_address'],
                    'method': log_entry['method'],
                    'path': log_entry['path'],
                    'payload': str(log_entry['payload'])[:500],
                    'blocked_by': detection_results.get('blocked_by', []),
                    'modsecurity_blocked': detection_results.get('modsecurity', {}).get('blocked', False),
                    'ml_blocked': detection_results.get('ml', {}).get('is_malicious', False)
                })
                logger.info(f"Logged blocked request to Neo4j: {request_data['request_id']}")
        except Exception as e:
            logger.error(f"Neo4j logging error: {e}")


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "gateway"}), 200


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def gateway(path):
    """
    Main gateway endpoint that intercepts all requests
    Flow:
    1. Request arrives at gateway
    2. Check with ModSecurity
    3. Check with ML API
    4. If either blocks, log and return 403
    5. If both allow, forward to bWAPP
    """
    request_id = str(uuid.uuid4())
    
    # Collect request data
    request_data = {
        'request_id': request_id,
        'ip_address': request.remote_addr,
        'method': request.method,
        'path': f"/{path}",
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'headers': dict(request.headers),
        'params': dict(request.args),
        'payload': {}
    }
    
    # Get payload based on content type
    if request.method in ['POST', 'PUT', 'PATCH']:
        if request.is_json:
            request_data['payload'] = request.get_json(silent=True) or {}
        elif request.form:
            request_data['payload'] = dict(request.form)
        else:
            request_data['payload'] = {'raw': request.get_data(as_text=True)}
    
    # Combine all input data for ML checking
    all_data = {
        'url': request_data['path'],
        'params': request_data['params'],
        'body': request_data['payload']
    }
    
    logger.info(f"Request {request_id}: {request_data['method']} {request_data['path']}")
    
    detection_results = {}
    blocked_by = []
    
    # Step 1: Check with ModSecurity
    logger.info(f"Request {request_id}: Checking with ModSecurity")
    modsec_blocked, modsec_result = check_modsecurity(
        method=request.method,
        path=request_data['path'],
        headers=request.headers,
        data=request.get_data(),
        params=request.args
    )
    detection_results['modsecurity'] = modsec_result
    
    if modsec_blocked:
        blocked_by.append('ModSecurity')
        logger.warning(f"Request {request_id}: BLOCKED by ModSecurity")
    
    # Step 2: Check with ML API
    logger.info(f"Request {request_id}: Checking with ML API")
    ml_blocked, ml_result = check_ml_detection(all_data)
    detection_results['ml'] = ml_result
    
    if ml_blocked:
        blocked_by.append('ML')
        logger.warning(f"Request {request_id}: BLOCKED by ML")
    
    # Step 3: Decide whether to block or forward
    if blocked_by:
        # Request is malicious - block and log
        detection_results['blocked_by'] = blocked_by
        log_blocked_request(request_data, detection_results)
        
        return jsonify({
            "error": "Request blocked",
            "request_id": request_id,
            "blocked_by": blocked_by,
            "message": "Your request was identified as potentially malicious and has been blocked."
        }), 403
    
    # Step 4: Forward to bWAPP if not blocked
    logger.info(f"Request {request_id}: ALLOWED - Forwarding to bWAPP")
    try:
        url = f"{BWAPP_URL}/{path}"
        
        response = requests.request(
            method=request.method,
            url=url,
            headers={key: value for key, value in request.headers if key.lower() != 'host'},
            data=request.get_data(),
            params=request.args,
            allow_redirects=False,
            timeout=30
        )
        
        # Forward the response from bWAPP back to the client
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in response.raw.headers.items()
                   if name.lower() not in excluded_headers]
        
        return Response(response.content, response.status_code, headers)
        
    except Exception as e:
        logger.error(f"Error forwarding to bWAPP: {e}")
        return jsonify({
            "error": "Backend error",
            "message": "Unable to process request"
        }), 502


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
