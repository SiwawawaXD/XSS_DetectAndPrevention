from flask import Flask, request, jsonify, Response
import requests
import logging
from datetime import datetime
import json
import uuid
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

# Neo4j connection
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
    
    IMPORTANT: Filter out authentication field values to prevent false positives
    """
    payloads = []
    
    # Skip these common authentication fields to prevent false positives
    skip_fields = ['password', 'passwd', 'pwd', 'pass']
    
    if isinstance(request_data, dict):
        for key, value in request_data.items():
            # Skip authentication fields
            if key.lower() in skip_fields:
                continue
                
            if isinstance(value, str) and value:
                # Only check values that look like they could contain XSS
                # Skip simple alphanumeric values that are clearly not XSS
                if any(char in value for char in ['<', '>', 'script', 'javascript', 'onerror', 'onload', 'alert']):
                    payloads.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item:
                        if any(char in item for char in ['<', '>', 'script', 'javascript', 'onerror', 'onload', 'alert']):
                            payloads.append(item)
    elif isinstance(request_data, str):
        payloads.append(request_data)
    
    return ' '.join(payloads) if payloads else ''


def check_ml_detection(payload_data):
    """Send request to ML API for detection"""
    try:
        response = requests.post(
            f"{ML_API_URL}/detect",
            json=payload_data,
            timeout=3  # Reduced from 5 to 3 seconds
        )
        if response.status_code == 200:
            result = response.json()
            return result.get('is_malicious', False), result
        else:
            logger.error(f"ML API returned status {response.status_code}")
            return False, {"error": "ML API unavailable"}
    except requests.exceptions.Timeout:
        logger.error("ML API timeout")
        return False, {"error": "ML API timeout"}
    except Exception as e:
        logger.error(f"ML detection error: {e}")
        return False, {"error": str(e)}


def check_modsecurity(method, path, headers, data=None, params=None):
    """
    Send request through ModSecurity for WAF checking.
    ModSecurity acts as a reverse proxy to bWAPP.
    """
    try:
        url = f"{MODSECURITY_URL}{path}"
        
        response = requests.request(
            method=method,
            url=url,
            headers=dict(headers),
            data=data,
            params=params,
            allow_redirects=False,
            timeout=30  # Reduced from 60 to 30 seconds
        )
        
        # ModSecurity returns 403 when it blocks a request
        is_blocked = response.status_code == 403
        
        return is_blocked, response, {
            "blocked": is_blocked,
            "status_code": response.status_code,
            "response_body": response.text[:500] if response.text else ""
        }
    except requests.exceptions.Timeout:
        logger.error(f"ModSecurity timeout for {path}")
        raise  # Re-raise to handle at gateway level
    except Exception as e:
        logger.error(f"ModSecurity check error: {e}")
        raise  # Re-raise to handle at gateway level


def log_to_neo4j(detection_data):
    """Log detection results to Neo4j"""
    if not neo4j_driver:
        return
    
    try:
        with neo4j_driver.session() as session:
            request_id = detection_data.get('request_id', str(uuid.uuid4()))
           
            # Create detection node with proper labels
            session.run("""
                MERGE (r:Request {request_id: $request_id})
                SET r.timestamp = $timestamp,
                    r.method = $method,
                    r.path = $path,
                    r.client_ip = $client_ip,
                    r.payload = $payload
                
                CREATE (d:Detection {
                    request_id: $request_id,
                    timestamp: $timestamp,
                    modsecurity_blocked: $modsecurity_blocked,
                    ml_detected: $ml_detected,
                    ml_confidence: $ml_confidence,
                    detection_method: $detection_method,
                    is_blocked: $is_blocked,
                    payload: $payload
                })
                
                MERGE (r)-[:HAS_DETECTION]->(d)
            """,
                request_id=request_id,
                timestamp=detection_data.get('timestamp', datetime.now().isoformat()),
                method=detection_data.get('method', 'GET'),
                path=detection_data.get('path', '/'),
                client_ip=detection_data.get('client_ip', 'unknown'),
                payload=detection_data.get('payload', ''),
                modsecurity_blocked=detection_data.get('modsecurity_blocked', False),
                ml_detected=detection_data.get('ml_detected', False),
                ml_confidence=detection_data.get('ml_confidence', 0.0),
                detection_method=detection_data.get('detection_method', 'Unknown'),
                is_blocked=detection_data.get('is_blocked', False)
            )
            
            logger.info(f"Logged to Neo4j: {request_id}")
    except Exception as e:
        logger.error(f"Neo4j logging error: {e}")


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'neo4j_connected': neo4j_driver is not None,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def gateway(path):
    """
    Main gateway endpoint - DUAL-LAYER DETECTION
    
    ARCHITECTURE:
    1. Request arrives at Gateway
    2. Gateway checks ModSecurity (Layer 1 - Signature-based)
    3. Gateway checks ML API (Layer 2 - Behavior-based) 
    4. If ModSecurity blocks: return 403 immediately
    5. If ML detects but ModSecurity allows: return 403
    6. If both allow: return ModSecurity's response (which already proxied to bWAPP)
    
    This ensures DUAL-LAYER protection while maintaining proper request flow.
    """
    try:
        request_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        # Extract request data
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        method = request.method
        request_path = f"/{path}"
        
        # Get payload from request
        if request.method == 'POST':
            if request.is_json:
                request_data = request.get_json()
            else:
                request_data = request.form.to_dict()
        else:
            request_data = request.args.to_dict()
        
        payload_string = extract_payload_string(request_data)
        
        # Skip detection for empty payloads and certain paths
        skip_paths = ['/health', '/favicon.ico', '/robots.txt']
        if any(request_path.startswith(p) for p in skip_paths):
            # Forward directly through ModSecurity to bWAPP
            try:
                _, modsec_response, _ = check_modsecurity(
                    method, request_path, request.headers, request.get_data(), request.args
                )
                return Response(
                    modsec_response.content, 
                    status=modsec_response.status_code, 
                    headers=dict(modsec_response.headers)
                )
            except Exception as e:
                logger.error(f"Error forwarding skip_path: {e}")
                return jsonify({'error': 'Backend error'}), 502
        
        # LAYER 1: Check ModSecurity (this also forwards to bWAPP if allowed)
        logger.info(f"[{request_id}] Checking ModSecurity for {method} {request_path}")
        try:
            modsecurity_blocked, modsec_response, modsecurity_result = check_modsecurity(
                method, request_path, request.headers, request.get_data(), request.args
            )
        except Exception as e:
            logger.error(f"[{request_id}] ModSecurity error: {e}")
            return jsonify({'error': 'Security check failed', 'details': str(e)}), 502
        
        # LAYER 2: Check ML detection (only if we have payload to check)
        ml_detected = False
        ml_confidence = 0.0
        ml_result = {}
        
        if payload_string:
            logger.info(f"[{request_id}] Checking ML API with payload: {payload_string[:100]}")
            ml_detected, ml_result = check_ml_detection({
                'payload': payload_string,
                'client_ip': client_ip,
                'path': request_path,
                'method': method
            })
            ml_confidence = ml_result.get('confidence', 0.0)
            if ml_detected:
                logger.warning(f"[{request_id}] ML detected attack with confidence {ml_confidence}")
        
        # Determine detection method
        detection_method = []
        if modsecurity_blocked:
            detection_method.append('ModSecurity')
        if ml_detected:
            detection_method.append('ML')
        
        is_blocked = modsecurity_blocked or ml_detected
        
        # Log to Neo4j
        log_to_neo4j({
            'request_id': request_id,
            'timestamp': timestamp,
            'method': method,
            'path': request_path,
            'client_ip': client_ip,
            'payload': payload_string,
            'modsecurity_blocked': modsecurity_blocked,
            'ml_detected': ml_detected,
            'ml_confidence': ml_confidence,
            'detection_method': ', '.join(detection_method) if detection_method else 'None',
            'is_blocked': is_blocked
        })
        
        # Decision logic
        if is_blocked:
            logger.warning(f"[{request_id}] BLOCKED by {', '.join(detection_method)}")
            return jsonify({
                'request_id': request_id,
                'blocked': True,
                'timestamp': timestamp,
                'detection_layers': {
                    'modsecurity': {
                        'blocked': modsecurity_blocked,
                        'details': modsecurity_result
                    },
                    'ml': {
                        'detected': ml_detected,
                        'confidence': ml_confidence,
                        'details': ml_result
                    }
                },
                'message': 'Request blocked by security filters'
            }), 403
        else:
            # Both layers allowed - return ModSecurity's response
            # (which already proxied to bWAPP)
            logger.info(f"[{request_id}] ALLOWED - returning bWAPP response")
            
            # Clean up headers for response
            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            clean_headers = {k: v for k, v in modsec_response.headers.items() 
                           if k.lower() not in excluded_headers}
            
            return Response(
                modsec_response.content, 
                status=modsec_response.status_code, 
                headers=clean_headers
            )
            
    except Exception as e:
        logger.error(f"Gateway error: {e}", exc_info=True)
        return jsonify({'error': 'Gateway error', 'details': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)