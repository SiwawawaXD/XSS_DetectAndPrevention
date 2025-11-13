from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import re
from datetime import datetime
import json
import logging
from elasticsearch import Elasticsearch
from neo4j import GraphDatabase
import socket
import urllib.parse
import os

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/logs/xss_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load ML model
try:
    model = joblib.load('/models/xss_model.pkl')
    scaler = joblib.load('/models/scaler.pkl')
    logger.info("ML models loaded successfully")
except Exception as e:
    logger.error(f"Error loading models: {e}")
    model = None
    scaler = None

# Elasticsearch connection
try:
    es = Elasticsearch(['http://elasticsearch:9200'])
    logger.info("Connected to Elasticsearch")
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
    logger.info("Connected to Neo4j")
except Exception as e:
    logger.error(f"Neo4j connection error: {e}")
    neo4j_driver = None


class XSSDetector:
    """XSS Detection using Machine Learning"""
    
    def __init__(self, model, scaler):
        self.model = model
        self.scaler = scaler
        
    def extract_features(self, payload):
        """Extract features from payload for ML model"""
        features = {}
        
        # Decode URL encoded strings
        decoded = urllib.parse.unquote(payload)
        
        # Basic features
        features['length'] = len(payload)
        features['num_special_chars'] = len(re.findall(r'[<>\'\"(){}[\]]', payload))
        features['num_digits'] = len(re.findall(r'\d', payload))
        features['num_spaces'] = payload.count(' ')
        
        # XSS-specific patterns
        features['has_script'] = int(bool(re.search(r'<script', payload, re.I)))
        features['has_javascript'] = int(bool(re.search(r'javascript:', payload, re.I)))
        features['has_onerror'] = int(bool(re.search(r'onerror\s*=', payload, re.I)))
        features['has_onload'] = int(bool(re.search(r'onload\s*=', payload, re.I)))
        features['has_onclick'] = int(bool(re.search(r'onclick\s*=', payload, re.I)))
        features['has_onfocus'] = int(bool(re.search(r'onfocus\s*=', payload, re.I)))
        features['has_onmouseover'] = int(bool(re.search(r'onmouseover\s*=', payload, re.I)))
        features['has_alert'] = int(bool(re.search(r'alert\s*\(', payload, re.I)))
        features['has_eval'] = int(bool(re.search(r'eval\s*\(', payload, re.I)))
        features['has_document_cookie'] = int(bool(re.search(r'document\.cookie', payload, re.I)))
        features['has_document_write'] = int(bool(re.search(r'document\.write', payload, re.I)))
        features['has_window_location'] = int(bool(re.search(r'window\.location', payload, re.I)))
        features['has_iframe'] = int(bool(re.search(r'<iframe', payload, re.I)))
        features['has_embed'] = int(bool(re.search(r'<embed', payload, re.I)))
        features['has_object'] = int(bool(re.search(r'<object', payload, re.I)))
        features['has_svg'] = int(bool(re.search(r'<svg', payload, re.I)))
        features['has_img'] = int(bool(re.search(r'<img', payload, re.I)))
        features['has_base64'] = int(bool(re.search(r'base64', payload, re.I)))
        features['has_data_uri'] = int(bool(re.search(r'data:', payload, re.I)))
        
        # Obfuscation detection
        features['has_hex_encoding'] = int(bool(re.search(r'\\x[0-9a-f]{2}', payload, re.I)))
        features['has_unicode'] = int(bool(re.search(r'\\u[0-9a-f]{4}', payload, re.I)))
        features['has_url_encoding'] = int(bool(re.search(r'%[0-9a-f]{2}', payload, re.I)))
        features['has_html_entity'] = int(bool(re.search(r'&#\d+;', payload)))
        
        # Statistical features
        features['entropy'] = self.calculate_entropy(payload)
        features['uppercase_ratio'] = sum(1 for c in payload if c.isupper()) / max(len(payload), 1)
        features['digit_ratio'] = features['num_digits'] / max(len(payload), 1)
        features['special_char_ratio'] = features['num_special_chars'] / max(len(payload), 1)
        
        # Count dangerous functions
        dangerous_funcs = ['eval', 'alert', 'prompt', 'confirm', 'setTimeout', 'setInterval']
        features['dangerous_func_count'] = sum(payload.lower().count(func) for func in dangerous_funcs)
        
        # HTML tag count
        features['html_tag_count'] = len(re.findall(r'<[^>]+>', payload))
        
        return features
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy
    
    def predict(self, payload):
        """Predict if payload is XSS attack"""
        if not self.model or not self.scaler:
            return {'error': 'Model not loaded'}, None
        
        try:
            features = self.extract_features(payload)
            feature_vector = np.array(list(features.values())).reshape(1, -1)
            feature_vector_scaled = self.scaler.transform(feature_vector)
            
            prediction = self.model.predict(feature_vector_scaled)[0]
            probability = self.model.predict_proba(feature_vector_scaled)[0]
            
            return {
                'is_malicious': bool(prediction),
                'confidence': float(max(probability)),
                'malicious_probability': float(probability[1]) if len(probability) > 1 else 0,
                'features': features
            }, features
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {'error': str(e)}, None


def determine_xss_type(payload):
    """Determine XSS attack type"""
    payload_lower = payload.lower()
    
    # DOM-based indicators
    dom_patterns = [
        'document.write', 'document.writeln', 'innerhtml', 'outerhtml',
        'document.location', 'window.location', 'document.url', 'document.referrer',
        'window.name', 'location.href', 'location.hash'
    ]
    
    if any(pattern in payload_lower for pattern in dom_patterns):
        return 'DOM-based XSS'
    
    # Stored/Reflected indicators
    if '<script' in payload_lower or 'javascript:' in payload_lower:
        return 'Stored/Reflected XSS'
    
    # Event handler based
    if re.search(r'on\w+\s*=', payload, re.I):
        return 'Event-based XSS'
    
    return 'Potential XSS'


def calculate_impact_level(confidence, features):
    """Calculate impact level based on confidence and features"""
    high_risk_features = [
        features.get('has_document_cookie', 0),
        features.get('has_eval', 0),
        features.get('has_document_write', 0),
        features.get('has_window_location', 0)
    ]
    
    if confidence > 0.9 or sum(high_risk_features) >= 2:
        return 'CRITICAL'
    elif confidence > 0.75 or sum(high_risk_features) >= 1:
        return 'HIGH'
    elif confidence > 0.6:
        return 'MEDIUM'
    elif confidence > 0.4:
        return 'LOW'
    return 'INFO'


def log_to_elasticsearch(detection_result):
    """Log detection result to Elasticsearch"""
    if not es:
        return
    
    try:
        es.index(
            index=f"xss-detections-{datetime.now().strftime('%Y.%m')}",
            document=detection_result
        )
        logger.info(f"Logged to Elasticsearch: {detection_result['request_id']}")
    except Exception as e:
        logger.error(f"Elasticsearch logging error: {e}")


def log_to_neo4j(detection_result):
    """Log attack pattern to Neo4j graph database"""
    if not neo4j_driver:
        return
    
    try:
        with neo4j_driver.session() as session:
            # Create attack node
            query = """
            CREATE (a:Attack {
                id: $id,
                timestamp: datetime($timestamp),
                payload: $payload,
                type: $type,
                impact: $impact,
                confidence: $confidence,
                ip_address: $ip_address,
                user_agent: $user_agent,
                blocked: $blocked
            })
            RETURN a
            """
            
            session.run(query, {
                'id': detection_result['request_id'],
                'timestamp': detection_result['timestamp'],
                'payload': detection_result['payload'][:500],  # Limit length
                'type': detection_result['xss_type'],
                'impact': detection_result['impact_level'],
                'confidence': detection_result['ml_detection']['confidence'],
                'ip_address': detection_result['ip_address'],
                'user_agent': detection_result['user_agent'],
                'blocked': detection_result['blocked']
            })
            
            # Create relationships for attack patterns
            if detection_result['ml_detection'].get('features'):
                features = detection_result['ml_detection']['features']
                
                # Link to attack techniques
                if features.get('has_script'):
                    session.run("""
                        MATCH (a:Attack {id: $id})
                        MERGE (t:Technique {name: 'Script Injection'})
                        MERGE (a)-[:USES]->(t)
                    """, {'id': detection_result['request_id']})
                
                if features.get('has_javascript'):
                    session.run("""
                        MATCH (a:Attack {id: $id})
                        MERGE (t:Technique {name: 'JavaScript Protocol'})
                        MERGE (a)-[:USES]->(t)
                    """, {'id': detection_result['request_id']})
                
                if features.get('has_onerror') or features.get('has_onload'):
                    session.run("""
                        MATCH (a:Attack {id: $id})
                        MERGE (t:Technique {name: 'Event Handler'})
                        MERGE (a)-[:USES]->(t)
                    """, {'id': detection_result['request_id']})
            
            logger.info(f"Logged to Neo4j: {detection_result['request_id']}")
    except Exception as e:
        logger.error(f"Neo4j logging error: {e}")


# Initialize detector
detector = XSSDetector(model, scaler) if model and scaler else None


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'elasticsearch': es is not None,
        'neo4j': neo4j_driver is not None
    })


@app.route('/detect', methods=['POST'])
def detect_xss():
    """Main XSS detection endpoint"""
    try:
        data = request.get_json()
        payload = data.get('payload', '')
        source = data.get('source', 'unknown')
        
        if not payload:
            return jsonify({'error': 'No payload provided'}), 400
        
        # Get client information
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # ML Detection
        ml_result, features = detector.predict(payload) if detector else ({'error': 'Detector not initialized'}, None)
        
        # Determine XSS type and impact
        xss_type = determine_xss_type(payload)
        impact_level = calculate_impact_level(
            ml_result.get('malicious_probability', 0),
            features or {}
        )
        
        # Create detection result
        detection_result = {
            'request_id': f"{datetime.now().strftime('%Y%m%d%H%M%S')}-{hash(payload) % 10000}",
            'timestamp': datetime.now().isoformat(),
            'payload': payload,
            'source': source,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'ml_detection': ml_result,
            'xss_type': xss_type,
            'impact_level': impact_level,
            'blocked': ml_result.get('is_malicious', False)
        }
        
        # Log to Elasticsearch
        log_to_elasticsearch(detection_result)
        
        # Log to Neo4j if malicious
        if detection_result['blocked']:
            log_to_neo4j(detection_result)
        
        logger.info(f"Detection completed: {detection_result['request_id']} - Blocked: {detection_result['blocked']}")
        
        return jsonify(detection_result)
    
    except Exception as e:
        logger.error(f"Detection error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/stats', methods=['GET'])
def get_stats():
    """Get detection statistics from Elasticsearch"""
    if not es:
        return jsonify({'error': 'Elasticsearch not available'}), 500
    
    try:
        # Get today's stats
        today = datetime.now().strftime('%Y.%m')
        
        # Total requests
        total = es.count(index=f"xss-detections-{today}")
        
        # Blocked requests
        blocked = es.count(
            index=f"xss-detections-{today}",
            body={'query': {'term': {'blocked': True}}}
        )
        
        # By impact level
        impact_agg = es.search(
            index=f"xss-detections-{today}",
            body={
                'size': 0,
                'aggs': {
                    'by_impact': {
                        'terms': {'field': 'impact_level.keyword'}
                    }
                }
            }
        )
        
        return jsonify({
            'total_requests': total['count'],
            'blocked_requests': blocked['count'],
            'allowed_requests': total['count'] - blocked['count'],
            'by_impact': impact_agg['aggregations']['by_impact']['buckets']
        })
    
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)