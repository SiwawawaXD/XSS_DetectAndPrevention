from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd
import re
from datetime import datetime
import json
import logging
from neo4j import GraphDatabase
import os
import shutil
from pathlib import Path
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import urllib.parse

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

# Paths
MODELS_DIR = Path('/models')
ACTIVE_MODEL_PATH = MODELS_DIR / 'xss_model.pkl'
ACTIVE_SCALER_PATH = MODELS_DIR / 'scaler.pkl'
MODEL_ARCHIVE_DIR = MODELS_DIR / 'archive'
TRAINING_DATA_DIR = Path('/training_data')

# Create directories
MODELS_DIR.mkdir(exist_ok=True)
MODEL_ARCHIVE_DIR.mkdir(exist_ok=True)
TRAINING_DATA_DIR.mkdir(exist_ok=True)

# Model version tracking
MODEL_METADATA_PATH = MODELS_DIR / 'model_metadata.json'

class ModelManager:
    """Manages multiple ML models and version control"""
    
    def __init__(self):
        self.metadata = self.load_metadata()
        
    def load_metadata(self):
        """Load model metadata"""
        if MODEL_METADATA_PATH.exists():
            with open(MODEL_METADATA_PATH, 'r') as f:
                return json.load(f)
        return {
            'active_model': 'initial',
            'models': {},
            'model_history': []
        }
    
    def save_metadata(self):
        """Save model metadata"""
        with open(MODEL_METADATA_PATH, 'w') as f:
            json.dump(self.metadata, f, indent=2)
    
    def list_models(self):
        """List all available models"""
        models = []
        for model_file in MODEL_ARCHIVE_DIR.glob('*.pkl'):
            model_name = model_file.stem.replace('xss_model_', '')
            scaler_file = MODEL_ARCHIVE_DIR / f'scaler_{model_name}.pkl'
            if scaler_file.exists():
                models.append({
                    'name': model_name,
                    'model_path': str(model_file),
                    'scaler_path': str(scaler_file),
                    'metadata': self.metadata.get('models', {}).get(model_name, {})
                })
        
        # Add active model
        if ACTIVE_MODEL_PATH.exists():
            models.insert(0, {
                'name': 'active',
                'model_path': str(ACTIVE_MODEL_PATH),
                'scaler_path': str(ACTIVE_SCALER_PATH),
                'metadata': self.metadata.get('models', {}).get(self.metadata.get('active_model'), {})
            })
        
        return models
    
    def save_model(self, model, scaler, model_name, metrics=None):
        """Save a trained model with version control"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        version_name = f"{model_name}_{timestamp}"
        
        # Save to archive
        archive_model_path = MODEL_ARCHIVE_DIR / f'xss_model_{version_name}.pkl'
        archive_scaler_path = MODEL_ARCHIVE_DIR / f'scaler_{version_name}.pkl'
        
        joblib.dump(model, archive_model_path)
        joblib.dump(scaler, archive_scaler_path)
        
        # Update metadata
        self.metadata['models'][version_name] = {
            'created_at': timestamp,
            'name': model_name,
            'metrics': metrics or {},
            'version': version_name
        }
        
        self.metadata['model_history'].append({
            'version': version_name,
            'timestamp': timestamp,
            'action': 'trained'
        })
        
        self.save_metadata()
        logger.info(f"Model saved: {version_name}")
        
        return version_name
    
    def activate_model(self, model_name):
        """Switch to a different model - with backup of current active model"""
        # Find model in archive
        model_path = MODEL_ARCHIVE_DIR / f'xss_model_{model_name}.pkl'
        scaler_path = MODEL_ARCHIVE_DIR / f'scaler_{model_name}.pkl'
        
        if not model_path.exists() or not scaler_path.exists():
            raise FileNotFoundError(f"Model {model_name} not found")
        
        # Backup current active model if exists
        # This allows you to revert back if the new model doesn't work well
        if ACTIVE_MODEL_PATH.exists():
            backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            backup_model_path = MODEL_ARCHIVE_DIR / f'xss_model_{backup_name}.pkl'
            backup_scaler_path = MODEL_ARCHIVE_DIR / f'scaler_{backup_name}.pkl'
            
            shutil.copy(ACTIVE_MODEL_PATH, backup_model_path)
            shutil.copy(ACTIVE_SCALER_PATH, backup_scaler_path)
            
            # Store backup info in metadata
            self.metadata['models'][backup_name] = {
                'created_at': datetime.now().strftime('%Y%m%d_%H%M%S'),
                'name': 'backup',
                'is_backup': True,
                'backed_up_from': self.metadata.get('active_model', 'unknown')
            }
            
            logger.info(f"Current active model backed up as: {backup_name}")
        
        # Copy selected model to active
        shutil.copy(model_path, ACTIVE_MODEL_PATH)
        shutil.copy(scaler_path, ACTIVE_SCALER_PATH)
        
        # Update metadata
        self.metadata['active_model'] = model_name
        self.metadata['model_history'].append({
            'version': model_name,
            'timestamp': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'action': 'activated'
        })
        self.save_metadata()
        
        logger.info(f"Activated model: {model_name}")
        return True

# Initialize model manager
model_manager = ModelManager()

# Load active ML model
class XSSDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.load_model()
    
    def load_model(self):
        """Load the active model"""
        try:
            if ACTIVE_MODEL_PATH.exists() and ACTIVE_SCALER_PATH.exists():
                self.model = joblib.load(ACTIVE_MODEL_PATH)
                self.scaler = joblib.load(ACTIVE_SCALER_PATH)
                logger.info("Active ML model loaded successfully")
            else:
                logger.warning("No active model found - training initial model")
                self.train_initial_model()
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self.model = None
            self.scaler = None
    
    def train_initial_model(self):
        """Train initial model from kaggle_xss.csv"""
        try:
            # Check for kaggle dataset
            kaggle_path = TRAINING_DATA_DIR / 'kaggle_xss.csv'
            
            if not kaggle_path.exists():
                logger.error("kaggle_xss.csv not found in /training_data directory")
                return False
            
            logger.info(f"Training initial model from {kaggle_path}")
            
            # Load dataset - FIXED: Handle index column properly
            df = pd.read_csv(kaggle_path)
            logger.info(f"Loaded CSV with columns: {list(df.columns)}")
            logger.info(f"Total rows in CSV: {len(df)}")
            
            # Handle different CSV formats
            # Format 1: Has unnamed index column + Sentence,Label
            if 'Unnamed: 0' in df.columns or df.columns[0].startswith('Unnamed'):
                # Drop the index column
                df = df.drop(df.columns[0], axis=1)
                logger.info("Dropped index column")
            
            # Rename columns to standard format
            if 'Sentence' in df.columns and 'Label' in df.columns:
                df = df.rename(columns={'Sentence': 'payload', 'Label': 'label'})
            elif 'text' in df.columns and 'target' in df.columns:
                df = df.rename(columns={'text': 'payload', 'target': 'label'})
            elif 'payload' not in df.columns or 'label' not in df.columns:
                logger.error(f"CSV must have 'payload' and 'label' columns. Found: {list(df.columns)}")
                return False
            
            # Clean data
            df = df.dropna()  # Remove any null values
            df['payload'] = df['payload'].astype(str)  # Ensure payload is string
            df['label'] = df['label'].astype(int)  # Ensure label is integer
            
            logger.info(f"After cleaning: {len(df)} samples")
            logger.info(f"Label distribution: {df['label'].value_counts().to_dict()}")
            
            # Extract features
            extractor = FeatureExtractor()
            X = extractor.extract_features_batch(df['payload'].values)
            y = df['label'].values
            
            # Train model
            model, scaler, metrics = self._train_model(X, y)
            
            # Save as initial model
            version = model_manager.save_model(model, scaler, 'initial', metrics)
            
            # Activate it
            model_manager.activate_model(version)
            
            # Reload
            self.load_model()
            
            logger.info("Initial model training completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error training initial model: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def _train_model(self, X, y):
        """Internal method to train XGBoost model"""
        # Split dataset
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info(f"Training set: {len(X_train)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train XGBoost model
        logger.info("Training XGBoost model...")
        model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            objective='binary:logistic',
            random_state=42,
            use_label_encoder=False,
            eval_metric='logloss'
        )
        
        model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = model.predict(X_test_scaled)
        y_pred_proba = model.predict_proba(X_test_scaled)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'samples_train': len(X_train),
            'samples_test': len(X_test)
        }
        
        logger.info("=" * 60)
        logger.info("Model Performance:")
        logger.info(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
        logger.info(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
        logger.info(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
        logger.info(f"F1 Score:  {f1:.4f} ({f1*100:.2f}%)")
        logger.info("=" * 60)
        
        return model, scaler, metrics
    
    def extract_features(self, payload):
        """Extract features from a single payload"""
        extractor = FeatureExtractor()
        return extractor.extract_features(payload)
    
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

class FeatureExtractor:
    """Extract features from payloads for ML model"""
    
    def extract_features(self, payload):
        """Extract features from a single payload"""
        features = {}
        
        # Decode URL encoded strings
        try:
            decoded = urllib.parse.unquote(payload)
        except:
            decoded = payload
        
        # Basic features
        features['length'] = len(payload)
        features['num_special_chars'] = len(re.findall(r'[<>\'\"(){}[\]]', payload))
        features['num_digits'] = len(re.findall(r'\d', payload))
        features['num_spaces'] = payload.count(' ')
        features['num_equals'] = payload.count('=')
        
        # XSS-specific patterns
        features['has_script'] = int(bool(re.search(r'<script', payload, re.I)))
        features['has_javascript'] = int(bool(re.search(r'javascript:', payload, re.I)))
        features['has_onerror'] = int(bool(re.search(r'onerror', payload, re.I)))
        features['has_onload'] = int(bool(re.search(r'onload', payload, re.I)))
        features['has_eval'] = int(bool(re.search(r'\beval\s*\(', payload, re.I)))
        features['has_alert'] = int(bool(re.search(r'\balert\s*\(', payload, re.I)))
        features['has_prompt'] = int(bool(re.search(r'\bprompt\s*\(', payload, re.I)))
        features['has_confirm'] = int(bool(re.search(r'\bconfirm\s*\(', payload, re.I)))
        
        # DOM manipulation
        features['has_document_write'] = int(bool(re.search(r'document\.write', payload, re.I)))
        features['has_document_cookie'] = int(bool(re.search(r'document\.cookie', payload, re.I)))
        features['has_window_location'] = int(bool(re.search(r'window\.location|location\.href', payload, re.I)))
        features['has_innerhtml'] = int(bool(re.search(r'innerHTML', payload, re.I)))
        
        # HTML tags
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
    
    def extract_features_batch(self, payloads):
        """Extract features for multiple payloads"""
        features_list = []
        for payload in payloads:
            features = self.extract_features(payload)
            features_list.append(features)
        return pd.DataFrame(features_list)

# Initialize detector
detector = XSSDetector()

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

def log_to_neo4j(detection_result, request_data):
    """Log detection result to Neo4j"""
    if not neo4j_driver:
        return
    
    try:
        with neo4j_driver.session() as session:
            session.run("""
                CREATE (d:Detection {
                    timestamp: $timestamp,
                    detection_method: 'ML',
                    payload: $payload,
                    is_malicious: $is_malicious,
                    confidence: $confidence,
                    xss_type: $xss_type,
                    impact_level: $impact_level,
                    client_ip: $client_ip,
                    request_path: $request_path,
                    model_version: $model_version
                })
            """, 
                timestamp=detection_result['timestamp'],
                payload=request_data.get('payload', ''),
                is_malicious=detection_result['is_malicious'],
                confidence=detection_result['confidence'],
                xss_type=detection_result.get('xss_type', 'Unknown'),
                impact_level=detection_result.get('impact_level', 'INFO'),
                client_ip=request_data.get('client_ip', 'unknown'),
                request_path=request_data.get('path', '/'),
                model_version=model_manager.metadata.get('active_model', 'unknown')
            )
    except Exception as e:
        logger.error(f"Error logging to Neo4j: {e}")

def fetch_modsecurity_blocked_payloads(limit=1000):
    """Fetch blocked payloads from ModSecurity logs in Neo4j"""
    if not neo4j_driver:
        logger.error("Neo4j driver not available")
        return []
    
    try:
        with neo4j_driver.session() as session:
            result = session.run("""
                MATCH (d:Detection)
                WHERE d.detection_method = 'ModSecurity' 
                  AND d.is_blocked = true
                  AND d.payload IS NOT NULL
                  AND d.payload <> ''
                RETURN DISTINCT d.payload as payload
                ORDER BY d.timestamp DESC
                LIMIT $limit
            """, limit=limit)
            
            payloads = [record['payload'] for record in result]
            logger.info(f"Fetched {len(payloads)} unique blocked payloads from Neo4j")
            return payloads
    except Exception as e:
        logger.error(f"Error fetching payloads from Neo4j: {e}")
        return []

# API Endpoints

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': detector.model is not None,
        'neo4j_connected': neo4j_driver is not None,
        'active_model': model_manager.metadata.get('active_model', 'none')
    })

@app.route('/detect', methods=['POST'])
def detect():
    """XSS detection endpoint"""
    try:
        data = request.get_json()
        payload = data.get('payload', '')
        
        if not payload:
            return jsonify({'error': 'No payload provided'}), 400
        
        # Get prediction
        result, features = detector.predict(payload)
        
        if 'error' in result:
            return jsonify(result), 500
        
        # Determine XSS type and impact
        xss_type = determine_xss_type(payload)
        impact_level = calculate_impact_level(result['confidence'], features)
        
        detection_result = {
            'timestamp': datetime.now().isoformat(),
            'is_malicious': result['is_malicious'],
            'confidence': result['confidence'],
            'xss_type': xss_type,
            'impact_level': impact_level,
            'detection_method': 'ML',
            'model_version': model_manager.metadata.get('active_model', 'unknown')
        }
        
        # Log to Neo4j
        log_to_neo4j(detection_result, data)
        
        return jsonify(detection_result)
        
    except Exception as e:
        logger.error(f"Detection error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/retrain', methods=['POST'])
def retrain_model():
    """
    Manual retraining endpoint - trains model from ModSecurity blocked payloads in Neo4j
    For demonstration purposes during presentation
    """
    try:
        data = request.get_json() or {}
        model_name = data.get('model_name', 'retrained')
        limit = data.get('limit', 1000)  # Number of samples to fetch
        
        logger.info(f"Starting manual retrain with model name: {model_name}")
        
        # Fetch blocked payloads from Neo4j (these are malicious)
        blocked_payloads = fetch_modsecurity_blocked_payloads(limit)
        
        if len(blocked_payloads) < 10:
            return jsonify({
                'error': 'Insufficient training data',
                'message': f'Only {len(blocked_payloads)} blocked payloads found. Need at least 10.',
                'suggestion': 'Generate more test traffic through bWAPP first'
            }), 400
        
        # Create training dataset
        # All blocked payloads are malicious (label=1)
        malicious_data = [{'payload': p, 'label': 1} for p in blocked_payloads]
        
        # Load benign samples from kaggle dataset to balance the training
        # This is important because we need both malicious and benign examples
        kaggle_path = TRAINING_DATA_DIR / 'kaggle_xss.csv'
        benign_data = []
        
        if kaggle_path.exists():
            df = pd.read_csv(kaggle_path)
            
            # Handle index column
            if 'Unnamed: 0' in df.columns or df.columns[0].startswith('Unnamed'):
                df = df.drop(df.columns[0], axis=1)
            
            # Rename columns
            if 'Sentence' in df.columns and 'Label' in df.columns:
                df = df.rename(columns={'Sentence': 'payload', 'Label': 'label'})
            elif 'text' in df.columns and 'target' in df.columns:
                df = df.rename(columns={'text': 'payload', 'target': 'label'})
            
            # Get same number of benign samples as malicious to balance the dataset
            benign_samples_df = df[df['label'] == 0]
            num_benign_needed = len(blocked_payloads)  # Match the number of malicious samples
            
            if len(benign_samples_df) >= num_benign_needed:
                benign_samples = benign_samples_df.sample(n=num_benign_needed, random_state=42)
            else:
                benign_samples = benign_samples_df  # Use all available benign samples
            
            benign_data = benign_samples[['payload', 'label']].to_dict('records')
            logger.info(f"Loaded {len(benign_data)} benign samples from Kaggle dataset")
        
        # Combine datasets
        training_data = malicious_data + benign_data
        df_train = pd.DataFrame(training_data)
        
        logger.info(f"Training dataset: {len(df_train)} samples ({len(malicious_data)} malicious, {len(benign_data)} benign)")
        
        # Extract features
        extractor = FeatureExtractor()
        X = extractor.extract_features_batch(df_train['payload'].values)
        y = df_train['label'].values
        
        # Train new model
        model, scaler, metrics = detector._train_model(X, y)
        
        # Save model
        version = model_manager.save_model(model, scaler, model_name, metrics)
        
        return jsonify({
            'success': True,
            'message': 'Model retrained successfully',
            'model_version': version,
            'metrics': metrics,
            'training_samples': {
                'total': len(df_train),
                'malicious': len(malicious_data),
                'benign': len(benign_data)
            }
        })
        
    except Exception as e:
        logger.error(f"Retrain error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/models', methods=['GET'])
def list_models():
    """List all available models"""
    try:
        models = model_manager.list_models()
        return jsonify({
            'active_model': model_manager.metadata.get('active_model'),
            'models': models
        })
    except Exception as e:
        logger.error(f"Error listing models: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/models/activate', methods=['POST'])
def activate_model():
    """Switch to a different model"""
    try:
        data = request.get_json()
        model_name = data.get('model_name')
        
        if not model_name:
            return jsonify({'error': 'model_name required'}), 400
        
        model_manager.activate_model(model_name)
        
        # Reload detector with new model
        detector.load_model()
        
        return jsonify({
            'success': True,
            'message': f'Activated model: {model_name}',
            'active_model': model_manager.metadata.get('active_model')
        })
        
    except FileNotFoundError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        logger.error(f"Error activating model: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/training-data/stats', methods=['GET'])
def training_data_stats():
    """Get statistics about available training data"""
    try:
        stats = {
            'neo4j_blocked_payloads': 0,
            'neo4j_unique_payloads': 0,
            'kaggle_dataset_size': 0,
            'kaggle_malicious': 0,
            'kaggle_benign': 0
        }
        
        # Count blocked payloads in Neo4j
        if neo4j_driver:
            with neo4j_driver.session() as session:
                # Total blocked
                result = session.run("""
                    MATCH (d:Detection)
                    WHERE d.detection_method = 'ModSecurity' 
                      AND d.is_blocked = true
                    RETURN count(d) as count
                """)
                record = result.single()
                if record:
                    stats['neo4j_blocked_payloads'] = record['count']
                
                # Unique payloads
                result = session.run("""
                    MATCH (d:Detection)
                    WHERE d.detection_method = 'ModSecurity' 
                      AND d.is_blocked = true
                      AND d.payload IS NOT NULL
                    RETURN count(DISTINCT d.payload) as count
                """)
                record = result.single()
                if record:
                    stats['neo4j_unique_payloads'] = record['count']
        
        # Check Kaggle dataset
        kaggle_path = TRAINING_DATA_DIR / 'kaggle_xss.csv'
        if kaggle_path.exists():
            df = pd.read_csv(kaggle_path)
            
            # Handle index column
            if 'Unnamed: 0' in df.columns or df.columns[0].startswith('Unnamed'):
                df = df.drop(df.columns[0], axis=1)
            
            # Rename columns
            if 'Sentence' in df.columns and 'Label' in df.columns:
                df = df.rename(columns={'Sentence': 'payload', 'Label': 'label'})
            elif 'text' in df.columns and 'target' in df.columns:
                df = df.rename(columns={'text': 'payload', 'target': 'label'})
            
            stats['kaggle_dataset_size'] = len(df)
            stats['kaggle_malicious'] = int((df['label'] == 1).sum())
            stats['kaggle_benign'] = int((df['label'] == 0).sum())
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting training data stats: {e}")
        return jsonify({'error': str(e)}), 500

def determine_xss_type(payload):
    """Determine XSS attack type"""
    payload_lower = payload.lower()
    
    dom_patterns = [
        'document.write', 'document.writeln', 'innerhtml', 'outerhtml',
        'document.location', 'window.location', 'document.url', 'document.referrer',
        'window.name', 'location.href', 'location.hash'
    ]
    
    if any(pattern in payload_lower for pattern in dom_patterns):
        return 'DOM-based XSS'
    
    if '<script' in payload_lower or 'javascript:' in payload_lower:
        return 'Stored/Reflected XSS'
    
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)