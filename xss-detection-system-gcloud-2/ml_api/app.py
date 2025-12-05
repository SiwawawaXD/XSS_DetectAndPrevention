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
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import urllib.parse
import torch
from transformers import AutoTokenizer, AutoModel

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
MODEL_ARCHIVE_DIR = MODELS_DIR / 'archive'
TRAINING_DATA_DIR = Path('/training_data')

# Create directories
MODELS_DIR.mkdir(exist_ok=True)
MODEL_ARCHIVE_DIR.mkdir(exist_ok=True)
TRAINING_DATA_DIR.mkdir(exist_ok=True)

# Model version tracking
MODEL_METADATA_PATH = MODELS_DIR / 'model_metadata.json'

# Model type constants
MODEL_TYPES = {
    'xgboost': 'XGBoost',
    'svm': 'SVM',
    'randomforest': 'RandomForest',
    'codebert': 'CodeBERT'
}


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
            'active_model': None,
            'active_model_type': None,
            'models': {},
            'model_history': []
        }
    
    def save_metadata(self):
        """Save model metadata"""
        with open(MODEL_METADATA_PATH, 'w') as f:
            json.dump(self.metadata, f, indent=2)
    
    def list_models(self):
        """List all available models grouped by type"""
        models_by_type = {model_type: [] for model_type in MODEL_TYPES.keys()}
        
        for model_name, model_info in self.metadata.get('models', {}).items():
            model_type = model_info.get('model_type', 'unknown')
            if model_type in models_by_type:
                models_by_type[model_type].append({
                    'name': model_name,
                    'created_at': model_info.get('created_at'),
                    'metrics': model_info.get('metrics', {}),
                    'is_active': model_name == self.metadata.get('active_model')
                })
        
        return models_by_type
    
    def save_model(self, model, scaler, model_name, model_type, metrics=None, tokenizer=None):
        """Save a trained model with version control"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        version_name = f"{model_type}_{model_name}_{timestamp}"
        
        # Save to archive
        archive_model_path = MODEL_ARCHIVE_DIR / f'model_{version_name}.pkl'
        archive_scaler_path = MODEL_ARCHIVE_DIR / f'scaler_{version_name}.pkl'
        
        joblib.dump(model, archive_model_path)
        joblib.dump(scaler, archive_scaler_path)
        
        # Save tokenizer for CodeBERT
        if tokenizer is not None and model_type == 'codebert':
            tokenizer_path = MODEL_ARCHIVE_DIR / f'tokenizer_{version_name}.pkl'
            joblib.dump(tokenizer, tokenizer_path)
        
        # Update metadata
        self.metadata['models'][version_name] = {
            'created_at': timestamp,
            'name': model_name,
            'model_type': model_type,
            'metrics': metrics or {},
            'version': version_name,
            'has_tokenizer': tokenizer is not None
        }
        
        self.metadata['model_history'].append({
            'version': version_name,
            'timestamp': timestamp,
            'action': 'trained',
            'model_type': model_type
        })
        
        self.save_metadata()
        logger.info(f"Model saved: {version_name} (Type: {model_type})")
        
        return version_name
    
    def get_model_path(self, model_name):
        """Get paths for a specific model"""
        model_path = MODEL_ARCHIVE_DIR / f'model_{model_name}.pkl'
        scaler_path = MODEL_ARCHIVE_DIR / f'scaler_{model_name}.pkl'
        tokenizer_path = MODEL_ARCHIVE_DIR / f'tokenizer_{model_name}.pkl'
        
        return model_path, scaler_path, tokenizer_path
    
    def activate_model(self, model_name):
        """Switch to a different model"""
        model_path, scaler_path, tokenizer_path = self.get_model_path(model_name)
        
        if not model_path.exists() or not scaler_path.exists():
            raise FileNotFoundError(f"Model {model_name} not found")
        
        model_info = self.metadata['models'].get(model_name, {})
        
        # Update metadata
        self.metadata['active_model'] = model_name
        self.metadata['active_model_type'] = model_info.get('model_type')
        self.metadata['model_history'].append({
            'version': model_name,
            'timestamp': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'action': 'activated',
            'model_type': model_info.get('model_type')
        })
        self.save_metadata()
        
        logger.info(f"Activated model: {model_name} (Type: {model_info.get('model_type')})")
        return True


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
        features['has_img'] = int(bool(re.search(r'<img', payload, re.I)))
        features['has_iframe'] = int(bool(re.search(r'<iframe', payload, re.I)))
        features['has_svg'] = int(bool(re.search(r'<svg', payload, re.I)))
        
        # Obfuscation indicators
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


class CodeBERTExtractor:
    """Extract features using CodeBERT embeddings"""
    
    def __init__(self):
        self.tokenizer = None
        self.model = None
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        logger.info(f"CodeBERT using device: {self.device}")
    
    def load_model(self):
        """Load CodeBERT model and tokenizer"""
        if self.tokenizer is None or self.model is None:
            logger.info("Loading CodeBERT model...")
            self.tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
            self.model = AutoModel.from_pretrained("microsoft/codebert-base")
            self.model.to(self.device)
            self.model.eval()
            logger.info("CodeBERT model loaded successfully")
    
    def extract_embedding(self, payload):
        """Extract CodeBERT embedding for a single payload"""
        self.load_model()
        
        # Tokenize
        inputs = self.tokenizer(
            payload, 
            return_tensors="pt", 
            padding=True, 
            truncation=True, 
            max_length=512
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        # Get embeddings
        with torch.no_grad():
            outputs = self.model(**inputs)
            # Use [CLS] token embedding
            embedding = outputs.last_hidden_state[:, 0, :].cpu().numpy()
        
        return embedding.flatten()
    
    def extract_embeddings_batch(self, payloads):
        """Extract CodeBERT embeddings for multiple payloads"""
        embeddings = []
        for payload in payloads:
            embedding = self.extract_embedding(payload)
            embeddings.append(embedding)
        return np.array(embeddings)


class MultiModelDetector:
    """Multi-model XSS detector supporting XGBoost, SVM, RandomForest, and CodeBERT"""
    
    def __init__(self):
        self.models = {}  # Store all loaded models
        self.scalers = {}
        self.active_model_name = None
        self.active_model_type = None
        self.codebert_extractor = CodeBERTExtractor()
        self.load_active_model()
    
    def load_active_model(self):
        """Load the currently active model"""
        try:
            active_model = model_manager.metadata.get('active_model')
            active_type = model_manager.metadata.get('active_model_type')
            
            if active_model and active_type:
                self.load_model(active_model, active_type)
                logger.info(f"Active {active_type} model loaded: {active_model}")
            else:
                logger.warning("No active model found - will train initial models")
                self.train_all_initial_models()
        except Exception as e:
            logger.error(f"Error loading active model: {e}")
    
    def load_model(self, model_name, model_type):
        """Load a specific model"""
        model_path, scaler_path, tokenizer_path = model_manager.get_model_path(model_name)
        
        if not model_path.exists() or not scaler_path.exists():
            raise FileNotFoundError(f"Model files not found for {model_name}")
        
        self.models[model_name] = joblib.load(model_path)
        self.scalers[model_name] = joblib.load(scaler_path)
        self.active_model_name = model_name
        self.active_model_type = model_type
        
        logger.info(f"Loaded {model_type} model: {model_name}")
    
    def train_all_initial_models(self):
        """Train initial versions of all model types from kaggle_xss.csv"""
        kaggle_path = TRAINING_DATA_DIR / 'kaggle_xss.csv'
        
        if not kaggle_path.exists():
            logger.error("kaggle_xss.csv not found in /training_data directory")
            return False
        
        logger.info("=" * 70)
        logger.info("TRAINING ALL INITIAL MODELS FROM KAGGLE DATASET")
        logger.info("=" * 70)
        
        try:
            # Load dataset
            df = pd.read_csv(kaggle_path)
            logger.info(f"Loaded CSV with columns: {list(df.columns)}")
            
            # Handle different CSV formats
            if 'Unnamed: 0' in df.columns or df.columns[0].startswith('Unnamed'):
                df = df.drop(df.columns[0], axis=1)
            
            # Rename columns to standard format
            if 'Sentence' in df.columns and 'Label' in df.columns:
                df = df.rename(columns={'Sentence': 'payload', 'Label': 'label'})
            elif 'text' in df.columns and 'target' in df.columns:
                df = df.rename(columns={'text': 'payload', 'target': 'label'})
            
            # Clean data
            df = df.dropna()
            df['payload'] = df['payload'].astype(str)
            df['label'] = df['label'].astype(int)
            
            logger.info(f"Dataset loaded: {len(df)} samples")
            logger.info(f"Label distribution: {df['label'].value_counts().to_dict()}")
            
            # Train each model type
            results = {}
            
            # 1. XGBoost
            logger.info("\n" + "=" * 70)
            logger.info("TRAINING XGBOOST MODEL")
            logger.info("=" * 70)
            version_xgb = self.train_model(df, 'xgboost', 'initial')
            results['xgboost'] = version_xgb
            
            # 2. SVM
            logger.info("\n" + "=" * 70)
            logger.info("TRAINING SVM MODEL")
            logger.info("=" * 70)
            version_svm = self.train_model(df, 'svm', 'initial')
            results['svm'] = version_svm
            
            # 3. RandomForest
            logger.info("\n" + "=" * 70)
            logger.info("TRAINING RANDOM FOREST MODEL")
            logger.info("=" * 70)
            version_rf = self.train_model(df, 'randomforest', 'initial')
            results['randomforest'] = version_rf
            
            # 4. CodeBERT
            logger.info("\n" + "=" * 70)
            logger.info("TRAINING CODEBERT MODEL")
            logger.info("=" * 70)
            version_cb = self.train_model(df, 'codebert', 'initial')
            results['codebert'] = version_cb
            
            # Activate XGBoost as default
            if results['xgboost']:
                model_manager.activate_model(results['xgboost'])
                self.load_model(results['xgboost'], 'xgboost')
            
            logger.info("\n" + "=" * 70)
            logger.info("ALL INITIAL MODELS TRAINED SUCCESSFULLY")
            logger.info("=" * 70)
            logger.info("Trained models:")
            for model_type, version in results.items():
                logger.info(f"  - {model_type}: {version}")
            logger.info(f"Active model: {results['xgboost']} (XGBoost)")
            logger.info("=" * 70)
            
            return True
            
        except Exception as e:
            logger.error(f"Error training initial models: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def train_model(self, df, model_type, model_name):
        """Train a specific model type"""
        try:
            # Extract features based on model type
            if model_type == 'codebert':
                logger.info("Extracting CodeBERT embeddings...")
                X = self.codebert_extractor.extract_embeddings_batch(df['payload'].values)
            else:
                logger.info("Extracting traditional features...")
                extractor = FeatureExtractor()
                X = extractor.extract_features_batch(df['payload'].values)
                X = X.values
            
            y = df['label'].values
            
            logger.info(f"Feature extraction complete: {X.shape}")
            
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
            
            # Train model based on type
            logger.info(f"Training {model_type.upper()} model...")
            
            if model_type == 'xgboost':
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
            
            elif model_type == 'svm':
                model = SVC(
                    kernel='rbf',
                    C=1.0,
                    gamma='scale',
                    probability=True,
                    random_state=42
                )
            
            elif model_type == 'randomforest':
                model = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=20,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    random_state=42,
                    n_jobs=-1
                )
            
            elif model_type == 'codebert':
                # Use a simple classifier on top of CodeBERT embeddings
                model = RandomForestClassifier(
                    n_estimators=50,
                    max_depth=10,
                    random_state=42,
                    n_jobs=-1
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
            logger.info(f"{model_type.upper()} Model Performance:")
            logger.info(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
            logger.info(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
            logger.info(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
            logger.info(f"F1 Score:  {f1:.4f} ({f1*100:.2f}%)")
            logger.info("=" * 60)
            
            # Confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            logger.info(f"Confusion Matrix: TN={cm[0][0]}, FP={cm[0][1]}, FN={cm[1][0]}, TP={cm[1][1]}")
            
            # Save model
            tokenizer = self.codebert_extractor.tokenizer if model_type == 'codebert' else None
            version = model_manager.save_model(model, scaler, model_name, model_type, metrics, tokenizer)
            
            logger.info(f"{model_type.upper()} model saved: {version}")
            
            return version
            
        except Exception as e:
            logger.error(f"Error training {model_type} model: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None
    
    def predict(self, payload):
        """Predict if payload is XSS attack using active model"""
        if not self.active_model_name or self.active_model_name not in self.models:
            return {'error': 'No active model loaded'}, None
        
        try:
            # Extract features based on model type
            if self.active_model_type == 'codebert':
                feature_vector = self.codebert_extractor.extract_embedding(payload).reshape(1, -1)
                features = {'type': 'codebert_embedding', 'dimensions': feature_vector.shape[1]}
            else:
                extractor = FeatureExtractor()
                features = extractor.extract_features(payload)
                feature_vector = np.array(list(features.values())).reshape(1, -1)
            
            # Scale and predict
            model = self.models[self.active_model_name]
            scaler = self.scalers[self.active_model_name]
            
            feature_vector_scaled = scaler.transform(feature_vector)
            
            prediction = model.predict(feature_vector_scaled)[0]
            probability = model.predict_proba(feature_vector_scaled)[0]
            
            return {
                'is_malicious': bool(prediction),
                'confidence': float(max(probability)),
                'malicious_probability': float(probability[1]) if len(probability) > 1 else 0,
                'model_type': self.active_model_type,
                'model_name': self.active_model_name,
                'features': features
            }, features
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {'error': str(e)}, None


# Initialize managers and detector
model_manager = ModelManager()
detector = MultiModelDetector()

# Neo4j connection
try:
    neo4j_uri = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
    neo4j_user = os.getenv('NEO4J_USER', 'neo4j')
    neo4j_password = os.getenv('NEO4J_PASSWORD', 'SecureGCPPassword123!')
    neo4j_driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    logger.info("ML API connected to Neo4j")
except Exception as e:
    logger.error(f"Neo4j connection error: {e}")
    neo4j_driver = None


# API Endpoints

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'active_model': detector.active_model_name,
        'active_model_type': detector.active_model_type,
        'neo4j_connected': neo4j_driver is not None,
        'available_model_types': list(MODEL_TYPES.keys())
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
        
        # Log to Neo4j
        try:
            if neo4j_driver:
                with neo4j_driver.session() as session:
                    session.run("""
                        CREATE (d:Detection {
                            timestamp: datetime(),
                            payload: $payload,
                            is_malicious: $is_malicious,
                            confidence: $confidence,
                            model_type: $model_type,
                            model_name: $model_name,
                            detection_method: 'ML'
                        })
                    """, 
                    payload=payload,
                    is_malicious=result['is_malicious'],
                    confidence=result['confidence'],
                    model_type=detector.active_model_type,
                    model_name=detector.active_model_name
                    )
        except Exception as e:
            logger.error(f"Error logging to Neo4j: {e}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Detection error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/models', methods=['GET'])
def list_models():
    """List all available models grouped by type"""
    try:
        models_by_type = model_manager.list_models()
        return jsonify({
            'active_model': model_manager.metadata.get('active_model'),
            'active_model_type': model_manager.metadata.get('active_model_type'),
            'models_by_type': models_by_type,
            'model_types': MODEL_TYPES
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
        
        # Get model type from metadata
        model_info = model_manager.metadata['models'].get(model_name)
        if not model_info:
            return jsonify({'error': f'Model {model_name} not found'}), 404
        
        model_type = model_info['model_type']
        
        # Activate model
        model_manager.activate_model(model_name)
        
        # Reload detector with new model
        detector.load_model(model_name, model_type)
        
        return jsonify({
            'success': True,
            'message': f'Activated model: {model_name}',
            'active_model': model_name,
            'active_model_type': model_type
        })
        
    except Exception as e:
        logger.error(f"Error activating model: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/models/train', methods=['POST'])
def train_new_model():
    """Train a new model of specified type"""
    try:
        data = request.get_json()
        model_type = data.get('model_type', 'xgboost')
        model_name = data.get('model_name', 'retrained')
        
        if model_type not in MODEL_TYPES:
            return jsonify({
                'error': f'Invalid model_type. Must be one of: {list(MODEL_TYPES.keys())}'
            }), 400
        
        # Load kaggle dataset
        kaggle_path = TRAINING_DATA_DIR / 'kaggle_xss.csv'
        if not kaggle_path.exists():
            return jsonify({'error': 'kaggle_xss.csv not found'}), 404
        
        df = pd.read_csv(kaggle_path)
        
        # Handle CSV format
        if 'Unnamed: 0' in df.columns:
            df = df.drop(df.columns[0], axis=1)
        if 'Sentence' in df.columns:
            df = df.rename(columns={'Sentence': 'payload', 'Label': 'label'})
        
        df = df.dropna()
        df['payload'] = df['payload'].astype(str)
        df['label'] = df['label'].astype(int)
        
        # Train model
        version = detector.train_model(df, model_type, model_name)
        
        if version:
            return jsonify({
                'success': True,
                'message': f'{MODEL_TYPES[model_type]} model trained successfully',
                'model_version': version,
                'model_type': model_type
            })
        else:
            return jsonify({'error': 'Training failed'}), 500
            
    except Exception as e:
        logger.error(f"Training error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/training-data/stats', methods=['GET'])
def training_data_stats():
    """Get statistics about training data"""
    try:
        kaggle_path = TRAINING_DATA_DIR / 'kaggle_xss.csv'
        
        if not kaggle_path.exists():
            return jsonify({'error': 'No training data found'}), 404
        
        df = pd.read_csv(kaggle_path)
        
        # Handle format
        if 'Unnamed: 0' in df.columns:
            df = df.drop(df.columns[0], axis=1)
        if 'Sentence' in df.columns:
            df = df.rename(columns={'Sentence': 'payload', 'Label': 'label'})
        
        df = df.dropna()
        
        stats = {
            'total_samples': len(df),
            'label_distribution': df['label'].value_counts().to_dict() if 'label' in df.columns else {},
            'file_path': str(kaggle_path),
            'columns': list(df.columns)
        }
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
