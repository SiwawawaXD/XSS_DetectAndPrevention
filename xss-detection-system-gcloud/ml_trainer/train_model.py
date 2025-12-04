"""
TRAINING PIPELINE FOR XSS DETECTION (MULTI-MODEL VERSION)
---------------------------------------------------------

Trains:
 - XGBoost
 - CodeBurp (placeholder wrapper)
 - RandomForest (example "another ML model")

Outputs:
 - /models/{model_name}_model.joblib
 - /models/xss_scaler.joblib
"""

import os
import joblib
import logging
import pandas as pd
import numpy as np
from neo4j import GraphDatabase
from urllib.parse import quote

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score
)

from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
from sklearn.svm import LinearSVC


from feature_extractor import FeatureExtractor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("trainer")


# =========================================================
# 1) LOAD FROM NEO4J
# =========================================================
def load_from_neo4j(limit=20000):
    try:
        uri = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "password123")

        driver = GraphDatabase.driver(uri, auth=(user, password))

        q = """
        MATCH (e:AttackEvent)
        RETURN e.input_normalized AS payload,
               CASE WHEN e.attack_type = 'xss' THEN 1 ELSE 0 END AS label
        LIMIT $limit
        """

        with driver.session() as session:
            rows = session.run(q, limit=limit)
            df = pd.DataFrame([dict(r) for r in rows])

        logger.info(f"Loaded {len(df)} rows from Neo4j")
        return df
    except Exception as e:
        logger.error(f"Neo4j load failed: {e}")
        return pd.DataFrame(columns=["payload", "label"])


# =========================================================
# 2) LOAD DATASETS — Kaggle + DeepXSS
# =========================================================
def load_kaggle_csv(path="/datasets/kaggle_xss.csv"):
    if not os.path.exists(path):
        logger.warning(f"Kaggle dataset not found: {path}")
        return pd.DataFrame()
    try:
        df = pd.read_csv(path)
        df = df.rename(columns={"Sentence": "payload", "Label": "label"})
        logger.info(f"Kaggle dataset loaded: {len(df)} entries")
        return df[["payload", "label"]]
    except Exception as e:
        logger.error(f"Kaggle dataset error: {e}")
        return pd.DataFrame()


def load_deepxss_csv(path="/datasets/deepxss.csv"):
    if not os.path.exists(path):
        logger.warning(f"DeepXSS dataset not found: {path}")
        return pd.DataFrame()
    try:
        df = pd.read_csv(path)
        df = df.rename(columns={"text": "payload", "label": "label"})
        logger.info(f"DeepXSS dataset loaded: {len(df)} samples")
        return df[["payload", "label"]]
    except Exception as e:
        logger.error(f"DeepXSS dataset error: {e}")
        return pd.DataFrame()

def load_xssed_csv(path="/datasets/xssed.csv"):
    if not os.path.exists(path):
        logger.warning(f"XSSed dataset not found: {path}")
        return pd.DataFrame()

    try:
        df = pd.read_csv(path, header=None, names=["payload"])
        df["label"] = 1  # all malicious
        logger.info(f"XSSed dataset loaded: {len(df)} samples")
        return df
    except Exception as e:
        logger.error(f"XSSed dataset error: {e}")
        return pd.DataFrame()


# =========================================================
# 3) ENCODING AUGMENTATION
# =========================================================
def apply_encoding_variations(payload):
    """Generate encoded variations of a payload"""
    variations = [payload]
    
    # Single URL encoding
    variations.append(quote(payload))
    
    # Double URL encoding
    variations.append(quote(quote(payload)))
    
    # Triple URL encoding
    variations.append(quote(quote(quote(payload))))
    
    # HTML entity encoding (numeric)
    html_encoded = ''.join([f'&#{ord(c)};' for c in payload])
    variations.append(html_encoded)
    
    # HTML entity encoding (hex)
    html_hex = ''.join([f'&#x{ord(c):x};' for c in payload])
    variations.append(html_hex)
    
    # Mixed case (for script tags, etc.)
    if '<script' in payload.lower():
        variations.append(payload.replace('<script', '<ScRiPt').replace('</script', '</ScRiPt'))
    
    return variations


def augment_dataset_with_encoding(df):
    """
    Take existing malicious payloads and create encoded variations
    This helps the model learn to detect obfuscated attacks
    """
    augmented_rows = []
    
    for idx, row in df[df['label'] == 1].iterrows():
        payload = row['payload']
        variations = apply_encoding_variations(payload)
        
        for variant in variations:
            augmented_rows.append({
                'payload': variant,
                'label': 1
            })
    
    df_augmented = pd.DataFrame(augmented_rows)
    logger.info(f"Generated {len(df_augmented)} encoded variations")
    
    return pd.concat([df, df_augmented], ignore_index=True)


# =========================================================
# 4) SYNTHETIC GENERATOR (Enhanced)
# =========================================================
class XSSDatasetGenerator:
    def __init__(self):
        self.malicious = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            '<svg onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',
            'eval(String.fromCharCode(97,108,101,114,116,40,49,41))',
        ]
        self.benign = [
            'hello world',
            'https://example.com',
            'test123',
            'name=John',
            'search term',
            'user@example.com',
            'path/to/file.txt',
            '{"key": "value"}',
        ]

    def generate(self):
        rows = []
        
        # Add base payloads
        rows.extend([{"payload": p, "label": 1} for p in self.malicious])
        rows.extend([{"payload": p, "label": 0} for p in self.benign])
        
        # Add encoded variations of malicious payloads
        for payload in self.malicious:
            for variant in apply_encoding_variations(payload):
                rows.append({"payload": variant, "label": 1})
        
        return pd.DataFrame(rows)


# =========================================================
# 5) PLACEHOLDER CODEBURP MODEL (replace with real implementation)
# =========================================================
class CodeBurpClassifier:
    """
    Dummy placeholder. Replace with real CodeBurp model inference.
    Must implement .fit(X, y) and .predict(X)
    """
    def fit(self, X, y):
        # Fake "training"
        self.mean_vector = np.mean(X[y == 1], axis=0)
        return self

    def predict(self, X):
        sims = np.dot(X, self.mean_vector)
        return (sims > np.percentile(sims, 50)).astype(int)


# =========================================================
# 6) MAIN TRAINING PIPELINE
# =========================================================
def train_all_models():

    logger.info("======== TRAINING XSS MODELS =========")

    # Load datasets
    df_synth = XSSDatasetGenerator().generate()
    df_kaggle = load_kaggle_csv()
    df_xssed = load_xssed_csv()
    df_deep = load_deepxss_csv()
    df_neo4j = load_from_neo4j()
    
    # Merge datasets
    df_all = pd.concat(
        [df_synth, df_kaggle, df_deep, df_neo4j, df_xssed],
        ignore_index=True
    ).dropna()

    # Apply encoding augmentation to increase robustness
    logger.info("Applying encoding augmentation...")
    df_all = augment_dataset_with_encoding(df_all)
    
    df_all = df_all.drop_duplicates(subset=["payload"])
    logger.info(f"Total combined dataset size: {len(df_all)}")

    if len(df_all) < 50:
        raise RuntimeError("Not enough training data available!")

    # Feature extraction
    extractor = FeatureExtractor()
    X = extractor.extract_batch(df_all["payload"].values)
    y = df_all["label"].astype(int).values

    # Train/val split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # Shared scaler
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    os.makedirs("/models", exist_ok=True)
    joblib.dump(scaler, "/models/xss_scaler.joblib")
    logger.info("Scaler saved → /models/xss_scaler.joblib")

    # =========================================================
    # MODELS TO TRAIN
    # =========================================================
    models = {
        "xgboost": xgb.XGBClassifier(
            n_estimators=500,
            learning_rate=0.03,

            max_depth=12,
            min_child_weight=1,

            subsample=0.9,
            colsample_bytree=0.9,

            gamma=0.0,

            reg_alpha=0.0,
            reg_lambda=1.0,

            tree_method="hist",
            eval_metric="logloss",
            use_label_encoder=False,
            n_jobs=-1
        ),

        "codeburp": CodeBurpClassifier(),

        "svm": LinearSVC(
            C=1.0,
            dual=False,
            max_iter=5000,
        )

    }

    # =========================================================
    # TRAIN + EVALUATE EACH MODEL
    # =========================================================
    for name, model in models.items():
        logger.info(f"\n===== Training {name} =====")
        model.fit(X_train_s, y_train)

        pred = model.predict(X_test_s)

        # AUC only if model has predict_proba
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X_test_s)[:, 1]
            auc = roc_auc_score(y_test, proba)
        else:
            auc = float("nan")

        logger.info(f"{name} Accuracy:   {accuracy_score(y_test, pred):.4f}")
        logger.info(f"{name} Precision:  {precision_score(y_test, pred):.4f}")
        logger.info(f"{name} Recall:     {recall_score(y_test, pred):.4f}")
        logger.info(f"{name} F1 Score:   {f1_score(y_test, pred):.4f}")
        logger.info(f"{name} AUC:        {auc:.4f}")
        logger.info(f"{name} Confusion:\n{confusion_matrix(y_test, pred)}")

        joblib.dump(model, f"/models/{name}_model.joblib")
        logger.info(f"{name} model saved → /models/{name}_model.joblib")

    return models, scaler


if __name__ == "__main__":
    train_all_models()