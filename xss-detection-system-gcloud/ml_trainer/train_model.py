"""
ENHANCED TRAINING SCRIPT - LEARNS FROM NEO4J LOGS
==================================================

Features:
- Loads ModSecurity decisions from Neo4j
- Combines with Kaggle + DeepXSS datasets
- Saves versioned models (xgb_model_v2.joblib, v3, v4, etc.)
- Generates training report for academic presentation

Usage:
  python train_from_neo4j.py --from-neo4j --version 2
"""

import os
import joblib
import logging
import pandas as pd
import numpy as np
from neo4j import GraphDatabase
from datetime import datetime
import json

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score, classification_report
)

import xgboost as xgb
from feature_extractor import FeatureExtractor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("neo4j-trainer")


# =========================================================
# LOAD FROM NEO4J (MODSECURITY DECISIONS)
# =========================================================
def load_from_neo4j(limit=20000):
    """
    Load ModSecurity decisions from Neo4j
    These logs contain real traffic + expert (ModSecurity) labels
    
    Schema matches your actual Neo4j structure:
    - AttackEvent nodes with normalized_payload field
    - Labels: ["AttackEvent", "BlockedRequest"] for malicious
    - Labels: ["NormalRequest"] for benign
    - attack_type field: "xss" or "none"
    """
    try:
        uri = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "SecureGCPPassword123!")

        driver = GraphDatabase.driver(uri, auth=(user, password))

        # Query that matches your actual schema
        query = """
        MATCH (e)
        WHERE "AttackEvent" IN labels(e) OR "NormalRequest" IN labels(e)
        RETURN 
            COALESCE(e.normalized_payload, e.payload) AS payload,
            e.attack_type AS attack_type,
            labels(e) AS event_labels,
            e.timestamp AS timestamp
        ORDER BY e.timestamp DESC
        LIMIT $limit
        """

        with driver.session() as session:
            result = session.run(query, limit=limit)
            rows = []
            
            for record in result:
                payload = record["payload"]
                attack_type = record["attack_type"]
                event_labels = record["event_labels"]
                
                # Determine label based on attack_type and labels
                # BlockedRequest or attack_type='xss' → malicious (1)
                # NormalRequest or attack_type='none' → benign (0)
                if "BlockedRequest" in event_labels or attack_type == "xss":
                    label = 1
                elif "NormalRequest" in event_labels or attack_type == "none":
                    label = 0
                else:
                    # Default to benign for ambiguous cases
                    label = 0
                
                rows.append({
                    "payload": payload,
                    "label": label
                })
            
            df = pd.DataFrame(rows)

        driver.close()

        if df.empty:
            logger.warning("⚠ No logs found in Neo4j. System needs traffic first!")
            logger.info("💡 Generate traffic first:")
            logger.info('   curl "http://localhost:8000/bwapp/xss_get.php?firstname=<script>alert(1)</script>"')
            return pd.DataFrame(columns=["payload", "label"])

        # Remove any null payloads
        df = df.dropna(subset=["payload"])
        
        logger.info(f"✓ Loaded {len(df)} samples from Neo4j")
        logger.info(f"  - Malicious: {df['label'].sum()}")
        logger.info(f"  - Benign: {(df['label'] == 0).sum()}")

        return df[["payload", "label"]]

    except Exception as e:
        logger.error(f"✗ Neo4j connection failed: {e}")
        logger.error(f"   Make sure Neo4j is running and credentials are correct")
        return pd.DataFrame(columns=["payload", "label"])


# =========================================================
# LOAD EXISTING DATASETS
# =========================================================
def load_kaggle_csv(path="/datasets/kaggle_xss.csv"):
    """Load Kaggle XSS dataset"""
    if not os.path.exists(path):
        logger.warning(f"Kaggle dataset not found: {path}")
        return pd.DataFrame()
    
    try:
        df = pd.read_csv(path)
        df = df.rename(columns={"Sentence": "payload", "Label": "label"})
        logger.info(f"✓ Loaded Kaggle dataset: {len(df)} samples")
        return df[["payload", "label"]]
    except Exception as e:
        logger.error(f"Kaggle load error: {e}")
        return pd.DataFrame()


def load_deepxss_csv(path="/datasets/deepxss.csv"):
    """Load DeepXSS dataset"""
    if not os.path.exists(path):
        logger.warning(f"DeepXSS dataset not found: {path}")
        return pd.DataFrame()
    
    try:
        df = pd.read_csv(path)
        df = df.rename(columns={"text": "payload", "label": "label"})
        logger.info(f"✓ Loaded DeepXSS dataset: {len(df)} samples")
        return df[["payload", "label"]]
    except Exception as e:
        logger.error(f"DeepXSS load error: {e}")
        return pd.DataFrame()


# =========================================================
# TRAINING FUNCTION
# =========================================================
def train_model_with_neo4j(version="v2", from_neo4j=True):
    """
    Train XGBoost model with optional Neo4j data
    
    Args:
        version: Model version string (v2, v3, v4, etc.)
        from_neo4j: Whether to include Neo4j logs
    """
    logger.info("="*60)
    logger.info("STARTING TRAINING - Learning from ModSecurity")
    logger.info("="*60)
    
    datasets = []
    dataset_info = {}
    
    # 1. Load synthetic datasets (always include for baseline)
    kaggle_df = load_kaggle_csv()
    if not kaggle_df.empty:
        datasets.append(kaggle_df)
        dataset_info["kaggle"] = len(kaggle_df)
    
    deepxss_df = load_deepxss_csv()
    if not deepxss_df.empty:
        datasets.append(deepxss_df)
        dataset_info["deepxss"] = len(deepxss_df)
    
    # 2. Load Neo4j logs (ModSecurity expert labels)
    if from_neo4j:
        neo4j_df = load_from_neo4j()
        if not neo4j_df.empty:
            datasets.append(neo4j_df)
            dataset_info["neo4j"] = len(neo4j_df)
        else:
            logger.warning("⚠ No Neo4j data available. Train with synthetic data only.")
    
    if not datasets:
        raise SystemExit("❌ No training data available!")
    
    # 3. Combine all datasets
    df_all = pd.concat(datasets, ignore_index=True)
    df_all = df_all.drop_duplicates(subset=["payload"])
    
    logger.info(f"\n📊 TRAINING DATASET COMPOSITION:")
    for source, count in dataset_info.items():
        logger.info(f"  - {source}: {count:,} samples")
    logger.info(f"  - TOTAL (after dedup): {len(df_all):,} samples")
    logger.info(f"  - Malicious: {df_all['label'].sum():,}")
    logger.info(f"  - Benign: {(df_all['label'] == 0).sum():,}")
    
    if len(df_all) < 100:
        raise SystemExit("❌ Not enough training data (minimum 100 samples)")
    
    # 4. Feature extraction
    logger.info("\n🔍 Extracting features...")
    extractor = FeatureExtractor()
    X = extractor.extract_batch(df_all["payload"].values)
    y = df_all["label"].astype(int).values
    
    # 5. Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    # 6. Scale features
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)
    
    # 7. Train XGBoost
    logger.info("\n🎯 Training XGBoost...")
    model = xgb.XGBClassifier(
        n_estimators=250,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        use_label_encoder=False
    )
    model.fit(X_train_s, y_train)
    
    # 8. Evaluate
    pred = model.predict(X_test_s)
    proba = model.predict_proba(X_test_s)[:, 1]
    
    metrics = {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred),
        "recall": recall_score(y_test, pred),
        "f1_score": f1_score(y_test, pred),
        "auc": roc_auc_score(y_test, proba)
    }
    
    logger.info("\n📈 MODEL PERFORMANCE:")
    for metric, value in metrics.items():
        logger.info(f"  {metric.upper()}: {value:.4f}")
    
    logger.info("\n📊 Confusion Matrix:")
    cm = confusion_matrix(y_test, pred)
    logger.info(f"  TN: {cm[0][0]}, FP: {cm[0][1]}")
    logger.info(f"  FN: {cm[1][0]}, TP: {cm[1][1]}")
    
    # 9. Save models with version
    os.makedirs("/models", exist_ok=True)
    
    model_path = f"/models/xgb_model_{version}.joblib"
    scaler_path = f"/models/xss_scaler.joblib"  # Scaler stays the same
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    logger.info(f"\n✅ MODEL SAVED:")
    logger.info(f"  Model: {model_path}")
    logger.info(f"  Scaler: {scaler_path}")
    
    # 10. Generate training report
    report = {
        "version": version,
        "trained_at": datetime.now().isoformat(),
        "datasets": dataset_info,
        "total_samples": len(df_all),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "metrics": metrics,
        "confusion_matrix": cm.tolist(),
        "model_path": model_path
    }
    
    report_path = f"/models/training_report_{version}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"  Report: {report_path}")
    logger.info("\n" + "="*60)
    logger.info("✅ TRAINING COMPLETE!")
    logger.info("="*60)
    
    return model, scaler, report


# =========================================================
# MAIN
# =========================================================
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Train XGBoost from Neo4j logs")
    parser.add_argument("--version", default="v2", help="Model version (v2, v3, v4, etc.)")
    parser.add_argument("--from-neo4j", action="store_true", help="Include Neo4j logs")
    parser.add_argument("--neo4j-only", action="store_true", help="Use ONLY Neo4j logs (no synthetic)")
    
    args = parser.parse_args()
    
    train_model_with_neo4j(
        version=args.version,
        from_neo4j=args.from_neo4j or args.neo4j_only
    )