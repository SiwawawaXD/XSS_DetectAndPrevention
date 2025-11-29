# train_from_sources.py
import argparse
import pandas as pd
import joblib
import os
import uuid
from neo4j import GraphDatabase
import logging
from feature_extractor import FeatureExtractor
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import xgboost as xgb

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("trainer")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASSWORD", "password")


# ---------------------------------------------------
# LOAD DATA FROM NEO4J (Matches your new schema)
# ---------------------------------------------------
def load_from_neo4j(limit=20000):
    """
    Loads logs from Neo4j that follow the final schema:

    (:AttackEvent { 
        event_id, timestamp, attack_type,
        payload, normalized_payload, decoded_versions,
        confidence, endpoint, method
    })
    LABELS: ["AttackEvent", "BlockedRequest"], ["NormalRequest"], etc.
    """

    logger.info("Querying Neo4j with final schema...")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    query = """
    MATCH (e)
    WHERE "AttackEvent" IN labels(e)
    RETURN 
        e.payload AS raw_payload,
        e.normalized_payload AS normalized_payload,
        e.attack_type AS attack_type,
        e.confidence AS confidence,
        labels(e) AS labels
    LIMIT $limit
    """

    rows_out = []

    with driver.session() as session:
        result = session.run(query, limit=limit)

        for r in result:
            raw = r["raw_payload"] or ""
            norm = r["normalized_payload"] or raw
            labels = r["labels"] or []
            attack_type = r["attack_type"]

            # --------------------------
            # LABELING LOGIC FOR TRAINING
            # --------------------------

            if "BlockedRequest" in labels or attack_type == "xss":
                label = 1

            elif "NormalRequest" in labels:
                label = 0

            else:
                # SuspiciousRequest or unlabeled → treat as benign
                label = 0

            rows_out.append({
                "payload": norm,
                "label": label
            })

    df = pd.DataFrame(rows_out)
    logger.info(f"Loaded {len(df)} logs from Neo4j for ML training")
    return df


# ---------------------------------------------------
# TRAINING FUNCTION
# ---------------------------------------------------
def train_model(datasets):
    """
    datasets = [df_kaggle, df_deepxss, df_neo4j]
    """

    df_all = pd.concat(datasets, ignore_index=True).dropna()
    df_all = df_all.drop_duplicates(subset=["payload"])

    logger.info(f"Total combined rows for training: {len(df_all)}")

    if len(df_all) < 50:
        raise RuntimeError("Not enough training samples. Need at least 50.")

    # Feature extraction
    extractor = FeatureExtractor()
    features_df = extractor.extract_batch(df_all["payload"].tolist())
    labels = df_all["label"].astype(int).tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        features_df, labels, test_size=0.2, random_state=42, stratify=labels
    )

    logger.info("Training XGBoost...")

    model = xgb.XGBClassifier(
        n_estimators=250,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        use_label_encoder=False
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]

    logger.info("\n" + classification_report(y_test, preds))

    try:
        logger.info(f"AUC: {roc_auc_score(y_test, proba):.4f}")
    except:
        pass

    os.makedirs("/models", exist_ok=True)
    joblib.dump(model, "/models/xgb_model.joblib")

    logger.info("Model saved → /models/xgb_model.joblib")

    return model


# ---------------------------------------------------
# MAIN
# ---------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--kaggle", default="/datasets/kaggle_xss.csv")
    parser.add_argument("--deepxss", default="/datasets/deepxss.csv")
    parser.add_argument("--from-neo4j", action="store_true")
    args = parser.parse_args()

    datasets = []

    # Load Kaggle
    if os.path.exists(args.kaggle):
        logger.info("Loading Kaggle dataset...")
        df = pd.read_csv(args.kaggle)
        df = df.rename(columns={"Sentence": "payload", "Label": "label"})
        datasets.append(df)

    # Load DeepXSS
    if os.path.exists(args.deepxss):
        logger.info("Loading DeepXSS dataset...")
        df = pd.read_csv(args.deepxss)
        df = df.rename(columns={"text": "payload", "label": "label"})
        datasets.append(df)

    # Load Neo4j logs
    if args.from_neo4j:
        logger.info("Loading from Neo4j...")
        df = load_from_neo4j()
        datasets.append(df)

    if not datasets:
        raise SystemExit("No datasets available. Provide CSVs or enable --from-neo4j")

    train_model(datasets)
