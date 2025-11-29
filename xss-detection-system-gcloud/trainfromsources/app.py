# train_from_sources.py
import argparse
import pandas as pd
import joblib
import os
from neo4j import GraphDatabase
import re
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import xgboost as xgb

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "password")

def load_kaggle_csv(path):
    return pd.read_csv(path)

def load_deepxss_csv(path):
    # repo has xssed.csv, dmzo_nomal.csv etc.
    return pd.read_csv(path)

def neo4j_to_dataframe(limit=10000):
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with driver.session() as session:
        q = """
        MATCH (r:Request)-[:HAS_PAYLOAD]->(p:Payload)
        RETURN p.payload AS payload, r.is_malicious AS label, r.confidence AS confidence
        LIMIT $limit
        """
        res = session.run(q, {"limit": limit})
        rows = [{"payload": rec["payload"], "label": int(rec["label"] or 0), "confidence": float(rec["confidence"] or 0.0)} for rec in res]
    return pd.DataFrame(rows)

def featurize(df):
    # create simple numeric features for XGBoost; replace with better tokenization
    df['len'] = df['payload'].fillna("").str.len()
    df['count_lt'] = df['payload'].fillna("").str.count('<')
    df['count_gt'] = df['payload'].fillna("").str.count('>')
    df['count_script'] = df['payload'].fillna("").str.lower().str.count('script')
    df['count_encoded'] = df['payload'].fillna("").str.count(r'%[0-9A-Fa-f]{2}')
    df['count_entity'] = df['payload'].fillna("").str.count(r'&[#a-zA-Z0-9]+;')
    # label
    df = df.fillna(0)
    return df

def train_and_save(X, y, model_path="models/xgb_model.joblib"):
    clf = xgb.XGBClassifier(n_estimators=200, max_depth=6, use_label_encoder=False, eval_metric='logloss')
    clf.fit(X, y)
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(clf, model_path)
    return clf

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--kaggle", default="kaggle_xss.csv", help="Kaggle dataset CSV path")
    parser.add_argument("--deepxss", default="deepxss.csv", help="DeepXSS CSV path")
    parser.add_argument("--from-neo4j", action="store_true")
    args = parser.parse_args()

    frames = []
    if os.path.exists(args.kaggle):
        print("Loading Kaggle dataset...")
        frames.append(load_kaggle_csv(args.kaggle))
    if os.path.exists(args.deepxss):
        print("Loading DeepXSS dataset...")
        frames.append(load_deepxss_csv(args.deepxss))
    if args.from_neo4j:
        print("Loading from Neo4j...")
        frames.append(neo4j_to_dataframe(limit=20000))

    if not frames:
        raise SystemExit("No datasets found. Place CSVs or enable --from-neo4j")

    df = pd.concat(frames, ignore_index=True, sort=False)
    print("Total rows:", len(df))
    df = df.rename(columns={df.columns[0]: "payload"})  # heuristic if datasets vary
    df = df[['payload', 'label']] if 'label' in df.columns else df[['payload']]
    # If dataset lacks label, create heuristic labels (e.g. from filenames) or skip rows without label
    if 'label' not in df.columns:
        raise SystemExit("Dataset must contain label column (0/1) or use neo4j which should include label")

    df = featurize(df)
    features = ['len','count_lt','count_gt','count_script','count_encoded','count_entity']
    X = df[features].values
    y = df['label'].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = train_and_save(X_train, y_train)
    preds = clf.predict(X_test)
    proba = clf.predict_proba(X_test)[:,1]
    print(classification_report(y_test, preds))
    try:
        print("AUC:", roc_auc_score(y_test, proba))
    except Exception:
        pass
    print("Model saved.")
