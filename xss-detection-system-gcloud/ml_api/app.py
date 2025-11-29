# ml_api.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Dict
import uvicorn
import joblib
import math
import re
import os
from urllib.parse import unquote

from feature_extractor import FeatureExtractor

MODEL_PATH = os.getenv("MODEL_PATH", "/models/xgboost_model.joblib")
# MODEL_PATH = os.getenv("MODEL_PATH", "/models/codeburp_model.joblib")
# MODEL_PATH = os.getenv("MODEL_PATH", "/models/random_forest_model.joblib")
model = None
try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    print("Model not loaded:", e)

app = FastAPI(title="ML Payload Analysis API")

extractor = FeatureExtractor()


class AnalyzeRequest(BaseModel):
    payload: str
    meta: Optional[Dict] = None

class AnalyzeResponse(BaseModel):
    is_malicious: bool
    confidence: float
    detected_patterns: List[str]
    raw_payload: str
    normalized_payload: str
    decoded_versions: List[str]

COMMON_PATTERNS = [
    r"<\s*script\b",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"document\.cookie",
    r"eval\s*\(",
    r"&#x",
    r"&#\d+",
    r"\\x[0-9a-f]{2}",
    r"\\u[0-9a-f]{4}",
]

def recursive_decode(payload: str, max_iterations=5):
    """
    Recursively URL-decode the payload until no more decoding occurs
    or max iterations reached. This handles double/triple encoding.
    """
    decoded_versions = [payload]
    current = payload
    
    for _ in range(max_iterations):
        try:
            decoded = unquote(current)
            if decoded == current:
                # No more decoding possible
                break
            decoded_versions.append(decoded)
            current = decoded
        except Exception:
            break
    
    return decoded_versions

def rule_detect(payload: str):
    """Check payload against common XSS patterns"""
    detected = []
    for pattern in COMMON_PATTERNS:
        if re.search(pattern, payload, re.I):
            detected.append(pattern)
    return detected


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    payload = req.payload or ""
    
    # 1. Decode payload multiple times to handle encoding obfuscation
    decoded_versions = recursive_decode(payload)
    
    normalized_payload = decoded_versions[-1]
    
    # 2. Check all decoded versions for patterns
    all_detected_patterns = set()
    max_confidence = 0.0
    
    for decoded_payload in decoded_versions:
        # Rule-based detection on each version
        patterns = rule_detect(decoded_payload)
        all_detected_patterns.update(patterns)
        
        # ML detection on each version
        if model:
            try:
                features = extractor.extract(decoded_payload)
                vector = extractor.vectorize(features)
                
                try:
                    confidence = float(model.predict_proba([vector])[0][1])
                except Exception:
                    # Fallback for models without predict_proba
                    try:
                        score = model.predict([vector])[0]
                        confidence = 1 / (1 + math.exp(-score))
                    except:
                        confidence = 0.0
                
                max_confidence = max(max_confidence, confidence)
            except Exception as e:
                print(f"ML detection error: {e}")
    
    # 3. Final decision
    detected_patterns_list = list(all_detected_patterns)
    is_malicious = len(detected_patterns_list) > 0 or max_confidence >= 0.5
    
    if detected_patterns_list:
        max_confidence = max(max_confidence, 0.9)
    
    return AnalyzeResponse(
        is_malicious=is_malicious,
        confidence=round(max_confidence, 4),
        detected_patterns=detected_patterns_list,
        raw_payload=payload,
        normalized_payload=normalized_payload,
        decoded_versions=decoded_versions
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)