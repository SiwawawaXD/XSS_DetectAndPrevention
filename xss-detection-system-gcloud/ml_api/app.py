# ml_api.py (ENHANCED VERSION WITH HOT-RELOAD)
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict
import uvicorn
import joblib
import math
import re
import os
import threading
import time
from urllib.parse import unquote
from datetime import datetime

from feature_extractor import FeatureExtractor

# Global model state with thread lock for safe hot-reloading
model_lock = threading.Lock()
current_model = {
    "model": None,
    "scaler": None,
    "version": None,
    "loaded_at": None,
    "path": None
}

MODEL_PATH = os.getenv("MODEL_PATH", "/models/xgboost_model.joblib")
SCALER_PATH = os.getenv("SCALER_PATH", "/models/xss_scaler.joblib")

app = FastAPI(title="ML Payload Analysis API with Hot-Reload")

extractor = FeatureExtractor()


# =========================================================
# MODEL LOADING FUNCTIONS
# =========================================================
def load_model_from_path(model_path: str, scaler_path: str = None):
    """Load model and scaler from specified paths"""
    try:
        print(f"[{datetime.now()}] Loading model from: {model_path}")
        model = joblib.load(model_path)
        
        scaler = None
        if scaler_path and os.path.exists(scaler_path):
            print(f"[{datetime.now()}] Loading scaler from: {scaler_path}")
            scaler = joblib.load(scaler_path)
        
        # Extract version from filename (e.g., xgb_model_v2.joblib -> v2)
        version = "v1"  # default
        if "_v" in model_path:
            version = model_path.split("_v")[-1].replace(".joblib", "")
        
        return {
            "model": model,
            "scaler": scaler,
            "version": version,
            "loaded_at": datetime.now().isoformat(),
            "path": model_path
        }
    except Exception as e:
        print(f"[ERROR] Failed to load model: {e}")
        return None


def initialize_model():
    """Initialize model at startup"""
    global current_model
    
    model_data = load_model_from_path(MODEL_PATH, SCALER_PATH)
    if model_data:
        with model_lock:
            current_model = model_data
        print(f"✓ Model initialized: {current_model['version']} at {current_model['loaded_at']}")
    else:
        print("✗ Model not loaded - API will return errors")


# Load model at startup
initialize_model()


# =========================================================
# PYDANTIC MODELS
# =========================================================
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
    model_version: str  # NEW: Track which model version made the decision


class ModelInfo(BaseModel):
    version: str
    loaded_at: str
    model_path: str
    status: str


class ReloadRequest(BaseModel):
    model_path: str
    scaler_path: Optional[str] = None


class ReloadResponse(BaseModel):
    success: bool
    message: str
    old_version: str
    new_version: str
    loaded_at: str


# =========================================================
# XSS DETECTION PATTERNS
# =========================================================
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
    """Recursively URL-decode the payload"""
    decoded_versions = [payload]
    current = payload
    
    for _ in range(max_iterations):
        try:
            decoded = unquote(current)
            if decoded == current:
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


# =========================================================
# API ENDPOINTS
# =========================================================
@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    """Analyze payload for XSS with current model"""
    payload = req.payload or ""
    
    with model_lock:
        if current_model["model"] is None:
            raise HTTPException(status_code=503, detail="Model not loaded")
        
        model = current_model["model"]
        scaler = current_model["scaler"]
        version = current_model["version"]
    
    # 1. Decode payload
    decoded_versions = recursive_decode(payload)
    normalized_payload = decoded_versions[-1]
    
    # 2. Rule-based detection
    detected_patterns = rule_detect(normalized_payload)
    
    # 3. ML prediction
    features = extractor.extract_batch([normalized_payload])
    
    if scaler is not None:
        features = scaler.transform(features)
    
    prediction = model.predict(features)[0]
    proba = model.predict_proba(features)[0]
    confidence = float(proba[1]) if prediction == 1 else float(proba[0])
    
    is_malicious = bool(prediction == 1 and confidence >= 0.8)
    
    return AnalyzeResponse(
        is_malicious=is_malicious,
        confidence=confidence,
        detected_patterns=detected_patterns,
        raw_payload=payload,
        normalized_payload=normalized_payload,
        decoded_versions=decoded_versions,
        model_version=version  # Include model version in response
    )


@app.get("/model/info", response_model=ModelInfo)
def get_model_info():
    """Get current model information"""
    with model_lock:
        if current_model["model"] is None:
            return ModelInfo(
                version="none",
                loaded_at="never",
                model_path="none",
                status="not_loaded"
            )
        
        return ModelInfo(
            version=current_model["version"],
            loaded_at=current_model["loaded_at"],
            model_path=current_model["path"],
            status="loaded"
        )


@app.post("/model/reload", response_model=ReloadResponse)
def reload_model(req: ReloadRequest):
    """
    Hot-reload model from specified path (ZERO DOWNTIME)
    
    Example usage:
    POST /model/reload
    {
        "model_path": "/models/xgb_model_v2.joblib",
        "scaler_path": "/models/xss_scaler.joblib"
    }
    """
    global current_model
    
    # Validate paths exist
    if not os.path.exists(req.model_path):
        raise HTTPException(status_code=404, detail=f"Model file not found: {req.model_path}")
    
    if req.scaler_path and not os.path.exists(req.scaler_path):
        raise HTTPException(status_code=404, detail=f"Scaler file not found: {req.scaler_path}")
    
    # Load new model (outside lock - slow operation)
    new_model_data = load_model_from_path(req.model_path, req.scaler_path)
    
    if new_model_data is None:
        raise HTTPException(status_code=500, detail="Failed to load new model")
    
    # Quick swap (inside lock - fast operation)
    with model_lock:
        old_version = current_model["version"]
        current_model = new_model_data
    
    return ReloadResponse(
        success=True,
        message=f"Model hot-reloaded successfully",
        old_version=old_version,
        new_version=current_model["version"],
        loaded_at=current_model["loaded_at"]
    )


@app.get("/health")
def health_check():
    """Health check endpoint"""
    with model_lock:
        model_loaded = current_model["model"] is not None
    
    return {
        "status": "healthy" if model_loaded else "degraded",
        "model_loaded": model_loaded,
        "model_version": current_model.get("version", "none")
    }


# =========================================================
# STARTUP
# =========================================================
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)