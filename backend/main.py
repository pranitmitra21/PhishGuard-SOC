from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
import hashlib
import redis
import json
import os

import models, schemas, database
from ml.model_inference import predict_phishing
from blockchain_utils import log_to_blockchain

models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="Phishing Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect to Redis container
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

def process_detection_bg(features_dict: dict, url_hash: str, db: Session):
    # 1. Run ML Inference
    status, confidence = predict_phishing(features_dict)
    
    # 2. Log to Blockchain if Phishing
    logged_to_bc = False
    if status == "Phishing":
        try:
            log_to_blockchain(url_hash, features_dict)
            logged_to_bc = True
        except Exception as e:
            print(f"Blockchain logging failed: {e}")

    # 3. Save to DB
    db_log = models.DetectionLog(
        url=features_dict.get('url'),
        url_hash=url_hash,
        status=status,
        confidence=confidence,
        logged_to_blockchain=logged_to_bc,
        url_length=features_dict.get('url_length'),
        has_at_symbol=features_dict.get('has_at_symbol'),
        num_subdomains=features_dict.get('num_subdomains'),
        is_https=features_dict.get('is_https'),
        suspicious_dom_elements=features_dict.get('suspicious_dom_elements')
    )
    db.add(db_log)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        pass

    # 4. Cache result in Redis for 1 hour (3600 seconds)
    cache_result = {
        "status": status,
        "confidence": confidence,
        "logged_to_blockchain": logged_to_bc
    }
    redis_client.setex(f"phish_cache:{url_hash}", 3600, json.dumps(cache_result))


@app.post("/detect")
def detect_url(features: schemas.URLFeatures, background_tasks: BackgroundTasks, db: Session = Depends(database.get_db)):
    url_hash = hashlib.sha256(features.url.encode()).hexdigest()
    
    # Check Redis Cache First
    cached = redis_client.get(f"phish_cache:{url_hash}")
    features_dump = features.model_dump() if hasattr(features, "model_dump") else features.dict()
    
    if cached:
        cache_data = json.loads(cached)
        return {
            "url": features.url,
            "status": cache_data.get("status"),
            "confidence": cache_data.get("confidence"),
            "logged_to_blockchain": cache_data.get("logged_to_blockchain"),
            "features": features_dump,
            "cached": True
        }
    
    # Not cached. Queue Background Task
    background_tasks.add_task(process_detection_bg, features_dump, url_hash, db)
    
    return {
        "url": features.url,
        "status": "Scanning_Pending",
        "confidence": 0.0,
        "logged_to_blockchain": False,
        "features": features_dump,
        "cached": False,
        "message": "URL submitted for background scanning."
    }

@app.get("/logs", response_model=List[schemas.LogOut])
def get_logs(skip: int = 0, limit: int = 20, db: Session = Depends(database.get_db)):
    return db.query(models.DetectionLog).order_by(models.DetectionLog.timestamp.desc()).offset(skip).limit(limit).all()

@app.get("/stats")
def get_stats(db: Session = Depends(database.get_db)):
    total = db.query(models.DetectionLog).count()
    phishing = db.query(models.DetectionLog).filter(models.DetectionLog.status == 'Phishing').count()
    suspicious = db.query(models.DetectionLog).filter(models.DetectionLog.status == 'Suspicious').count()
    safe = db.query(models.DetectionLog).filter(models.DetectionLog.status == 'Safe').count()
    
    # Example accuracy metric (could be calculated dynamically based on user feedback if implemented)
    accuracy = 94.5 
    
    return {
        "total_scanned": total,
        "phishing_detected": phishing,
        "suspicious_detected": suspicious,
        "safe_detected": safe,
        "model_accuracy": accuracy
    }
