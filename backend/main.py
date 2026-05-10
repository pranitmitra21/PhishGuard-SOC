from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
import hashlib
import redis
import json
import os
from datetime import datetime, timedelta
import tldextract

import models, schemas, database
from ml.model_inference import predict_phishing, reload_model, load_metrics
from ml.retrain_pipeline import run_pipeline
from ml.heuristics import analyze_url_heuristics
from ml.vision_engine import scan_screenshot
from threat_intel import check_safe_browsing
from blockchain_utils import log_to_blockchain
from whois_utils import get_domain_age_days

# Load Tranco Whitelist into a fast memory Set on Startup
def load_whitelist():
    path = os.path.join(os.path.dirname(__file__), "ml", "tranco.txt")
    if not os.path.exists(path):
        return set()
    with open(path, "r") as f:
        return set(line.strip() for line in f)

TRANCO_WHITELIST = load_whitelist()

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

def process_blockchain_bg(url_hash: str, features_dict: dict):
    # This runs asynchronously so Polygon testnet latency doesn't block the UI
    try:
        log_to_blockchain(url_hash, features_dict)
    except Exception as e:
        print(f"Blockchain logging bg failed: {e}")
@app.post("/detect")
def detect_url(features: schemas.URLFeatures, background_tasks: BackgroundTasks, db: Session = Depends(database.get_db)):
    url_hash = hashlib.sha256(features.url.encode()).hexdigest()
    features_dump = features.model_dump() if hasattr(features, "model_dump") else features.dict()
    
    # 1. Check Tranco Top 1M Whitelist First (Instant O(1) lookup)
    domain_extract = tldextract.extract(features.url)
    root_domain = f"{domain_extract.domain}.{domain_extract.suffix}"
    
    if root_domain in TRANCO_WHITELIST:
        existing = db.query(models.DetectionLog).filter(models.DetectionLog.url_hash == url_hash).first()
        if not existing:
            db_log = models.DetectionLog(
                url=features.url,
                url_hash=url_hash,
                status="Safe",
                confidence=100.0,
                logged_to_blockchain=False,
                url_length=features_dump.get('url_length'),
                has_at_symbol=features_dump.get('has_at_symbol'),
                num_subdomains=features_dump.get('num_subdomains'),
                is_https=features_dump.get('is_https'),
                suspicious_dom_elements=features_dump.get('suspicious_dom_elements')
            )
            db.add(db_log)
            db.commit()
            
        return {
            "url": features.url,
            "status": "Safe",
            "confidence": 100.0,
            "logged_to_blockchain": False,
            "features": features_dump,
            "domain_age_days": -1,
            "is_whitelisted": True,
            "cached": True,
            "message": f"Mathematically verified safe (Top 1M Whitelist: {root_domain})."
        }
    
    # 2. Get Domain Age via WHOIS
    domain_age_days = get_domain_age_days(root_domain)
    
    # 3. Check Redis Cache
    cached = redis_client.get(f"phish_cache:{url_hash}")
    
    if cached:
        cache_data = json.loads(cached)
        return {
            "url": features.url,
            "status": cache_data.get("status"),
            "confidence": cache_data.get("confidence"),
            "logged_to_blockchain": cache_data.get("logged_to_blockchain"),
            "domain_age_days": cache_data.get("domain_age_days", -1),
            "is_whitelisted": False,
            "features": features_dump,
            "cached": True
        }
    
    # 3.5 Check External Threat Intelligence
    ti_result = check_safe_browsing(features.url)
    if ti_result["is_phishing"]:
        status = "Phishing"
        final_confidence = 100.0
        logged_to_bc = True
        background_tasks.add_task(process_blockchain_bg, url_hash, features_dump)
        
        # Save to DB Synchronously so session is still open
        existing = db.query(models.DetectionLog).filter(models.DetectionLog.url_hash == url_hash).first()
        if not existing:
            db_log = models.DetectionLog(
                url=features.url,
                url_hash=url_hash,
                status=status,
                confidence=final_confidence,
                logged_to_blockchain=logged_to_bc,
                url_length=features_dump.get('url_length'),
                has_at_symbol=features_dump.get('has_at_symbol'),
                num_subdomains=features_dump.get('num_subdomains'),
                is_https=features_dump.get('is_https'),
                suspicious_dom_elements=features_dump.get('suspicious_dom_elements')
            )
            db.add(db_log)
        else:
            existing.status = status
            existing.confidence = final_confidence
            existing.logged_to_blockchain = logged_to_bc
            existing.suspicious_dom_elements = features_dump.get('suspicious_dom_elements')
            existing.is_https = features_dump.get('is_https')
            existing.num_subdomains = features_dump.get('num_subdomains')
            existing.url_length = features_dump.get('url_length')
            existing.has_at_symbol = features_dump.get('has_at_symbol')

        db.commit()

        # Cache result in Redis
        cache_result = {
            "status": status,
            "confidence": final_confidence,
            "logged_to_blockchain": logged_to_bc,
            "domain_age_days": domain_age_days
        }
        redis_client.setex(f"phish_cache:{url_hash}", 3600, json.dumps(cache_result))
        
        return {
            "url": features.url,
            "status": status,
            "confidence": final_confidence,
            "logged_to_blockchain": logged_to_bc,
            "domain_age_days": domain_age_days,
            "is_whitelisted": False,
            "features": features_dump,
            "cached": False,
            "message": ti_result["message"]
        }

    # 4. Run ML Inference Synchronously
    status, base_confidence = predict_phishing(features_dump)
    base_confidence = float(base_confidence)  # Fix: PostgreSQL crashes on np.float64 types
    
    # 4.5 Run Advanced Lexical Heuristics (Tier 1 AI)
    heuristics = analyze_url_heuristics(features.url)
    features_dump["heuristics"] = heuristics # Append to features dump for logging
    
    # 5. Multi-Layer Decision Engine (Combine ML with WHOIS Risk and Heuristics)
    final_confidence = base_confidence
    
    # Factor in heuristic risk (Typo-squatting, Entropy, Keywords)
    if heuristics["heuristic_risk_score"] > 0:
        final_confidence = final_confidence + heuristics["heuristic_risk_score"]
        # If it's a direct typo-squat, jump immediately to critical threshold
        if heuristics["is_typosquat"]:
            final_confidence = max(final_confidence, 85.0)

    # Factor in Deep DOM Analytics
    if features_dump.get("has_cross_origin_form"):
        final_confidence = max(final_confidence, 95.0)
        heuristics["reasons"].append("Zero-Click Theft: Password form submits to external tracking domain!")

    if domain_age_days != -1:
        if domain_age_days < 30:
            # High risk: Brand new domain. Spike the phishing probability.
            final_confidence = min(99.9, final_confidence * 1.5)
        elif domain_age_days > 365:
            # Low risk: Established domain. Slash the phishing probability.
            # Don't slash it too much if it's a known typo-squat though
            slash_factor = 0.8 if heuristics["is_typosquat"] else 0.4
            final_confidence = final_confidence * slash_factor
            
    final_confidence = min(99.9, final_confidence)

    # Re-evaluate final status based on weighted confidence
    if final_confidence >= 80:
        status = "Phishing"
    elif final_confidence >= 40:
        status = "Suspicious"
    else:
        status = "Safe"
    
    logged_to_bc = False
    if status == "Phishing":
        background_tasks.add_task(process_blockchain_bg, url_hash, features_dump)
        logged_to_bc = True

    # Save to DB Synchronously so session is still open
    existing = db.query(models.DetectionLog).filter(models.DetectionLog.url_hash == url_hash).first()
    if not existing:
        db_log = models.DetectionLog(
            url=features.url,
            url_hash=url_hash,
            status=status,
            confidence=final_confidence,
            logged_to_blockchain=logged_to_bc,
            url_length=features_dump.get('url_length'),
            has_at_symbol=features_dump.get('has_at_symbol'),
            num_subdomains=features_dump.get('num_subdomains'),
            is_https=features_dump.get('is_https'),
            suspicious_dom_elements=features_dump.get('suspicious_dom_elements')
        )
        db.add(db_log)
    else:
        # Force stale database records to update to the immediate live ML output
        existing.status = status
        existing.confidence = final_confidence
        existing.logged_to_blockchain = logged_to_bc
        existing.suspicious_dom_elements = features_dump.get('suspicious_dom_elements')
        existing.is_https = features_dump.get('is_https')
        existing.num_subdomains = features_dump.get('num_subdomains')
        existing.url_length = features_dump.get('url_length')
        existing.has_at_symbol = features_dump.get('has_at_symbol')

    db.commit()

    # Cache result in Redis
    cache_result = {
        "status": status,
        "confidence": final_confidence,
        "logged_to_blockchain": logged_to_bc,
        "domain_age_days": domain_age_days
    }
    redis_client.setex(f"phish_cache:{url_hash}", 3600, json.dumps(cache_result))
    
    message = "Scanned successfully with multi-layer engine."
    if heuristics["reasons"]:
        message = "Heuristics triggered: " + " | ".join(heuristics["reasons"])
    
    return {
        "url": features.url,
        "status": status,
        "confidence": final_confidence,
        "logged_to_blockchain": logged_to_bc,
        "domain_age_days": domain_age_days,
        "is_whitelisted": False,
        "features": features_dump,
        "cached": False,
        "message": message
    }

class ReportItem(BaseModel):
    url: str

class VisionScanRequest(BaseModel):
    url: str
    screenshot_base64: str

@app.post("/vision-scan")
def api_vision_scan(req: VisionScanRequest):
    result = scan_screenshot(req.screenshot_base64)
    # Return the CV matches to the frontend for the XAI Overlay
    return result

@app.post("/report")
def report_phishing(item: ReportItem, db: Session = Depends(database.get_db)):
    url_hash = hashlib.sha256(item.url.encode()).hexdigest()
    existing = db.query(models.DetectionLog).filter(models.DetectionLog.url_hash == url_hash).first()
    
    if existing:
        existing.status = "User_Reported_Phishing"
    else:
        new_log = models.DetectionLog(
            url=item.url,
            url_hash=url_hash,
            status="User_Reported_Phishing",
            confidence=100.0,
            logged_to_blockchain=False
        )
        db.add(new_log)
        
    db.commit()
    # Cache the report so future scans catch it instantly
    cache_result = {"status": "User_Reported_Phishing", "confidence": 100.0, "logged_to_blockchain": False}
    redis_client.setex(f"phish_cache:{url_hash}", 86400, json.dumps(cache_result)) # Cache for 1 day
    
    return {"message": "Report logged successfully"}

@app.get("/domain-age")
def api_domain_age(url: str):
    domain_extract = tldextract.extract(url)
    root_domain = f"{domain_extract.domain}.{domain_extract.suffix}"
    age = get_domain_age_days(root_domain)
    return {"domain": root_domain, "age_days": age}

@app.get("/logs", response_model=List[schemas.LogOut])
def get_logs(skip: int = 0, limit: int = 20, db: Session = Depends(database.get_db)):
    return db.query(models.DetectionLog).order_by(models.DetectionLog.timestamp.desc()).offset(skip).limit(limit).all()

@app.get("/stats")
def get_stats(db: Session = Depends(database.get_db)):
    total = db.query(models.DetectionLog).count()
    phishing = db.query(models.DetectionLog).filter(models.DetectionLog.status == 'Phishing').count()
    suspicious = db.query(models.DetectionLog).filter(models.DetectionLog.status == 'Suspicious').count()
    safe = db.query(models.DetectionLog).filter(models.DetectionLog.status == 'Safe').count()
    
    # Load real metrics from the last training run (falls back to defaults if not yet trained)
    metrics = load_metrics()
    accuracy = metrics["model_accuracy"]
    false_positive_rate = metrics["false_positive_rate"]
    
    # Generate progression data for the last 7 days
    progression = []
    today = datetime.utcnow().date()
    for i in range(6, -1, -1):
        target_date = today - timedelta(days=i)
        
        # Calculate start and end of the day bounds
        start_of_day = datetime.combine(target_date, datetime.min.time())
        end_of_day = start_of_day + timedelta(days=1)
        
        day_logs = db.query(models.DetectionLog).filter(
            models.DetectionLog.timestamp >= start_of_day,
            models.DetectionLog.timestamp < end_of_day
        )
        total_day = day_logs.count()
        safe_day = day_logs.filter(models.DetectionLog.status == 'Safe').count()
        
        score = 100
        if total_day > 0:
            score = int((safe_day / total_day) * 100)
            
        progression.append({
            "name": target_date.strftime("%a"),
            "score": score
        })
    
    return {
        "total_scanned": total,
        "phishing_detected": phishing,
        "suspicious_detected": suspicious,
        "safe_detected": safe,
        "model_accuracy": accuracy,
        "false_positive_rate": false_positive_rate,
        "progression": progression
    }

def background_retrain():
    success = run_pipeline()
    if success:
        reload_model()
        print("MLOps: Background retrain and reload completed successfully.")

@app.post("/admin/retrain")
def trigger_retrain(background_tasks: BackgroundTasks):
    background_tasks.add_task(background_retrain)
    return {"message": "Model retraining pipeline initiated in the background."}
