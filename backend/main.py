from dotenv import load_dotenv
load_dotenv()  # MUST be first — loads .env before auth.py reads JWT_SECRET

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, status, Request
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from typing import List
import hashlib
import redis
import json
import os
from datetime import datetime, timedelta
import asyncio
import jwt
import tldextract
import socket
from urllib.parse import urlparse
import time
import random
from fastapi.responses import StreamingResponse
from ml.investigate import get_ssl_cert, get_dns_records

import models, schemas, database
import auth
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

# Sacred domains — hardcoded permanent override, can NEVER be flagged as phishing
# even if Redis cache is stale or ML makes a rare false positive
SACRED_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "googleusercontent.com",
    "github.com", "microsoft.com", "linkedin.com", "apple.com",
    "amazon.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "reddit.com", "wikipedia.org", "cloudflare.com",
    "stackoverflow.com", "openai.com", "netflix.com", "spotify.com",
    "whatsapp.com", "telegram.org", "zoom.us", "dropbox.com",
}

models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="Phishing Detection API")

# Build the CORS origins list:
# 1. Configured origins from env var (web dashboard + frontend)
# 2. Chrome extension origins — their background service worker sends
#    requests from a chrome-extension:// origin that we must allow.
#    We use allow_origin_regex to match any extension ID dynamically.
_configured_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost,http://localhost:80,http://localhost:5173"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_configured_origins,
    allow_origin_regex=r"chrome-extension://.*",  # Allow any installed Chrome extension
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect to Redis container
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

async def retry_failed_blockchain_logs():
    print("[Background Worker] Auto-Retry Blockchain Queue initialized...")
    while True:
        await asyncio.sleep(15) # Wait 15s after startup before first sweep
        db = None  # B4 FIX: declare outside try so finally can always close it
        try:
            db = database.SessionLocal()
            pending_logs = db.query(models.DetectionLog).filter(
                models.DetectionLog.status == "Phishing",
                models.DetectionLog.logged_to_blockchain == False
            ).all()
            
            if pending_logs:
                print(f"[Background Worker] Found {len(pending_logs)} pending threats. Attempting retry...")
                
            for log in pending_logs:
                try:
                    features_dict = {
                        "url": log.url,
                        "url_length": log.url_length,
                        "has_at_symbol": log.has_at_symbol,
                        "num_subdomains": log.num_subdomains,
                        "is_https": log.is_https,
                        "suspicious_dom_elements": log.suspicious_dom_elements
                    }
                    log_to_blockchain(log.url_hash, features_dict)
                    log.logged_to_blockchain = True
                    db.commit()
                    print(f"[Background Worker] Successfully logged {log.url_hash} to blockchain!")
                except Exception as e:
                    print(f"[Background Worker] Retry failed for {log.url_hash}: {e}")
        except Exception as e:
            print(f"[Background Worker] Fatal error in loop: {e}")
        finally:
            # B4 FIX: always close the session regardless of where an exception fires
            if db is not None:
                db.close()
            
        await asyncio.sleep(300) # Sleep for 5 minutes before next sweep

@app.on_event("startup")
async def startup_event():
    # B5 FIX: If the server restarted mid-retrain, the in-memory state would be stuck
    # as "running" forever, blocking all future retrain requests. Reset it on every boot.
    global retrain_state
    if retrain_state["status"] == "running":
        print("[Startup] Detected stale 'running' retrain state from prior session. Resetting to idle.")
        retrain_state["status"] = "idle"
        retrain_state["progress"] = 0
    asyncio.create_task(retry_failed_blockchain_logs())


@app.post("/api/auth/register", response_model=schemas.UserOut)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Enforce Role-Based Security Requirements
    role = user.role if user.role in ["User", "Analyst", "Admin"] else "User"
    
    if role == "Admin":
        admin_secret = os.getenv("ADMIN_SECURE_PIN", "SOC_ADMIN_777")
        if user.admin_pin != admin_secret:
            raise HTTPException(status_code=403, detail="Invalid Admin Security PIN")
            
    if role == "Analyst":
        if not user.wallet_id or len(user.wallet_id.strip()) == 0:
            raise HTTPException(status_code=400, detail="Wallet ID is required for Analyst clearance")
    
    hashed_password = auth.get_password_hash(user.password)
    new_user = models.User(
        username=user.username, 
        hashed_password=hashed_password, 
        role=role,
        wallet_id=user.wallet_id if role == "Analyst" else None
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/api/auth/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": user.username, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

def process_blockchain_bg(url_hash: str, features_dict: dict):
    # This runs asynchronously so Ethereum Sepolia testnet latency doesn't block the UI.
    # IMPORTANT: logged_to_blockchain is set False in the DB by detect_url().
    # We only flip it True here AFTER the TX confirms on-chain.
    # If this fails, it stays False and the retry_failed_blockchain_logs worker
    # will pick it up on the next 5-minute sweep.
    db = None
    try:
        log_to_blockchain(url_hash, features_dict)
        # TX confirmed — now update the DB record
        db = database.SessionLocal()
        log_entry = db.query(models.DetectionLog).filter(
            models.DetectionLog.url_hash == url_hash
        ).order_by(models.DetectionLog.timestamp.desc()).first()
        if log_entry:
            log_entry.logged_to_blockchain = True
            db.commit()
            print(f"[Blockchain BG] DB updated: {url_hash} confirmed on-chain.")
    except Exception as e:
        print(f"[Blockchain BG] TX failed for {url_hash}: {e}. Will retry in next sweep.")
    finally:
        if db is not None:
            db.close()

@app.post("/api/detect")
def detect_url(features: schemas.URLFeatures, background_tasks: BackgroundTasks, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user_optional)):
    from concurrent.futures import ThreadPoolExecutor
    config = get_or_create_config(db)
    url_hash = hashlib.sha256(features.url.encode()).hexdigest()
    features_dump = features.model_dump() if hasattr(features, "model_dump") else features.dict()
    
    # 0. Hard-whitelist localhost and internal IPs (prevent dashboard scanning itself)
    parsed_host = urlparse(features.url).hostname or ""
    INTERNAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    if parsed_host in INTERNAL_HOSTS or parsed_host.startswith("192.168.") or parsed_host.startswith("10."):
        return {
            "url": features.url,
            "status": "Safe",
            "logged_to_blockchain": False,
            "confidence": 100.0,
            "message": "Internal/local address — skipped by PhishGuard.",
            "is_whitelisted": True
        }
    
    # 1. Check Tranco Top 1M Whitelist First (Instant O(1) lookup)
    domain_extract = tldextract.extract(features.url)
    root_domain = f"{domain_extract.domain}.{domain_extract.suffix}"
    
    if root_domain in TRANCO_WHITELIST or root_domain in SACRED_DOMAINS:
        user_id = current_user.id if current_user else None
        existing = db.query(models.DetectionLog).filter(models.DetectionLog.url_hash == url_hash, models.DetectionLog.user_id == user_id).first()
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
                suspicious_dom_elements=features_dump.get('suspicious_dom_elements'),
                session_id=features_dump.get('session_id'),
                user_id=user_id
            )
            db.add(db_log)
            db.commit()
        else:
            existing.session_id = features_dump.get('session_id')
            db.commit()
            
        return {
            "url": features.url,
            "status": "Safe",
            "logged_to_blockchain": False,
            "confidence": 100.0,
            "message": "Domain is in the trusted Tranco Top 1M whitelist.",
            "is_whitelisted": True
        }
    
    # 2. Check Redis Cache BEFORE slow network calls (instant response for repeat scans)
    cached = redis_client.get(f"phish_cache:{url_hash}")
    if cached:
        cache_data = json.loads(cached)
        user_id = current_user.id if current_user else None
        existing = db.query(models.DetectionLog).filter(
            models.DetectionLog.url_hash == url_hash,
            models.DetectionLog.user_id == user_id
        ).first()
        if not existing:
            db_log = models.DetectionLog(
                url=features.url, url_hash=url_hash,
                status=cache_data.get("status"),
                confidence=cache_data.get("confidence", 0.0),
                logged_to_blockchain=cache_data.get("logged_to_blockchain", False),
                url_length=features_dump.get('url_length', 0),
                has_at_symbol=features_dump.get('has_at_symbol', False),
                num_subdomains=features_dump.get('num_subdomains', 0),
                is_https=features_dump.get('is_https', True),
                suspicious_dom_elements=features_dump.get('suspicious_dom_elements', 0),
                session_id=features_dump.get('session_id'),
                user_id=user_id
            )
            db.add(db_log)
            db.commit()
        cache_data["url"] = features.url
        cache_data["message"] = "Scanned previously."
        return cache_data

    # 3. Run WHOIS, SSL, DNS AND Safe Browsing concurrently.
    # All 4 slow network calls fire at the same time — total latency = max of the 4, not sum.
    # Each .result(timeout=4) ensures no single unresponsive server can stall the entire scan.
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_whois = executor.submit(get_domain_age_days, root_domain)
        future_ssl   = executor.submit(get_ssl_cert, root_domain, features.url)
        future_dns   = executor.submit(get_dns_records, root_domain)
        future_ti    = executor.submit(check_safe_browsing, features.url) if config.enable_safe_browsing else None

        try:
            domain_age_days = future_whois.result(timeout=2.0)
        except Exception:
            domain_age_days = -1  # Timeout or error — treat as unknown age

        try:
            ssl_info = future_ssl.result(timeout=2.0)
        except Exception:
            ssl_info = {"valid": False}

        try:
            dns_info = future_dns.result(timeout=2.0)
        except Exception:
            dns_info = {"MX": []}

        try:
            ti_result = future_ti.result(timeout=2.0) if future_ti else {"is_phishing": False}
        except Exception:
            ti_result = {"is_phishing": False}

    features_dump["has_ssl_certificate"] = 1 if ssl_info.get("valid", False) else 0
    features_dump["missing_mx_records"]  = 1 if len(dns_info.get("MX", [])) == 0 else 0
    features_dump["domain_age_days"]     = domain_age_days if domain_age_days != -1 else 180


        
    if ti_result["is_phishing"]:
        detection_status = "Phishing"
        final_confidence = 100.0
        logged_to_bc = False
        if config.enable_blockchain_logging:
            # Queue the background task. logged_to_blockchain stays False in DB until
            # process_blockchain_bg confirms the TX on-chain.
            background_tasks.add_task(process_blockchain_bg, url_hash, features_dump)
        
        # Save to DB Synchronously so session is still open
        user_id = current_user.id if current_user else None
        existing = db.query(models.DetectionLog).filter(models.DetectionLog.url_hash == url_hash, models.DetectionLog.user_id == user_id).first()
        if not existing:
            db_log = models.DetectionLog(
                url=features.url,
                url_hash=url_hash,
                status=detection_status,
                confidence=final_confidence,
                logged_to_blockchain=logged_to_bc,
                url_length=features_dump.get('url_length'),
                has_at_symbol=features_dump.get('has_at_symbol'),
                num_subdomains=features_dump.get('num_subdomains'),
                is_https=features_dump.get('is_https'),
                suspicious_dom_elements=features_dump.get('suspicious_dom_elements'),
                session_id=features_dump.get('session_id'),
                user_id=current_user.id if current_user else None
            )
            db.add(db_log)
        else:
            existing.status = detection_status
            existing.confidence = final_confidence
            existing.logged_to_blockchain = logged_to_bc
            existing.suspicious_dom_elements = features_dump.get('suspicious_dom_elements')
            existing.is_https = features_dump.get('is_https')
            existing.num_subdomains = features_dump.get('num_subdomains')
            existing.url_length = features_dump.get('url_length')
            existing.has_at_symbol = features_dump.get('has_at_symbol')
            existing.session_id = features_dump.get('session_id')
            if current_user: existing.user_id = current_user.id

        db.commit()

        # Cache result in Redis
        cache_result = {
            "status": detection_status,
            "confidence": final_confidence,
            "logged_to_blockchain": logged_to_bc,
            "domain_age_days": domain_age_days,
            "message": "Flagged by external Threat Intelligence (Safe Browsing)."
        }
        redis_client.setex(f"phish_cache:{url_hash}", 3600, json.dumps(cache_result))
        
        return {
            "url": features.url,
            "status": detection_status,
            "logged_to_blockchain": logged_to_bc,
            "confidence": final_confidence,
            "message": cache_result["message"]
        }

    # 4. Run ML Inference Synchronously
    # B9 FIX: Renamed local variable from 'status' to 'detection_status' to avoid
    # shadowing the 'from fastapi import status' import at the top of this file.
    detection_status, base_confidence = predict_phishing(features_dump)
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
    if final_confidence >= config.confidence_threshold_phishing:
        detection_status = "Phishing"
    elif final_confidence >= config.confidence_threshold_suspicious:
        detection_status = "Suspicious"
    else:
        detection_status = "Safe"
    
    logged_to_bc = False
    if detection_status == "Phishing" and config.enable_blockchain_logging:
        background_tasks.add_task(process_blockchain_bg, url_hash, features_dump)
        logged_to_bc = True

    # Save to DB Synchronously so session is still open
    user_id = current_user.id if current_user else None
    existing = db.query(models.DetectionLog).filter(models.DetectionLog.url_hash == url_hash, models.DetectionLog.user_id == user_id).first()
    if not existing:
        db_log = models.DetectionLog(
            url=features.url,
            url_hash=url_hash,
            status=detection_status,
            confidence=final_confidence,
            logged_to_blockchain=logged_to_bc,
            url_length=features_dump.get('url_length'),
            has_at_symbol=features_dump.get('has_at_symbol'),
            num_subdomains=features_dump.get('num_subdomains'),
            is_https=features_dump.get('is_https'),
            suspicious_dom_elements=features_dump.get('suspicious_dom_elements'),
            session_id=features_dump.get('session_id'),
            user_id=current_user.id if current_user else None
        )
        db.add(db_log)
    else:
        # Force stale database records to update to the immediate live ML output
        existing.status = detection_status
        existing.confidence = final_confidence
        existing.logged_to_blockchain = logged_to_bc
        existing.suspicious_dom_elements = features_dump.get('suspicious_dom_elements')
        existing.is_https = features_dump.get('is_https')
        existing.num_subdomains = features_dump.get('num_subdomains')
        existing.url_length = features_dump.get('url_length')
        existing.has_at_symbol = features_dump.get('has_at_symbol')
        existing.session_id = features_dump.get('session_id')
        if current_user: existing.user_id = current_user.id

    db.commit()

    # Cache result in Redis
    message = "Scanned successfully with multi-layer engine."
    if heuristics["reasons"]:
        message = "Heuristics triggered: " + " | ".join(heuristics["reasons"])

    cache_result = {
        "status": detection_status,
        "confidence": final_confidence,
        "logged_to_blockchain": logged_to_bc,
        "domain_age_days": domain_age_days,
        "message": message
    }
    redis_client.setex(f"phish_cache:{url_hash}", 3600, json.dumps(cache_result))
    
    return {
        "url": features.url,
        "status": detection_status,
        "logged_to_blockchain": logged_to_bc,
        "confidence": final_confidence,
        "message": message
    }

class ReportItem(BaseModel):
    url: str

class VisionScanRequest(BaseModel):
    url: str
    screenshot_base64: str

@app.post("/api/vision-scan")
def api_vision_scan(req: VisionScanRequest, current_user: models.User = Depends(auth.get_current_user)):
    result = scan_screenshot(req.screenshot_base64)
    # Return the CV matches to the frontend for the XAI Overlay
    return result

@app.post("/api/report")
def report_phishing(item: ReportItem, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    url_hash = hashlib.sha256(item.url.encode()).hexdigest()
    existing = db.query(models.DetectionLog).filter(models.DetectionLog.url_hash == url_hash, models.DetectionLog.user_id == current_user.id).first()
    
    if existing:
        existing.status = "User_Reported_Phishing"
    else:
        new_log = models.DetectionLog(
            url=item.url,
            url_hash=url_hash,
            status="User_Reported_Phishing",
            confidence=100.0,
            logged_to_blockchain=False,
            user_id=current_user.id
        )
        db.add(new_log)
        
    db.commit()
    # Cache the report so future scans catch it instantly
    cache_result = {"status": "User_Reported_Phishing", "confidence": 100.0, "logged_to_blockchain": False}
    redis_client.setex(f"phish_cache:{url_hash}", 86400, json.dumps(cache_result)) # Cache for 1 day
    
    return {"message": "Report logged successfully"}

@app.get("/api/domain-age")
def api_domain_age(url: str):
    domain_extract = tldextract.extract(url)
    root_domain = f"{domain_extract.domain}.{domain_extract.suffix}"
    age = get_domain_age_days(root_domain)
    return {"domain": root_domain, "age_days": age}

@app.get("/api/logs", response_model=List[schemas.LogOut])
def get_logs(skip: int = 0, limit: int = 20, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    query = db.query(models.DetectionLog)
    if current_user.role == "User":
        query = query.filter(models.DetectionLog.user_id == current_user.id)
    logs = query.order_by(models.DetectionLog.timestamp.desc()).offset(skip).limit(limit).all()
    return logs

@app.get("/api/stats")
def get_stats(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    query = db.query(models.DetectionLog)
    if current_user.role == "User":
        query = query.filter(models.DetectionLog.user_id == current_user.id)
        
    total = query.count()
    phishing = query.filter(models.DetectionLog.status == 'Phishing').count()
    suspicious = query.filter(models.DetectionLog.status == 'Suspicious').count()
    safe = query.filter(models.DetectionLog.status == 'Safe').count()
    
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
        
        day_logs = query.filter(
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

def get_or_create_config(db: Session):
    config = db.query(models.SystemConfig).first()
    if not config:
        config = models.SystemConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

# Retraining Status Mock
retrain_state = {"status": "idle", "progress": 0, "epochs": []}

def background_retrain():
    global retrain_state
    retrain_state["status"] = "running"
    retrain_state["progress"] = 0
    retrain_state["epochs"] = []
    
    def progress_callback(data):
        retrain_state["epochs"].append(data)
        retrain_state["progress"] = min(100, round((data["epoch"] / 15) * 100))
        
    success = run_pipeline(progress_callback=progress_callback)
    if success:
        reload_model()
        print("MLOps: Background retrain and reload completed successfully.")
        
    retrain_state["status"] = "completed"

@app.post("/api/admin/retrain")
def trigger_retrain(background_tasks: BackgroundTasks, _: models.User = Depends(auth.require_admin)):
    """Admin-only endpoint. Triggers the MLOps retraining pipeline in the background."""
    if retrain_state["status"] == "running":
        return {"message": "Retraining is already in progress."}
    background_tasks.add_task(background_retrain)
    return {"message": "Model retraining pipeline initiated in the background."}

@app.get("/api/admin/retrain/status")
async def get_retrain_status(request: Request, token: str, db: Session = Depends(database.get_db)):
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        user = db.query(models.User).filter(models.User.username == payload.get("sub")).first()
        if not user or user.role != "Admin":
            raise HTTPException(status_code=403, detail="Not authorized")
    except:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    async def event_generator():
        last_epoch = 0
        while True:
            if await request.is_disconnected():
                break
                
            if retrain_state["status"] == "idle":
                yield f"data: {json.dumps(retrain_state)}\n\n"
                break
                
            current_epochs = retrain_state["epochs"]
            if len(current_epochs) > last_epoch or retrain_state["status"] == "completed":
                yield f"data: {json.dumps(retrain_state)}\n\n"
                last_epoch = len(current_epochs)
                
            if retrain_state["status"] == "completed":
                break
                
            await asyncio.sleep(0.5)
            
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/admin/users", response_model=List[schemas.UserOut])
def get_all_users(db: Session = Depends(database.get_db), _: models.User = Depends(auth.require_admin)):
    return db.query(models.User).all()

@app.put("/api/admin/users/{user_id}/role", response_model=schemas.UserOut)
def update_user_role(user_id: int, user_update: schemas.UserUpdate, db: Session = Depends(database.get_db), _: models.User = Depends(auth.require_admin)):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    if user_update.role not in ["User", "Analyst", "Admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")
        
    if user_update.role == "Admin":
        admin_secret = os.getenv("ADMIN_SECURE_PIN", "SOC_ADMIN_777")
        if user_update.admin_pin != admin_secret:
            raise HTTPException(status_code=403, detail="Invalid Admin Security PIN")
            
    if user_update.role == "Analyst":
        # Check if user already has a wallet_id, otherwise require it from update
        if not db_user.wallet_id and (not user_update.wallet_id or len(user_update.wallet_id.strip()) == 0):
            raise HTTPException(status_code=400, detail="Wallet ID is required for Analyst clearance")
        if user_update.wallet_id:
            db_user.wallet_id = user_update.wallet_id
            
    db_user.role = user_update.role
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/api/admin/config", response_model=schemas.ConfigOut)
def get_system_config(db: Session = Depends(database.get_db), _: models.User = Depends(auth.require_admin)):
    config = get_or_create_config(db)
    return {
        "confidence_threshold_phishing": config.confidence_threshold_phishing,
        "confidence_threshold_suspicious": config.confidence_threshold_suspicious,
        "enable_blockchain_logging": config.enable_blockchain_logging,
        "enable_safe_browsing": config.enable_safe_browsing
    }

@app.put("/api/admin/config", response_model=schemas.ConfigOut)
def update_system_config(config_in: schemas.ConfigUpdate, db: Session = Depends(database.get_db), _: models.User = Depends(auth.require_admin)):
    config = get_or_create_config(db)
    if config_in.confidence_threshold_phishing is not None:
        config.confidence_threshold_phishing = config_in.confidence_threshold_phishing
    if config_in.confidence_threshold_suspicious is not None:
        config.confidence_threshold_suspicious = config_in.confidence_threshold_suspicious
    if config_in.enable_blockchain_logging is not None:
        config.enable_blockchain_logging = config_in.enable_blockchain_logging
    if config_in.enable_safe_browsing is not None:
        config.enable_safe_browsing = config_in.enable_safe_browsing
    db.commit()
    db.refresh(config)
    return {
        "confidence_threshold_phishing": config.confidence_threshold_phishing,
        "confidence_threshold_suspicious": config.confidence_threshold_suspicious,
        "enable_blockchain_logging": config.enable_blockchain_logging,
        "enable_safe_browsing": config.enable_safe_browsing
    }

@app.get("/api/network-graph-data")
def get_network_graph(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    from concurrent.futures import ThreadPoolExecutor
    query = db.query(models.DetectionLog)
    if current_user.role == "User":
        query = query.filter(models.DetectionLog.user_id == current_user.id)
    logs = query.order_by(models.DetectionLog.timestamp.desc()).limit(100).all()
    
    nodes = []
    links = []
    
    # Add a central "User/SOC" node
    nodes.append({"id": "SOC_CORE", "group": 0, "name": "Operations Center", "val": 15, "timestamp": time.time()})
    
    seen_ips = set()
    seen_domains = set()
    ip_cluster_map = {} # Maps IP to a list of domains
    
    # Collect all unique domains first so we can resolve IPs in parallel
    domain_log_map = {}
    for log in logs:
        try:
            parsed = urlparse(log.url)
            domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
        except:
            domain = log.url
        if not domain:
            continue
        if domain not in seen_domains:
            domain_log_map[domain] = log
            seen_domains.add(domain)

    # B14 FIX: Resolve IPs in parallel instead of blocking sequentially.
    # Previously, socket.gethostbyname() was called one-by-one in the request thread,
    # potentially blocking the event loop for seconds per domain (up to 100 lookups).
    def resolve_ip(domain):
        try:
            return domain, socket.gethostbyname(domain)
        except Exception:
            return domain, None

    ip_results = {}
    unique_domains = list(domain_log_map.keys())
    if unique_domains:
        with ThreadPoolExecutor(max_workers=20) as executor:
            for domain, ip in executor.map(resolve_ip, unique_domains):
                ip_results[domain] = ip

    for domain, log in domain_log_map.items():
        group = 1 if log.status == "Safe" else (2 if log.status == "Suspicious" else 3)
        val = 4 if log.status == "Safe" else (6 if log.status == "Suspicious" else 8)
        
        # Confidence represents the model's certainty of its prediction.
        # Convert this to a true "Risk Score" (0-100)
        if log.status == "Safe":
            risk_score = max(0, 100.0 - log.confidence) # e.g. 99% safe = 1% risk
        elif log.status == "Phishing":
            risk_score = log.confidence # e.g. 99% phishing = 99% risk
        else:
            risk_score = 50.0 + (log.confidence * 0.3) # Suspicious maps to 50-80
            
        nodes.append({
            "id": domain, 
            "group": group, 
            "name": domain, 
            "val": val, 
            "risk_score": risk_score,
            "timestamp": log.timestamp.timestamp(),
            "nodeType": "domain",
            "session_id": log.session_id
        })
        links.append({"source": "SOC_CORE", "target": domain})
        
        ip = ip_results.get(domain)
        if ip:
            if ip not in seen_ips:
                nodes.append({
                    "id": ip, "group": 4, "name": ip, "val": 5, 
                    "timestamp": log.timestamp.timestamp(), "nodeType": "ip",
                    "session_id": log.session_id
                })
                seen_ips.add(ip)
                ip_cluster_map[ip] = []
            
            ip_cluster_map[ip].append(domain)
            links.append({"source": domain, "target": ip})
                
    # Basic Phishing Infrastructure Cluster Detection
    # If multiple suspicious/phishing domains map to the same IP, mark the IP as a Threat Cluster
    for ip, domains in ip_cluster_map.items():
        if len(domains) > 1:
            # Find the IP node
            for node in nodes:
                if node["id"] == ip:
                    node["isCluster"] = True
                    node["val"] = 10 # Emphasize it
                    node["name"] = f"{ip} (THREAT CLUSTER: {len(domains)} DOMAINS)"
                    node["group"] = 3 # Mark IP as malicious
                    break
                
    return {"nodes": nodes, "links": links}

@app.get("/api/node-investigate")
def node_investigate(domain: str, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    ssl_info = get_ssl_cert(domain, f"https://{domain}")
    dns_info = get_dns_records(domain)
    
    log = db.query(models.DetectionLog).filter(models.DetectionLog.url.contains(domain)).order_by(models.DetectionLog.timestamp.desc()).first()
    
    log_details = None
    if log:
        log_details = {
            "status": log.status,
            "confidence": log.confidence,
            "url": log.url,
            "url_length": log.url_length,
            "num_subdomains": log.num_subdomains,
            "has_at_symbol": log.has_at_symbol,
            "suspicious_dom_elements": log.suspicious_dom_elements,
            "is_https": log.is_https,
            "logged_to_blockchain": log.logged_to_blockchain
        }
    
    return {
        "domain": domain,
        "ssl": ssl_info,
        "dns": dns_info,
        "log": log_details
    }

@app.get("/api/speedtest/ping")
def speedtest_ping(current_user: models.User = Depends(auth.get_current_user)):
    return {"status": "ok", "timestamp": time.time()}

@app.get("/api/speedtest/download")
def speedtest_download(current_user: models.User = Depends(auth.get_current_user)):
    # Return 5MB of random payload to measure speed
    def iterfile():
        chunk = os.urandom(1024 * 1024) # 1MB chunk
        for _ in range(5):
            yield chunk
    return StreamingResponse(iterfile(), media_type="application/octet-stream")

