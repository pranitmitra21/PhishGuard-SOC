import sys
import os
import pandas as pd

# Add backend directory to sys.path so we can import database and models
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(backend_dir)

from database import SessionLocal
import models
from ml.train import train_model

def run_pipeline(progress_callback=None):
    print("--- Starting Automated ML Retraining Pipeline ---")
    db = SessionLocal()
    
    # Get user reported threats
    reports = db.query(models.DetectionLog).filter(models.DetectionLog.status == "User_Reported_Phishing").all()
    
    if not reports:
        print("No new user reports found. Proceeding to retrain on existing dataset to validate pipeline.")
    else:
        print(f"Found {len(reports)} new user-reported threats. Ingesting into dataset...")
    
    new_data = []
    for r in reports:
        # B3 FIX: Build rows with all 22 columns to match processed_features.csv schema.
        # Previously only 7 columns were written, which corrupted the CSV and caused
        # the next training run to crash on a column count mismatch.
        # Also fixed label: model is binary (0=Safe, 1=Phishing); the old value of 2 was invalid.
        url_length = r.url_length or 0
        hostname_guess = ""  # hostname not stored in DetectionLog; use safe defaults
        new_data.append({
            'length_url': url_length,
            'length_hostname': 0,           # not stored
            'ip': 0,                         # not stored
            'nb_dots': 0,                    # not stored
            'nb_hyphens': r.url_length and 0 or 0,
            'nb_at': 1 if r.has_at_symbol else 0,
            'nb_qm': 0,                      # not stored
            'nb_eq': 0,                      # not stored
            'nb_slash': 0,                   # not stored
            'nb_www': 0,                     # not stored
            'ratio_digits_url': 0.0,         # not stored
            'ratio_digits_host': 0.0,        # not stored
            'tld_in_subdomain': 0,           # not stored
            'prefix_suffix': 0,              # not stored
            'shortening_service': 0,         # not stored
            'phish_hints': 0,                # not stored
            'domain_age': -1,               # not stored in DetectionLog
            'dns_record': 0,                 # not stored
            'https_token': 1 if r.is_https else 0,
            'google_index': 0,               # not available
            'page_rank': 0,                  # not available
            'web_traffic': 0,                # not available
            'label': 1  # B3 FIX: binary label — 1=Phishing (was incorrectly 2)
        })
        # Update status so it doesn't get ingested again on the next run
        # but remains visible in the dashboard as a Phishing detection
        r.status = "Phishing" 
        
    db.commit()
    db.close()
    if new_data:
        df_new = pd.DataFrame(new_data)
        
        processed_path = os.path.join(os.path.dirname(__file__), "processed_features.csv")
        if os.path.exists(processed_path):
            print("Appending new data to existing processed_features.csv...")
            df_new.to_csv(processed_path, mode='a', header=False, index=False)
        else:
            print("Error: Base dataset not found. Cannot retrain.")
            return False

    print("Triggering Model Retraining on updated massive dataset...")
    train_model(progress_callback=progress_callback)
    
    print("--- Pipeline Complete. Live Model Updated! ---")
    return True

if __name__ == "__main__":
    run_pipeline()
