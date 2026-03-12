import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re
from tqdm import tqdm
import os

# Configuration
DATASET_PATH = r"d:\phishing_detection\merged_all_rows_dataset\merged_all_rows_dataset.csv"
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "processed_features.csv")
CHUNK_SIZE = 100000 # Read in chunks to prevent MemoryError

def extract_features(url):
    try:
        # Some URLs in dataset might not have a scheme, causing urlparse to parse incorrectly.
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
            
        parsed_url = urlparse(url)
        
        url_length = len(url)
        has_at_symbol = 1 if '@' in url else 0
        
        # Count subdomains
        domain = parsed_url.netloc
        # Simple heuristic: count dots in domain. (e.g., www.google.com -> 2 dots -> ~2 subdomains/TLD parts)
        # Minus 1 to account for the generic TLD (e.g. .com)
        num_subdomains = max(0, domain.count('.') - 1)
        
        is_https = 1 if parsed_url.scheme == 'https' else 0
        
        # Real DOM features cannot be extracted statically from a URL.
        # As agreed, we set them to 0 for the base training. 
        # The model will learn to weigh the pure URL features higher.
        num_redirects = 0 
        suspicious_dom_elements = 0
        
        return [url_length, has_at_symbol, num_subdomains, is_https, num_redirects, suspicious_dom_elements]
    
    except Exception:
        # Fallback for completely malformed URLs
        return [len(str(url)), 0, 0, 0, 0, 0]

def label_to_numeric(label):
    label = str(label).lower().strip()
    if label == 'benign' or label == 'safe':
        return 0
    elif label in ['defacement', 'malware', 'suspicious']:
        return 1
    elif label == 'phishing':
        return 2
    return 1 # Default to suspicious if unknown

def build_dataset():
    print(f"Reading dataset from {DATASET_PATH} in chunks...")
    
    # Check if dataset exists
    if not os.path.exists(DATASET_PATH):
        print("Dataset not found! Please check the path.")
        return False
        
    first_chunk = True
    total_processed = 0
    
    # Process the CSV in chunks
    for chunk in tqdm(pd.read_csv(DATASET_PATH, chunksize=CHUNK_SIZE, on_bad_lines='skip', low_memory=False)):
        
        # Clean data: drop rows with missing URLs or labels
        chunk = chunk.dropna(subset=['url', 'type'])
        
        # Extract features
        features = chunk['url'].apply(extract_features)
        
        # Create new dataframe for features
        feature_df = pd.DataFrame(features.tolist(), columns=[
            'url_length', 'has_at_symbol', 'num_subdomains', 
            'is_https', 'num_redirects', 'suspicious_dom_elements'
        ])
        
        # Map labels
        feature_df['label'] = chunk['type'].apply(label_to_numeric).values
        
        # Append to main CSV
        mode = 'w' if first_chunk else 'a'
        header = first_chunk
        feature_df.to_csv(OUTPUT_PATH, mode=mode, header=header, index=False)
        
        first_chunk = False
        total_processed += len(feature_df)
        
        # For demonstration purposes, limit to 500,000 rows so it finishes in a reasonable time
        if total_processed >= 500000:
            print("Reached 500k rows. Stopping early for performance demo.")
            break
            
    print(f"Finished extracting features for {total_processed} rows.")
    print(f"Saved processed data to {OUTPUT_PATH}")
    return True

if __name__ == "__main__":
    build_dataset()
