import urllib.request
import zipfile
import os

URL = "https://tranco-list.eu/top-1m.csv.zip"
ZIP_PATH = os.path.join(os.path.dirname(__file__), "top-1m.csv.zip")
TXT_PATH = os.path.join(os.path.dirname(__file__), "tranco.txt")

def fetch():
    print("Downloading Tranco Top 1M list (this gives us 1,000,000 verified safe domains)...")
    try:
        req = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        with urllib.request.urlopen(req) as response, open(ZIP_PATH, 'wb') as out_file:
            out_file.write(response.read())
        print("Extracting and formatting...")
        with zipfile.ZipFile(ZIP_PATH, 'r') as z:
            filename = z.namelist()[0]
            with z.open(filename) as f, open(TXT_PATH, "w") as out:
                for line in f:
                    parts = line.decode('utf-8').strip().split(',')
                    if len(parts) == 2:
                        out.write(parts[1] + "\n")
        
        if os.path.exists(ZIP_PATH):
            os.remove(ZIP_PATH)
            
        print(f"Successfully saved 1 million safe domains to {TXT_PATH}")
    except Exception as e:
        print(f"Warning: Failed to fetch Tranco list: {e}")
        # Create an empty file so the app doesn't crash on startup if offline
        with open(TXT_PATH, "w") as out:
            pass

if __name__ == "__main__":
    fetch()
