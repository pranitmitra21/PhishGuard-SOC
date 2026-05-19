import whois
from datetime import datetime, timezone
import redis
import os
import concurrent.futures

WHOIS_TIMEOUT_SECONDS = 3   # Max seconds to wait for a WHOIS lookup.
                             # Tightened from 4s: most WHOIS servers respond in <1s.
                             # Falls back to domain_age=-1 (neutral) on timeout.

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

def get_domain_age_days(domain: str) -> int:
    """Returns the age of a domain in days, cached for 7 days."""
    if not domain:
        return -1
        
    cache_key = f"whois:{domain}"
    cached_age = redis_client.get(cache_key)
    
    if cached_age is not None:
        return int(cached_age)
        
    try:
        # Run the blocking WHOIS call in a thread with a hard timeout.
        # Without this, a single unresponsive WHOIS server can freeze the
        # FastAPI worker thread for 30+ seconds on every cache miss.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(whois.whois, domain)
            try:
                w = future.result(timeout=WHOIS_TIMEOUT_SECONDS)
            except concurrent.futures.TimeoutError:
                print(f"WHOIS lookup timed out for {domain} after {WHOIS_TIMEOUT_SECONDS}s")
                redis_client.setex(cache_key, 300, -1)  # Cache timeout for 5 minutes instead of 1 day
                return -1

        creation_date = w.creation_date

        # Handle cases where multiple dates are returned
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            # Normalize to UTC-aware datetime to handle both
            # timezone-aware (e.g. 2007-10-09+00:00) & naive dates from WHOIS
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days
            # Cache the successful result for 7 days (604800 seconds)
            redis_client.setex(cache_key, 604800, age_days)
            return max(0, age_days)

    except Exception as e:
        print(f"WHOIS lookup failed for {domain}: {e}")

    # If lookup fails or no creation date is found, assume age is unknown (-1)
    redis_client.setex(cache_key, 300, -1)  # Cache failure for 5 minutes instead of 1 day
    return -1
