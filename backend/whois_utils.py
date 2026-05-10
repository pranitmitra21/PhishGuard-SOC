import whois
from datetime import datetime, timezone
import redis
import os

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
        w = whois.whois(domain)
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
    redis_client.setex(cache_key, 86400, -1) # Cache failure for 1 day
    return -1
