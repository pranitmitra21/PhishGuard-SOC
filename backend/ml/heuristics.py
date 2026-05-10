import math
import re
import tldextract

# Top 20 commonly targeted brands for phishing
TOP_BRANDS = {
    "google", "microsoft", "apple", "paypal", "amazon", 
    "facebook", "instagram", "linkedin", "netflix", "whatsapp",
    "chase", "bankofamerica", "wellsfargo", "citi", "americanexpress",
    "yahoo", "outlook", "dropbox", "binance", "coinbase"
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "update", "account", "banking", 
    "wallet", "auth", "confirm", "free", "gift", "support", "service", 
    "recover", "billing", "invoice", "refund", "prize", "winner"
}

def calculate_shannon_entropy(string: str) -> float:
    """
    Calculates the Shannon Entropy of a string.
    High entropy means the string is highly random (common in DGA - Domain Generation Algorithms).
    e.g., xkqjz39d.com has high entropy. google.com has low entropy.
    """
    if not string:
        return 0.0
    entropy = 0.0
    length = len(string)
    frequencies = {}
    for char in string:
        frequencies[char] = frequencies.get(char, 0) + 1
    
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def check_typosquatting(domain: str) -> tuple[bool, str]:
    """
    Checks if a domain is typo-squatting a major brand.
    e.g., 'micros0ft' is distance 1 from 'microsoft'.
    Returns (is_typosquat, brand_mimicked)
    """
    # Exclude exact matches, those are presumably the real brands (handled by whitelist)
    for brand in TOP_BRANDS:
        if domain == brand:
            return False, ""
        
        # If the domain is within 1 or 2 character changes from a top brand, it's highly suspicious
        dist = levenshtein_distance(domain.lower(), brand.lower())
        threshold = 1 if len(brand) <= 5 else 2
        
        # Special check: substitution of o -> 0, or i -> l, l -> 1
        dist_similar = levenshtein_distance(
            domain.lower().replace('0', 'o').replace('1', 'l').replace('!','i'), 
            brand.lower()
        )
        
        if dist <= threshold or dist_similar == 0:
            return True, brand
            
    return False, ""

def analyze_url_heuristics(url: str) -> dict:
    """
    Runs advanced lexical analysis on the URL.
    Returns a dictionary of heuristic risks.
    """
    extract = tldextract.extract(url)
    domain = extract.domain
    subdomain = extract.subdomain
    
    # 1. Entropy Check
    # Combine subdomain + domain for entropy calculation on the host
    host_entropy = calculate_shannon_entropy(f"{subdomain}{domain}")
    
    # 2. Typosquatting
    # Attackers often put the brand in the subdomain (e.g., paypal.secure-login.com) or domain
    is_typosquat, brand = check_typosquatting(domain)
    subdomain_has_brand = False
    
    for top_brand in TOP_BRANDS:
        if top_brand in subdomain.lower():
            subdomain_has_brand = True
            brand = top_brand
            break
    
    # 3. Suspicious Keyword Density
    lower_url = url.lower()
    keyword_matches = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]
    
    # Aggregating risks
    risk_score = 0.0
    reasons = []
    
    if host_entropy > 4.0:
        risk_score += 20.0
        reasons.append(f"High hostname entropy ({host_entropy:.2f})")
        
    if is_typosquat:
        risk_score += 40.0
        reasons.append(f"Typosquatting detected (mimicking '{brand}')")
        
    if subdomain_has_brand:
        risk_score += 35.0
        reasons.append(f"Brand name '{brand}' used deceptively in subdomain")
        
    if len(keyword_matches) >= 2:
        risk_score += 10.0 * len(keyword_matches)
        reasons.append(f"Suspicious keywords found: {', '.join(keyword_matches)}")

    return {
        "heuristic_risk_score": min(risk_score, 100.0),
        "reasons": reasons,
        "entropy": host_entropy,
        "is_typosquat": is_typosquat or subdomain_has_brand
    }
