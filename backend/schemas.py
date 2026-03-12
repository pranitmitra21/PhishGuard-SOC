from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class URLFeatures(BaseModel):
    url: str
    url_length: int
    has_at_symbol: bool
    num_subdomains: int
    is_https: bool
    num_redirects: int
    suspicious_dom_elements: int

class DetectionResponse(BaseModel):
    url: str
    status: str
    confidence: float
    logged_to_blockchain: bool
    features: Optional[dict] = None

class LogOut(BaseModel):
    id: int
    url: str
    url_hash: str
    status: str
    confidence: float
    timestamp: datetime
    logged_to_blockchain: bool
    url_length: int
    has_at_symbol: bool
    num_subdomains: int
    is_https: bool
    suspicious_dom_elements: int

    class Config:
        from_attributes = True
