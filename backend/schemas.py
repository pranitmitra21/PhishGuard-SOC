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
    has_password_field: Optional[bool] = False
    has_cross_origin_form: Optional[bool] = False
    num_digits: Optional[int] = 0
    num_hyphens: Optional[int] = 0
    url_entropy: Optional[float] = 0.0
    domain_age_days: Optional[int] = 180
    has_ssl_certificate: Optional[int] = 1
    missing_mx_records: Optional[int] = 0
    session_id: Optional[str] = None

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

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "User"
    wallet_id: Optional[str] = None
    admin_pin: Optional[str] = None

class UserOut(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool
    wallet_id: Optional[str] = None
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class UserUpdate(BaseModel):
    role: str
    admin_pin: Optional[str] = None
    wallet_id: Optional[str] = None

class ConfigOut(BaseModel):
    confidence_threshold_phishing: float
    confidence_threshold_suspicious: float
    enable_blockchain_logging: bool
    enable_safe_browsing: bool

class ConfigUpdate(BaseModel):
    confidence_threshold_phishing: Optional[float] = None
    confidence_threshold_suspicious: Optional[float] = None
    enable_blockchain_logging: Optional[bool] = None
    enable_safe_browsing: Optional[bool] = None
