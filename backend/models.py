from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class DetectionLog(Base):
    __tablename__ = "detection_logs"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    url_hash = Column(String, index=True)
    status = Column(String) # Safe, Suspicious, Phishing
    confidence = Column(Float)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    logged_to_blockchain = Column(Boolean, default=False)
    url_length = Column(Integer, default=0)
    has_at_symbol = Column(Boolean, default=False)
    num_subdomains = Column(Integer, default=0)
    is_https = Column(Boolean, default=True)
    suspicious_dom_elements = Column(Integer, default=0)
    session_id = Column(String, index=True, nullable=True)
    user_id = Column(Integer, index=True, nullable=True)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="User") # User, Analyst, Admin
    wallet_id = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)

class SystemConfig(Base):
    __tablename__ = "system_config"

    id = Column(Integer, primary_key=True, index=True)
    confidence_threshold_phishing = Column(Float, default=80.0)
    confidence_threshold_suspicious = Column(Float, default=40.0)
    enable_blockchain_logging = Column(Boolean, default=True)
    enable_safe_browsing = Column(Boolean, default=True)
