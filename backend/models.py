from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class DetectionLog(Base):
    __tablename__ = "detection_logs"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    url_hash = Column(String, unique=True, index=True)
    status = Column(String) # Safe, Suspicious, Phishing
    confidence = Column(Float)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    logged_to_blockchain = Column(Boolean, default=False)
    url_length = Column(Integer, default=0)
    has_at_symbol = Column(Boolean, default=False)
    num_subdomains = Column(Integer, default=0)
    is_https = Column(Boolean, default=True)
    suspicious_dom_elements = Column(Integer, default=0)
