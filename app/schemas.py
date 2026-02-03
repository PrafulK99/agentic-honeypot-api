from pydantic import BaseModel
from typing import List, Optional

class HoneypotRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None

class ExtractedIntelligence(BaseModel):
    upi_ids: List[str] = []
    bank_accounts: List[str] = []
    ifsc_codes: List[str] = []
    phishing_links: List[str] = []
    phone_numbers: List[str] = []

class HoneypotResponse(BaseModel):
    scam_detected: bool
    confidence: float
    scam_type: Optional[str] = None
    extracted_intelligence: Optional[ExtractedIntelligence] = None
    risk_score: Optional[float] = None
    agent_metadata: Optional[dict] = None
    message: Optional[str] = None
    status: str
