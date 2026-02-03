from fastapi import FastAPI, Depends
from fastapi.exceptions import HTTPException, RequestValidationError
from app.schemas import HoneypotRequest, HoneypotResponse, ExtractedIntelligence
from app.auth import verify_api_key
from app.detector import detect_scam
from app.extractor import extract_intelligence
from app.agent import agent_decision, calculate_risk
from app.errors import (
    http_exception_handler,
    validation_exception_handler,
    generic_exception_handler,
)

app = FastAPI(title="Agentic Honeypot API")

# Register global exception handlers
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)


# Constants for input safety
MAX_MESSAGE_LENGTH = 5000


@app.post("/api/honeypot/analyze", response_model=HoneypotResponse)
def analyze_message(
    payload: HoneypotRequest,
    api_key: str = Depends(verify_api_key)
):
    # === Input Safety Guards ===
    # Ensure message is a string and normalize whitespace
    raw_message = payload.message if isinstance(payload.message, str) else ""
    message = raw_message.strip()

    # Handle empty or whitespace-only messages
    if not message:
        return {
            "scam_detected": False,
            "confidence": 0.1,
            "message": "No scam indicators detected",
            "status": "success"
        }

    # Handle excessively long messages (truncate safely)
    if len(message) > MAX_MESSAGE_LENGTH:
        message = message[:MAX_MESSAGE_LENGTH]

    # === Core Analysis ===
    detection = detect_scam(message)

    # 🟢 If NOT a scam → return early
    if not detection.get("is_scam"):
        return {
            "scam_detected": False,
            "confidence": detection.get("confidence", 0.1),
            "message": "No scam indicators detected",
            "status": "success"
        }

    # 🔴 Scam detected → extract intelligence
    scam_type = detection.get("scam_type")
    intel = extract_intelligence(message)
    risk = calculate_risk(intel, scam_type)
    agent_meta = agent_decision(scam_type, risk)

    return {
        "scam_detected": True,
        "scam_type": detection.get("scam_type"),
        "confidence": detection.get("confidence"),
        "extracted_intelligence": intel,
        "agent_metadata": agent_meta,
        "risk_score": risk,
        "status": "success"
    }
