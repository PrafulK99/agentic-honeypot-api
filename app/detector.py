SCAM_KEYWORDS = [
    "refund", "upi", "verify", "kyc", "urgent",
    "account blocked", "click link"
]

def detect_scam(message: str):
    message_lower = message.lower()
    hits = [k for k in SCAM_KEYWORDS if k in message_lower]

    if hits:
        return {
            "is_scam": True,
            "scam_type": "generic_scam",
            "confidence": min(0.9, 0.5 + 0.1 * len(hits))
        }

    return {
        "is_scam": False,
        "confidence": 0.1
    }
