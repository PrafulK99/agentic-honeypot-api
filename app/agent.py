# Scam type severity weights
SCAM_TYPE_WEIGHTS = {
    "upi_refund": 3,
    "bank_verification": 3,
    "kyc_update": 2,
    "generic_scam": 2,
    "prize_lottery": 1,
}


def calculate_risk(intel: dict, scam_type: str = None) -> float:
    """
    Calculate risk score based on scam type and extracted intelligence.
    Returns a float between 0.0 and 10.0.
    """
    # Safety: handle None or empty scam_type
    if not scam_type:
        return 0.0

    risk = 0

    # Add scam type severity weight
    risk += SCAM_TYPE_WEIGHTS.get(scam_type, 2)

    # Add intelligence-based weights
    if intel.get("upi_ids"):
        risk += 3
    if intel.get("phishing_links"):
        risk += 2
    if intel.get("phone_numbers"):
        risk += 1
    if intel.get("bank_accounts"):
        risk += 2
    if intel.get("ifsc_codes"):
        risk += 2

    # Cap at 10
    return float(min(risk, 10))


def agent_decision(scam_type: str, risk_score: float) -> dict:
    """
    Determine persona and conversation strategy based on risk score.
    Returns a dict with persona_used and conversation_strategy.
    """
    risk = int(risk_score) if risk_score else 0

    if risk <= 2:
        persona = "general_user"
        strategy = "inform_and_ignore"
    elif risk <= 4:
        persona = "general_user"
        strategy = "verify_before_action"
    elif risk <= 6:
        persona = "general_user"
        strategy = "trust_then_verify"
    elif risk <= 8:
        persona = "elderly_user"
        strategy = "trust_then_verify"
    else:  # 9-10
        persona = "elderly_user"
        strategy = "block_and_report"

    return {
        "persona_used": persona,
        "conversation_strategy": strategy
    }
