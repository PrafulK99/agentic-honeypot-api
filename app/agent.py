def agent_decision(scam_type: str):
    return {
        "persona_used": "elderly_user",
        "conversation_strategy": "trust_then_verify"
    }

def calculate_risk(intel: dict):
    score = 0
    if intel["upi_ids"]: score += 3
    if intel["phishing_links"]: score += 3
    if intel["bank_accounts"]: score += 2
    return min(score, 10)
