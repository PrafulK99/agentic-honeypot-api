import re

def extract_intelligence(message: str):
    return {
        "upi_ids": re.findall(r"\b[\w.-]+@[\w.-]+\b", message),
        "phishing_links": re.findall(r"https?://\S+", message),
        "phone_numbers": re.findall(r"\b\d{10}\b", message),
        "bank_accounts": re.findall(r"\b\d{9,18}\b", message),
        "ifsc_codes": re.findall(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", message)
    }
