import re

# Approved regex patterns
UPI_PATTERN = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")
URL_PATTERN = re.compile(r"https?://[^\s]+")
PHONE_PATTERN = re.compile(r"\b(?:\+91)?[6-9]\d{9}\b")
BANK_ACCOUNT_PATTERN = re.compile(r"\b\d{9,18}\b")
IFSC_PATTERN = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")


def _is_repeated_digits(value: str) -> bool:
    """Check if value is all repeated digits (e.g., 1111111111)."""
    return len(set(value)) == 1


def extract_intelligence(message: str) -> dict:
    """
    Extract structured scam intelligence from a message.
    Always returns a dict with all five keys, each containing a list.
    """
    # Safety: ensure message is a string
    if not isinstance(message, str):
        message = ""

    # Extract raw matches
    raw_upi = UPI_PATTERN.findall(message)
    raw_urls = URL_PATTERN.findall(message)
    raw_phones = PHONE_PATTERN.findall(message)
    raw_banks = BANK_ACCOUNT_PATTERN.findall(message)
    raw_ifsc = IFSC_PATTERN.findall(message.upper())

    # Normalize phone numbers (remove spaces, dedupe)
    phones = []
    phone_digits_set = set()
    for p in raw_phones:
        cleaned = p.replace(" ", "").replace("+91", "")
        if not _is_repeated_digits(cleaned) and cleaned not in phone_digits_set:
            phone_digits_set.add(cleaned)
            phones.append(cleaned)

    # Filter bank accounts: exclude phone numbers and repeated-digit junk
    banks = []
    seen_banks = set()
    for b in raw_banks:
        b = b.strip()
        # Length must be 9-18 digits
        if not (9 <= len(b) <= 18):
            continue
        # Exclude if it matches a phone number
        if b in phone_digits_set or b[-10:] in phone_digits_set:
            continue
        # Exclude repeated-digit junk
        if _is_repeated_digits(b):
            continue
        if b not in seen_banks:
            seen_banks.add(b)
            banks.append(b)

    return {
        "upi_ids": list(dict.fromkeys(v.strip() for v in raw_upi)),
        "phishing_links": list(dict.fromkeys(v.strip() for v in raw_urls)),
        "phone_numbers": phones,
        "bank_accounts": banks,
        "ifsc_codes": list(dict.fromkeys(v.strip().upper() for v in raw_ifsc))
    }
