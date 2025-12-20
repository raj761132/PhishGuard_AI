import whois
import tldextract
from datetime import datetime

def get_domain_age(url):
    """
    Returns domain age in days OR None if not available
    """
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"

        w = whois.whois(domain)
        creation_date = w.creation_date

        # Some WHOIS servers return list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return None

        age_days = (datetime.now() - creation_date).days
        return age_days

    except Exception:
        return None


def interpret_domain_age(age_days):
    """
    Converts raw age into human-readable risk
    """
    if age_days is None:
        return {
            "status": "UNKNOWN",
            "risk": "MEDIUM",
            "score": 0,
            "reason": "Domain registration details are hidden or unavailable"
        }

    if age_days < 30:
        return {
            "status": "VERY NEW",
            "risk": "HIGH",
            "score": -30,
            "reason": "Domain registered very recently"
        }

    if age_days < 180:
        return {
            "status": "NEW",
            "risk": "MEDIUM",
            "score": -10,
            "reason": "Domain is relatively new"
        }

    return {
        "status": "OLD",
        "risk": "LOW",
        "score": +20,
        "reason": "Domain has long registration history"
    }
