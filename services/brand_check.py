import re
import tldextract
from urllib.parse import urlparse

# You can extend this list anytime
BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "google": ["google.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "rbi": ["rbi.org.in"],
    "sbi": ["sbi.co.in"],
}


def detect_brand_impersonation(url):
    """
    Detects brand impersonation attempts in a URL
    """
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)

        full_domain = f"{ext.domain}.{ext.suffix}".lower()
        url_text = url.lower()

        detected_brands = []

        for brand, official_domains in BRAND_DOMAINS.items():
            # Brand name appears in URL text
            if brand in url_text:
                # Check if current domain is official
                if full_domain not in official_domains:
                    detected_brands.append({
                        "brand": brand.capitalize(),
                        "official_domains": official_domains,
                        "current_domain": full_domain
                    })

        if detected_brands:
            return {
                "impersonation": True,
                "brands": detected_brands,
                "risk": "HIGH",
                "reason": "Brand name found in URL but domain is not official"
            }

        return {
            "impersonation": False,
            "risk": "LOW",
            "reason": "No brand impersonation detected"
        }

    except Exception:
        return {
            "impersonation": False,
            "risk": "UNKNOWN",
            "reason": "Brand detection failed"
        }
