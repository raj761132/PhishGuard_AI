import re
import tldextract
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "bank", "confirm", "signin", "reset", "password"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd"
]

def analyze_url(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain

    findings = []
    score = 0

    #URL length
    if len(url) > 75:
        findings.append("Long URL length")
        score += 10

    #Too many subdomains
    if subdomain.count('.') >= 2:
        findings.append("Multiple subdomains detected")
        score += 15

    #Hyphens in domain
    if "-" in domain:
        findings.append("Hyphen in domain name")
        score += 10

    #Digits in domain
    if re.search(r"\d", domain):
        findings.append("Digits in domain name")
        score += 10

    #Suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            findings.append(f"Suspicious keyword detected: '{keyword}'")
            score += 10
            break

    #IP address instead of domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.hostname or ""):
        findings.append("IP address used instead of domain")
        score += 25

    #URL shortener
    if any(short in url for short in URL_SHORTENERS):
        findings.append("URL shortening service used")
        score += 20

    # Risk interpretation
    if score >= 40:
        risk = "HIGH"
    elif score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "risk": risk,
        "score": score,
        "findings": findings if findings else ["No suspicious patterns detected"]
    }
