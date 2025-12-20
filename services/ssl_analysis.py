import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

def get_ssl_info(url):
    """
    Returns SSL certificate details or None if SSL not available
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return None

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        issued_on = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        expires_on = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

        issuer = dict(x[0] for x in cert['issuer'])
        issuer_name = issuer.get('organizationName', 'Unknown')

        age_days = (datetime.now() - issued_on).days
        validity_days = (expires_on - issued_on).days

        return {
            "issuer": issuer_name,
            "issued_on": issued_on.date().isoformat(),
            "expires_on": expires_on.date().isoformat(),
            "certificate_age_days": age_days,
            "validity_days": validity_days,
            "is_valid": age_days >= 0
        }

    except Exception:
        return None


TRUSTED_ISSUERS = [
    "Google Trust Services",
    "DigiCert",
    "GlobalSign",
    "Cloudflare",
    "Amazon",
    "Microsoft"
]

def interpret_ssl_info(ssl_info):
    if ssl_info is None:
        return {
            "status": "NO SSL",
            "risk": "HIGH",
            "score": -40,
            "reason": "No valid SSL certificate found"
        }

    age = ssl_info["certificate_age_days"]
    issuer = ssl_info["issuer"]

    # 🔹 Trusted issuer logic (VERY IMPORTANT)
    if any(trusted.lower() in issuer.lower() for trusted in TRUSTED_ISSUERS):
        return {
            "status": "TRUSTED ISSUER",
            "risk": "LOW",
            "score": +25,
            "reason": f"SSL issued by trusted authority ({issuer})"
        }

    # 🔹 Untrusted issuer logic
    if age < 30:
        return {
            "status": "NEW CERTIFICATE",
            "risk": "HIGH",
            "score": -25,
            "reason": "SSL certificate issued very recently by untrusted authority"
        }

    if age < 180:
        return {
            "status": "RECENT CERTIFICATE",
            "risk": "MEDIUM",
            "score": -10,
            "reason": "SSL certificate is relatively new"
        }

    return {
        "status": "ESTABLISHED SSL",
        "risk": "LOW",
        "score": +15,
        "reason": "SSL certificate has a long and stable history"
    }
