"""
Organization Brand Monitoring Service
Uses existing final_verdict pipeline
"""

from services.final_verdict import final_verdict


def generate_suspicious_domains(brand_domain, brand_keywords):
    """
    Simple domain mutation logic for hackathon demo
    """
    base = brand_domain.replace("https://", "").replace("http://", "").replace("www.", "")
    base_name = base.split(".")[0]

    variations = set()

    for kw in brand_keywords:
        variations.add(f"{kw}-login.com")
        variations.add(f"{kw}-secure.com")
        variations.add(f"{kw}-verify.com")
        variations.add(f"{kw}-account.com")
        variations.add(f"{kw}-support.com")

    # Simple typosquatting
    variations.add(base_name.replace("a", "4") + ".com")
    variations.add(base_name.replace("o", "0") + ".com")
    variations.add(base_name.replace("l", "1") + ".com")

    return list(variations)


def monitor_brand(brand_domain, brand_keywords):
    """
    Core function for Organization Dashboard
    """

    alerts = []

    suspicious_domains = generate_suspicious_domains(
        brand_domain, brand_keywords
    )

    for domain in suspicious_domains:
        url = f"https://{domain}"

        # 🔹 Run your EXISTING full pipeline
        report = final_verdict(url)

        # Only keep meaningful threats
        if report["risk_level"] in ["HIGH", "MEDIUM"]:
            alerts.append({
                "brand_domain": brand_domain,
                "suspicious_domain": domain,
                "final_verdict": report["final_verdict"],
                "risk_level": report["risk_level"],
                "risk_score": report["score"],
                "ml_prediction": report["ml"]["prediction"],
                "ml_confidence": report["ml"]["confidence"],
                "evidence": report["signals"],
                "full_report": report
            })

    return alerts
