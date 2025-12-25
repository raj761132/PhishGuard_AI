from services.org_monitor import monitor_brand

alerts = monitor_brand(
    brand_domain="paypal.com",
    brand_keywords=["paypal", "pay-pal"]
)

for alert in alerts:
    print(alert["suspicious_domain"], alert["risk_level"], alert["risk_score"])
