import joblib

from services.url_analysis import analyze_url
from services.ssl_analysis import get_ssl_info, interpret_ssl_info
from services.ip_info import get_ip_info
from services.brand_check import detect_brand_impersonation


# 🔹 Load trained ML model (adjust path if needed)
ML_MODEL_PATH = "ml/models/url_phishing_model.pkl"
ml_model = joblib.load(ML_MODEL_PATH)


def ml_predict(url):
    """
    Predict phishing using trained ML model.
    Assumes your ML pipeline handles feature extraction internally.
    """
    try:
        prediction = ml_model.predict([url])[0]
        proba = ml_model.predict_proba([url])[0]
        confidence = max(proba) * 100

        return {
            "prediction": "PHISHING" if prediction == 1 else "LEGITIMATE",
            "confidence": round(confidence, 2)
        }
    except Exception:
        return {
            "prediction": "UNKNOWN",
            "confidence": 0
        }


def final_verdict(url):
    """
    Combines ML + rule-based analysis into a final decision
    """

    report = {
        "url": url,
        "signals": [],
        "score": 0
    }

    # 🔹 1. ML Prediction
    ml_result = ml_predict(url)
    report["ml"] = ml_result

    if ml_result["prediction"] == "PHISHING":
        report["score"] += 30
        report["signals"].append(
            f"ML model predicts phishing ({ml_result['confidence']}%)"
        )

    # 🔹 2. URL Structural Analysis
    url_result = analyze_url(url)
    report["url_analysis"] = url_result
    
    if "URL shortening service used" in url_result["findings"]:
        report["score"] += 15

    elif url_result["risk"] == "HIGH":
        report["score"] += 25
        report["signals"].extend(url_result["findings"])

    elif url_result["risk"] == "MEDIUM":
        report["score"] += 10
        report["signals"].extend(url_result["findings"])

    # 🔹 3. Brand Impersonation
    brand_result = detect_brand_impersonation(url)
    report["brand"] = brand_result

    if brand_result["impersonation"]:
        report["score"] += 35
        report["signals"].append("Brand impersonation detected")

    # 🔹 4. SSL Analysis
    ssl_info = get_ssl_info(url)
    ssl_result = interpret_ssl_info(ssl_info)
    report["ssl"] = ssl_result

    if ssl_result["risk"] == "HIGH":
        report["score"] += 25
        report["signals"].append(ssl_result["reason"])

    elif ssl_result["risk"] == "MEDIUM":
        report["score"] += 10
        report["signals"].append(ssl_result["reason"])

    # 🔹 5. IP & Hosting
    ip_info = get_ip_info(url)
    report["ip"] = ip_info

    if ip_info is None:
        report["score"] += 10
        report["signals"].append("Unverified or hidden hosting environment")

    # 🔹 FINAL DECISION
    if report["score"] >= 60:
       verdict = "PHISHING"
       risk = "HIGH"
    elif report["score"] >= 20:
       verdict = "SUSPICIOUS"
       risk = "MEDIUM"
    else:
       verdict = "LEGITIMATE"
       risk = "LOW"

    report["final_verdict"] = verdict
    report["risk_level"] = risk

    return report
