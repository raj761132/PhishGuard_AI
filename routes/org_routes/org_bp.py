from flask import Blueprint, request, jsonify
import datetime

from services.org_monitor import monitor_brand
from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

client = MongoClient(os.getenv("MONGO_URI"))

db = client.phishguard

alerts_col = db.org_alerts
authority_col = db.authority_reports

# =========================
# Blueprint
# =========================
org_bp = Blueprint("org", __name__)

# =========================
# Start Monitoring
# =========================

@org_bp.route("/org/monitor/start", methods=["POST"])
def start_monitoring():
    data = request.get_json(force=True, silent=True)

    if not data:
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    brand_domain = data.get("brand_domain")
    brand_keywords = data.get("brand_keywords", [])
    org_id = data.get("org_id")

    if not brand_domain or not org_id:
        return jsonify({"error": "brand_domain and org_id required"}), 400

    alerts = monitor_brand(brand_domain, brand_keywords)

    for alert in alerts:
        alert["org_id"] = org_id
        alert["status"] = "PENDING"
        alert["created_at"] = datetime.datetime.utcnow()
        alerts_col.insert_one(alert)

    return jsonify({
        "message": "Monitoring completed",
        "alerts_detected": len(alerts)
    })


# =========================
# Get Org Alerts
# =========================
@org_bp.route("/org/alerts", methods=["GET"])
def get_org_alerts():
    org_id = request.args.get("org_id")

    if not org_id:
        return jsonify({"error": "org_id required"}), 400

    alerts = list(
        alerts_col.find(
            {"org_id": org_id},
            {"_id": 0}
        )
    )

    return jsonify(alerts)


# =========================
# Review Alert
# =========================
@org_bp.route("/org/alerts/review", methods=["POST"])
def review_alert():
    data = request.json

    domain = data.get("suspicious_domain")
    status = data.get("status")  # CONFIRMED / FALSE

    if not domain or status not in ["CONFIRMED", "FALSE"]:
        return jsonify({"error": "Invalid input"}), 400

    alerts_col.update_one(
        {"suspicious_domain": domain},
        {"$set": {"status": status}}
    )

    return jsonify({"message": "Alert updated"})


# =========================
# Escalate to Authority
# =========================
@org_bp.route("/org/alerts/escalate", methods=["POST"])
def escalate_to_authority():
    data = request.json
    domain = data.get("suspicious_domain")

    if not domain:
        return jsonify({"error": "suspicious_domain required"}), 400

    alert = alerts_col.find_one(
        {"suspicious_domain": domain},
        {"_id": 0}
    )

    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    authority_col.insert_one({
        **alert,
        "reported_at": datetime.datetime.utcnow(),
        "authority_status": "UNDER_REVIEW"
    })

    alerts_col.update_one(
        {"suspicious_domain": domain},
        {"$set": {"status": "REPORTED"}}
    )

    return jsonify({"message": "Escalated to authority"})
