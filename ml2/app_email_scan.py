from flask import Flask, request, jsonify
import joblib
import re
import os

app = Flask(__name__)

# Load model and vectorizer
base_dir = os.path.dirname(__file__)
model = joblib.load(os.path.join(base_dir, "email_phishing_model.pkl"))
vectorizer = joblib.load(os.path.join(base_dir, "tfidf_vectorizer.pkl"))

def clean_text(text):
    if isinstance(text, str):
        text = text.lower()
        text = re.sub(r"http\S+", "", text)
        text = re.sub(r"[^a-z\s]", " ", text)
        return text
    return ""

# 👇 New route for browser preview
@app.route("/", methods=["GET"])
def home():
    return "<h2>PhishGuard Email Scanner is running!</h2><p>Use POST /scan-email with JSON to test.</p>"

@app.route("/scan-email", methods=["POST"])
def scan_email():
    data = request.json or {}

    email_body = clean_text(data.get("email_body", ""))

    # Only use TF-IDF features
    text_vec = vectorizer.transform([email_body])

    score = model.predict_proba(text_vec)[0][1] * 100
    risk_level = "High" if score > 70 else "Medium" if score > 40 else "Low"

    # Print to terminal for debugging
    print(f"Risk Score: {score:.2f} | Level: {risk_level}")

    return jsonify({
        "email_risk_score": round(score, 2),
        "risk_level": risk_level
    })

if __name__ == "__main__":
    app.run(debug=True)