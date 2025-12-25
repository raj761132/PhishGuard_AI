from flask import Flask, request, jsonify
import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

# -----------------------------
# 1. Load and prepare dataset
# -----------------------------
df = pd.read_csv("ml2/Phishing_Email.csv", encoding="latin-1")

# Clean dataset
df.drop(columns=["Unnamed: 0"], inplace=True)
df.rename(columns={
    "Email Text": "email_body",
    "Email Type": "label"
}, inplace=True)

df["label"] = df["label"].map({
    "Safe Email": 0,
    "Phishing Email": 1
})

df = df[df["email_body"].str.len() > 20]

def clean_text(text):
    if isinstance(text, str):
        text = text.lower()
        text = re.sub(r"http\S+", "", text)
        text = re.sub(r"[^a-z\s]", " ", text)
        return text
    return ""

df["email_body"] = df["email_body"].apply(clean_text)

# -----------------------------
# 2. Train model in memory
# -----------------------------
X = df["email_body"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

vectorizer = TfidfVectorizer(
    max_features=5000,
    stop_words="english",
    ngram_range=(1, 2)
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = LogisticRegression(max_iter=1000)
model.fit(X_train_vec, y_train)

print("Model trained and ready!")

# -----------------------------
# 3. Flask API
# -----------------------------
@app.route("/", methods=["GET"])
def home():
    return "<h2>PhishGuard Email Scanner is running!</h2><p>Use POST /scan-email with JSON to test.</p>"

@app.route("/scan-email", methods=["POST"])
def scan_email():
    data = request.json or {}
    email_body = clean_text(data.get("email_body", ""))

    text_vec = vectorizer.transform([email_body])
    score = model.predict_proba(text_vec)[0][1] * 100
    risk_level = "High" if score > 70 else "Medium" if score > 40 else "Low"

    print(f"Risk Score: {score:.2f} | Level: {risk_level}")

    return jsonify({
        "email_risk_score": round(score, 2),
        "risk_level": risk_level
    })

if __name__ == "__main__":
    app.run(debug=True)