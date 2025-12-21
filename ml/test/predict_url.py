# ml/test/predict_url.py

import joblib
from ml.features.url_features import extract_url_features

MODEL_PATH = "ml/models/url_phishing_model.pkl"

model = joblib.load(MODEL_PATH)

def predict_url(url: str):
    features = extract_url_features(url)

    prediction = model.predict([features])[0]
    probability = model.predict_proba([features])[0]

    confidence = max(probability) * 100

    return {
        "prediction": int(prediction),
        "confidence": round(confidence, 2)
    }

# Optional CLI testing
if __name__ == "__main__":
    url = input("Enter URL: ")
    print(predict_url(url))
