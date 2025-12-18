import joblib
from ml.features.url_features import extract_features

# Load trained model
model = joblib.load("ml/models/url_phishing_model.pkl")

def predict_url(url):
    features = extract_features(url)
    prediction = model.predict([features])[0]
    probability = model.predict_proba([features])[0]

    result = {
        "url": url,
        "prediction": "Phishing" if prediction == 1 else "Legitimate",
        "confidence": round(max(probability) * 100, 2)
    }

    return result


if __name__ == "__main__":
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://online0mgeving.ga/triodos/",
        "https://paypal.com",
        "http://secure-login-paypal.verify-user.com/login"
    ]

    for url in test_urls:
        print(predict_url(url))
