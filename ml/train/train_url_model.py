import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

from ml.train.load_dataset import load_url_dataset
from ml.features.url_features import extract_features

def train_model():
    # Load clean dataset
    df = load_url_dataset()

    # Feature extraction
    X = df["url"].apply(extract_features).tolist()
    y = df["label"]

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train model
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print("✅ Model trained successfully")
    print("Accuracy:", round(acc * 100, 2), "%")
    print("\nClassification Report:\n")
    print(classification_report(y_test, y_pred))

    # Save model
    joblib.dump(model, "ml/models/url_phishing_model.pkl")
    print("💾 Model saved to ml/models/url_phishing_model.pkl")

if __name__ == "__main__":
    train_model()
