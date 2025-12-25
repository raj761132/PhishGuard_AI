import pandas as pd
import re

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report


df = pd.read_csv("ml2/Phishing_Email.csv")

# Drop unnecessary column
df.drop(columns=["Unnamed: 0"], inplace=True)

# Rename columns for consistency
df.rename(columns={
    "Email Text": "email_body",
    "Email Type": "label"
}, inplace=True)

# Map labels to numeric
df["label"] = df["label"].map({
    "Safe Email": 0,
    "Phishing Email": 1
})

# Remove empty or very short emails
df = df[df["email_body"].str.len() > 20]

# Text cleaning function
def clean_text(text):
    text = text.lower()
    text = re.sub(r"http\S+", "", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

df["email_body"] = df["email_body"].apply(clean_text)

# print("Cleaned dataset shape:", df.shape)
# print(df.head())



# Split data
X = df["email_body"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# TF-IDF Vectorization
vectorizer = TfidfVectorizer(
    max_features=5000,
    stop_words="english",
    ngram_range=(1, 2)
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

# Train model
model = LogisticRegression(max_iter=1000)
model.fit(X_train_tfidf, y_train)

# Evaluate
y_pred = model.predict(X_test_tfidf)
print("\nModel Evaluation:\n")
print(classification_report(y_test, y_pred))


import joblib

joblib.dump(model, "email_phishing_model.pkl")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")

print("\nModel and vectorizer saved successfully.")


