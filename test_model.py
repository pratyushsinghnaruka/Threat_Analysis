import joblib
import numpy as np
import pandas as pd
import re

# ✅ Load vectorizer and trained model
vectorizer = joblib.load("vectorizer.pkl")
model = joblib.load("best_model.pkl")  # Ensure correct model filename

# ✅ Feature extraction functions
def extract_basic_features(url):
    return [
        len(url),  # URL length
        url.count('.'),  # Number of dots
        url.count('-'),  # Number of hyphens
        url.count('@'),  # Number of '@' symbols
        url.count('?'),  # Number of query parameters
        url.count('='),  # Number of '=' in URL
        int(bool(re.search(r'https?', url)))  # HTTPS presence
    ]

# ✅ New function to extract extra features (must match training script)
def extract_extra_features(url):
    return [
        sum(c.isdigit() for c in url),  # Number of digits
        sum(c.isalpha() for c in url),  # Number of letters
        url.count('/'),  # Number of slashes
        url.count('_')  # Number of underscores
    ]

# ✅ Process a single test URL
test_url = "http://malicious-site.com"

basic_features = np.array([extract_basic_features(test_url)])
extra_features = np.array([extract_extra_features(test_url)])  # 🔥 Missing features added
tfidf_features = vectorizer.transform([test_url]).toarray()

# 🔍 Debug feature counts
print(f"Basic Features Shape: {basic_features.shape}")  # Should be (1, 7)
print(f"Extra Features Shape: {extra_features.shape}")  # Should be (1, 4)
print(f"TF-IDF Features Shape: {tfidf_features.shape}")  # Should be (1, 2000)

# ✅ Ensure the feature count matches training
features = np.hstack((basic_features, extra_features, tfidf_features))
print(f"Final Feature Shape (Should be 2011): {features.shape[1]}")

# Ensure correct feature count before prediction
if features.shape[1] != 2011:
    raise ValueError(f"Feature count mismatch! Got {features.shape[1]}, expected 2011.")

# Make prediction
prediction = model.predict(features)[0]
print(f"🔍 Single URL: {test_url}")
print(f"Model Prediction: {prediction}\n")

# ✅ Process a CSV dataset if available
try:
    df = pd.read_csv("balanced_dataset.csv")
    print(f"✅ Loaded {len(df)} URLs from balanced_dataset.csv")

    # Extract features for all URLs
    X_basic = np.array([extract_basic_features(url) for url in df["url"]])
    X_extra = np.array([extract_extra_features(url) for url in df["url"]])  # 🔥 Missing features added
    X_tfidf = vectorizer.transform(df["url"]).toarray()

    # Debug shape check
    print(f"Dataset Basic Features Shape: {X_basic.shape}")
    print(f"Dataset Extra Features Shape: {X_extra.shape}")
    print(f"Dataset TF-IDF Features Shape: {X_tfidf.shape}")

    # Ensure feature count matches training
    X = np.hstack((X_basic, X_extra, X_tfidf))
    print(f"Final Dataset Feature Shape (Should be 2011): {X.shape[1]}")

    # Ensure feature count matches before prediction
    if X.shape[1] != 2011:
        raise ValueError(f"Feature count mismatch! Got {X.shape[1]}, expected 2011.")

    # Make predictions
    df["label"] = model.predict(X)

    # Save results
    df[["url", "label"]].to_csv("labeled_dataset.csv", index=False)
    print("✅ Classification completed! Results saved in labeled_dataset.csv")
except FileNotFoundError:
    print("⚠️ Warning: balanced_dataset.csv not found. Skipping dataset processing.")
