import joblib
import numpy as np
from scipy.sparse import hstack
from urllib.parse import urlparse
import re
import sys
import warnings

# Suppress warnings (like the ones from LGBM and sklearn)
warnings.filterwarnings("ignore", category=UserWarning)

# ✅ Load Model, Vectorizer, and Expected Feature Count
try:
    model = joblib.load("best_model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
    expected_features = len(joblib.load("feature_names.pkl"))  # ✅ Get the count of expected features
    print("✅ Model, vectorizer, and feature count loaded successfully.")
except Exception as e:
    print(f"❌ ERROR: Failed to load necessary files - {e}")
    sys.exit(1)

# ✅ Extract Features (SAME as train_model.py)
def extract_features(url):
    return [
        len(url),  # URL length
        url.count('.'),  # Number of dots
        url.count('-'),  # Number of hyphens
        url.count('@'),  # Number of '@' symbols
        url.count('?'),  # Number of query parameters
        url.count('='),  # Number of '=' in URL
        int(bool(re.search(r'https?', url))),  # HTTPS presence
        int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),  # IP Address presence
        urlparse(url).netloc.count('.'),  # Subdomain count
        len(urlparse(url).netloc)  # Domain length
    ]

def predict_url(url):
    print(f"🌍 Checking URL: {url}")

    # ✅ Extract numeric features
    numeric_features = np.array([extract_features(url)], dtype=np.float64)

    # ✅ Transform URL with the trained TF-IDF vectorizer
    tfidf_features = vectorizer.transform([url])

    # ✅ Debugging: Check individual feature shapes
    print(f"🔢 Numeric Features Shape: {numeric_features.shape}")
    print(f"📊 TF-IDF Features Shape: {tfidf_features.shape}")

    # ✅ Combine features
    features_vectorized = hstack((numeric_features, tfidf_features))

    # ✅ Debugging: Check the combined feature shape
    actual_features = features_vectorized.shape[1]
    print(f"✅ Model Expects Features: {expected_features}")
    print(f"✅ Your Features Shape: {actual_features}")

    # 🚨 Feature Mismatch Check
    if actual_features != expected_features:
        print(f"🔥 ERROR: Feature mismatch detected!")

        # Print exact difference (expected_features is now an integer)
        print(f"🔍 Difference: {actual_features - expected_features}")

        # Debug Feature Matrix
        print(f"🔍 Numeric Features Count: {numeric_features.shape[1]}")
        print(f"🔍 TF-IDF Features Count: {tfidf_features.shape[1]}")
        return None  # Stop execution if there's a mismatch

    # ✅ AI Model Prediction
    prediction_prob = model.predict_proba(features_vectorized)[0][1]  # Probability of being malicious

    threshold = 0.9  # Adjust for sensitivity

    if prediction_prob > threshold:
        print(f"🚨 Malicious! (Confidence: {prediction_prob:.2f})")
        return True
    else:
        print(f"✅ Safe. (Confidence: {prediction_prob:.2f})")
        return False

# ✅ Run Prediction from Command Line
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("❌ ERROR: Please provide a URL to check.")
        sys.exit(1)

    predict_url(sys.argv[1])
