import joblib
import numpy as np
import re
import sys
from scipy.sparse import hstack
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer

# ✅ Load the trained model and vectorizer
try:
    model = joblib.load("best_model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
    print("✅ Model and vectorizer loaded successfully.")
except FileNotFoundError:
    print("❌ Error: Model or vectorizer file not found. Please train the model first.")
    sys.exit()

# ✅ Function to extract URL-based features
def extract_features(url):
    return [
        len(url),  # URL length
        url.count('.'),  # Number of dots
        url.count('-'),  # Number of hyphens
        url.count('@'),  # Number of '@' symbols
        url.count('?'),  # Number of query parameters
        url.count('='),  # Number of '=' in URL
        int(bool(re.search(r'https?', url)))  # HTTPS presence
    ]

def has_ip_address(url):
    return int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))

def count_subdomains(url):
    return urlparse(url).netloc.count('.')

def domain_length(url):
    return len(urlparse(url).netloc)

# ✅ Predict function
def predict_url(url):
    basic_features = np.array([extract_features(url)])
    extra_features = np.array([[has_ip_address(url), count_subdomains(url), domain_length(url), 0]])
    
    # Convert URL to TF-IDF features
    tfidf_features = vectorizer.transform([url])
    
    # Stack features
    X = hstack((basic_features, extra_features, tfidf_features))
    
    # Make prediction
    prediction = model.predict(X)[0]
    
    # Output result
    if prediction == 1:
        print(f"🚨 Malicious URL detected: {url}")
    else:
        print(f"✅ Safe URL: {url}")

# ✅ Run script from command line
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python predict.py <URL>")
        sys.exit()
    
    test_url = sys.argv[1]
    predict_url(test_url)
