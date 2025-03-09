import warnings
import pandas as pd
import numpy as np
from scipy.sparse import hstack
from sklearn.metrics import classification_report
import joblib
from urllib.parse import urlparse
import re

# Suppress specific warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

# Load the model and vectorizer
model = joblib.load("best_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# Load your validation dataset
data = pd.read_csv("balanced_dataset.csv")  # Replace with your validation dataset
X = data["url"]  # Features (URLs)
y = data["label"]  # Labels (0 for safe, 1 for malicious)

# Function to extract numerical features
def extract_features(url):
    """
    Extract numerical features from a URL.
    """
    # Parse the URL
    parsed_url = urlparse(url)
    
    # Extract features
    features = [
        len(url),  # URL length
        url.count('.'),  # Number of dots
        url.count('-'),  # Number of hyphens
        url.count('@'),  # Number of '@' symbols
        url.count('?'),  # Number of query parameters
        url.count('='),  # Number of '=' in URL
        int(bool(re.search(r'https?', url))),  # HTTPS presence (use raw string for regex)
        int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))),  # IP Address presence (use raw string for regex)
        parsed_url.netloc.count('.'),  # Subdomain count
        len(parsed_url.netloc)  # Domain length
    ]
    
    return features

# Extract features
X_features = np.array([extract_features(url) for url in X], dtype=np.float64)  # Use np.float64 instead of np.float

# Vectorize URLs
X_vectorized = vectorizer.transform(X)

# Combine features
X_combined = hstack([X_features, X_vectorized])

# Evaluate the model
y_pred = model.predict(X_combined)
print(classification_report(y, y_pred))