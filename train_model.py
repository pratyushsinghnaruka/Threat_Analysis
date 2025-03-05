import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import pickle
import re

# Load dataset
data = pd.read_csv("dataset.csv")

# Function to extract URL features
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

# Apply feature extraction
X_features = np.array([extract_features(url) for url in data["url"]])

# Convert text URLs into TF-IDF features
vectorizer = TfidfVectorizer()
X_tfidf = vectorizer.fit_transform(data["url"]).toarray()

# Combine both feature sets
X = np.hstack((X_features, X_tfidf))
y = data["label"]

# Train a better model
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X, y)

# Save the improved model
pickle.dump((vectorizer, model), open("model.pkl", "wb"))
print("✅ Improved model trained and saved as model.pkl")

