import joblib
import pandas as pd
import numpy as np
import re
import time
from scipy.sparse import hstack
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.utils import shuffle

# ✅ Load dataset
try:
    data = pd.read_csv("balanced_dataset.csv")
    print(f"✅ balanced_dataset loaded successfully. Total samples: {len(data)}")
except FileNotFoundError:
    print("❌ Error: balanced_dataset.csv not found. Please check the file location.")
    exit()

# ✅ Function to extract URL-based features
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

# ✅ Apply feature extraction
X_basic_features = np.array([extract_features(url) for url in data["url"]], dtype=np.float64)

# ✅ Convert URLs into TF-IDF features
vectorizer = TfidfVectorizer(max_features=2000)
X_tfidf = vectorizer.fit_transform(data["url"])

# ✅ Combine features
X = hstack((X_basic_features, X_tfidf))

# ✅ Save feature count
num_features = X.shape[1]
joblib.dump(num_features, "num_features.pkl")  # ✅ Save expected feature count

# ✅ Extract labels
y = data["label"]

# ✅ Shuffle dataset for better generalization
X, y = shuffle(X, y, random_state=42)

# ✅ Split data (80% Train, 20% Test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ✅ Train LightGBM Classifier
lgb_model = LGBMClassifier(n_estimators=200, learning_rate=0.05, random_state=42, 
                           force_row_wise=True, verbose=-1, n_jobs=-1)
lgb_model.fit(X_train, y_train)
y_pred_lgb = lgb_model.predict(X_test)
acc_lgb = accuracy_score(y_test, y_pred_lgb)
print(f"🚀 LightGBM Accuracy: {acc_lgb:.2%}")

# ✅ Save the best model
joblib.dump(lgb_model, "best_model.pkl")
print(f"🏆 Best Model Saved as best_model.pkl")

# ✅ Save vectorizer
joblib.dump(vectorizer, "vectorizer.pkl")
print("✅ Vectorizer saved as vectorizer.pkl.")
