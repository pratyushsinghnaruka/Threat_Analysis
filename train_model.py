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
import sys

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
X_basic_features = np.array([extract_features(url) for url in data["url"]])

# ✅ Convert URLs into TF-IDF features
vectorizer = TfidfVectorizer(max_features=2000)
X_tfidf = vectorizer.fit_transform(data["url"])

# ✅ Debugging: Check the shapes of the individual features
print(f"🔢 Numeric Features Shape: {X_basic_features.shape}")
print(f"📊 TF-IDF Features Shape: {X_tfidf.shape}")

# ✅ Convert only non-sparse features to float64
X_basic_features = X_basic_features.astype(np.float64)

# ✅ Stack features efficiently
X = hstack((X_basic_features, X_tfidf))

# ✅ Debugging: Check the combined feature shape
print(f"🛠 Final Combined Features Shape: {X.shape}")

# ✅ Get feature names for LightGBM
all_feature_names = (
    ["url_length", "num_dots", "num_hyphens", "num_at", "num_question", 
     "num_equals", "https_presence", "ip_presence", "subdomain_count", "domain_length"] 
    + vectorizer.get_feature_names_out().tolist()
)

# ✅ Debugging: Print the total number of features
print("✅ Feature extraction completed. Total features:", X.shape[1])

# ✅ Extract labels
y = data["label"]

# ✅ Shuffle dataset for better generalization
X, y = shuffle(X, y, random_state=42)

# ✅ Split data (80% Train, 20% Test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ✅ Convert to DataFrame for LightGBM
X_train_df = pd.DataFrame(X_train.toarray(), columns=all_feature_names)
X_test_df = pd.DataFrame(X_test.toarray(), columns=all_feature_names)

# ✅ Train XGBoost Classifier
xgb_model = XGBClassifier(n_estimators=200, learning_rate=0.05, random_state=42, n_jobs=-1)
xgb_model.fit(X_train, y_train)
y_pred_xgb = xgb_model.predict(X_test)
acc_xgb = accuracy_score(y_test, y_pred_xgb)
print(f"🔥 XGBoost Accuracy: {acc_xgb:.2%}")

# ✅ Train LightGBM Classifier (WITH feature names)
lgb_model = LGBMClassifier(n_estimators=200, learning_rate=0.05, random_state=42, 
                           force_row_wise=True, verbose=-1, n_jobs=-1)
lgb_model.fit(X_train_df, y_train)  # ✅ Now trained with feature names
y_pred_lgb = lgb_model.predict(X_test_df)
acc_lgb = accuracy_score(y_test, y_pred_lgb)
print(f"🚀 LightGBM Accuracy: {acc_lgb:.2%}")

# ✅ Save the best model
best_model = xgb_model if acc_xgb > acc_lgb else lgb_model
joblib.dump(best_model, "best_model.pkl")
print(f"🏆 Best Model Saved as best_model.pkl")

# ✅ Save vectorizer
joblib.dump(vectorizer, "vectorizer.pkl")
print("✅ Vectorizer saved as vectorizer.pkl.")

# ✅ Save feature names
joblib.dump(all_feature_names, "feature_names.pkl")
print("✅ Feature names saved as feature_names.pkl.")
