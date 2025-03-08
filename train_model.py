import joblib
import pandas as pd
import numpy as np
import re
import time
from scipy.sparse import hstack
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
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
        int(bool(re.search(r'https?', url)))  # HTTPS presence
    ]

# ✅ Additional URL-based features
def has_ip_address(url):
    return int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))

def count_subdomains(url):
    return urlparse(url).netloc.count('.')

def domain_length(url):
    return len(urlparse(url).netloc)

# ✅ Ensure no missing values
if data.isnull().sum().sum() > 0:
    print("⚠️ Warning: Dataset contains missing values. Consider cleaning it before training.")

# ✅ Apply feature extraction
X_basic_features = np.array([extract_features(url) for url in data["url"]])
X_extra_features = np.array([
    [has_ip_address(url), count_subdomains(url), domain_length(url), 0]  # WHOIS removed
    for url in data["url"]
])

# ✅ Convert URLs into TF-IDF features
vectorizer = TfidfVectorizer(max_features=2000)  # 🔹 Reduced to avoid memory overload
X_tfidf = vectorizer.fit_transform(data["url"])  # Keep sparse format!

# ✅ Convert only non-sparse features to float64
X_basic_features = X_basic_features.astype(np.float64)
X_extra_features = X_extra_features.astype(np.float64)

# ✅ Stack features efficiently
X = hstack((X_basic_features, X_extra_features, X_tfidf))

# ✅ Debugging: Check feature shapes
print("✅ Feature extraction completed. Total features:", X.shape[1])

# ✅ Get feature names
feature_names = vectorizer.get_feature_names_out()
all_feature_names = (
    [f"basic_{i}" for i in range(X_basic_features.shape[1])] +
    [f"extra_{i}" for i in range(X_extra_features.shape[1])] +
    list(feature_names)
)

print("🚀 Starting model training on FULL dataset (641,129 samples)...")

# ✅ Extract labels
y = data["label"]

# ✅ Shuffle dataset for better generalization
X, y = shuffle(X, y, random_state=42)

# ✅ Split data (80% Train, 20% Test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ✅ Convert to DataFrame for LightGBM
X_train_df = pd.DataFrame(X_train.toarray(), columns=all_feature_names)
X_test_df = pd.DataFrame(X_test.toarray(), columns=all_feature_names)

# ✅ Train RandomForest Classifier with optimized parameters
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf_model.fit(X_train, y_train)
y_pred_rf = rf_model.predict(X_test)
acc_rf = accuracy_score(y_test, y_pred_rf)
print(f"\n🌲 RandomForest Accuracy: {acc_rf:.2%}")

# ✅ Train XGBoost Classifier with optimized settings
xgb_model = XGBClassifier(n_estimators=200, learning_rate=0.05, random_state=42, n_jobs=-1)
xgb_model.fit(X_train, y_train)
y_pred_xgb = xgb_model.predict(X_test)
acc_xgb = accuracy_score(y_test, y_pred_xgb)
print(f"🔥 XGBoost Accuracy: {acc_xgb:.2%}")

# ✅ Train LightGBM Classifier with optimizations (NO WARNINGS)
lgb_model = LGBMClassifier(n_estimators=200, learning_rate=0.05, random_state=42, 
                           force_row_wise=True, verbose=-1, n_jobs=-1)  # ✅ FIX: No warnings now
lgb_model.fit(X_train_df, y_train)
y_pred_lgb = lgb_model.predict(X_test_df)
acc_lgb = accuracy_score(y_test, y_pred_lgb)
print(f"🚀 LightGBM Accuracy: {acc_lgb:.2%}")

# ✅ Save the best model
best_model = None
best_model_name = ""
best_acc = max(acc_rf, acc_xgb, acc_lgb)

if best_acc == acc_rf:
    best_model = rf_model
    best_model_name = "RandomForest"
elif best_acc == acc_xgb:
    best_model = xgb_model
    best_model_name = "XGBoost"
else:
    best_model = lgb_model
    best_model_name = "LightGBM"

joblib.dump(best_model, "best_model.pkl")
print(f"\n🏆 Best Model: {best_model_name} (Accuracy: {best_acc:.2%}) Saved as best_model.pkl")

# ✅ Save vectorizer
joblib.dump(vectorizer, "vectorizer.pkl")
print("✅ Vectorizer saved as vectorizer.pkl.")
