import pandas as pd

# 🔹 Load Dataset (Modify the file name if needed)
data = pd.read_csv("balanced_dataset.csv")  # Change this to your actual dataset file

# ✅ Check the Distribution of Safe vs. Malicious URLs
print("🔍 Safe URLs:", data[data["label"] == 0].shape[0])
print("🔍 Malicious URLs:", data[data["label"] == 1].shape[0])

# 🚨 If Imbalance is Found, Print a Warning
safe_count = data[data["label"] == 0].shape[0]
malicious_count = data[data["label"] == 1].shape[0]

if abs(safe_count - malicious_count) > 0.1 * max(safe_count, malicious_count):  # If imbalance is >10%
    print("⚠️ WARNING: Dataset is imbalanced! Consider collecting more data.")
