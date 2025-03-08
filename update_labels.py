import pandas as pd

# Load the old dataset (already labeled)
old_df = pd.read_csv("dataset.csv")

# Load the new dataset (7000+ URLs)
new_df = pd.read_csv("new_dataset.csv")

# Convert "type" to "label"
# - 1 = malicious (phishing, malware, defacement, etc.)
# - 0 = safe (benign)
malicious_types = ["phishing", "malware", "defacement"]
new_df["label"] = new_df["type"].apply(lambda x: 1 if x in malicious_types else 0)

# Drop the "type" column (we only need "url" and "label")
new_df = new_df.drop(columns=["type"])

# Merge new data with old dataset
updated_df = pd.concat([old_df, new_df], ignore_index=True)

# Remove duplicates (if any)
updated_df = updated_df.drop_duplicates(subset="url", keep="last")

# Save the updated dataset
updated_df.to_csv("dataset.csv", index=False)

print("Dataset updated successfully! Total URLs:", len(updated_df))
