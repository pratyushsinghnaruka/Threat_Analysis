import pandas as pd

# ✅ Load the dataset
df = pd.read_csv("balanced_dataset.csv")  # Make sure this is the correct dataset file

# ✅ Count the number of malicious (1) vs benign (0) URLs
label_counts = df["label"].value_counts()

# ✅ Print the results
print("Class Distribution in Training Data:")
print(label_counts)

# ✅ Calculate percentage distribution
total = len(df)
print(f"\nPercentage Distribution:")
for label, count in label_counts.items():
    print(f"Label {label}: {count} URLs ({(count / total) * 100:.2f}%)")

# ✅ Optional: Visualize the distribution using a bar chart (requires matplotlib)
import matplotlib.pyplot as plt

plt.bar(label_counts.index.astype(str), label_counts.values, color=["blue", "red"])
plt.xlabel("Label (0 = Benign, 1 = Malicious)")
plt.ylabel("Number of URLs")
plt.title("Training Dataset Class Distribution")
plt.show()
