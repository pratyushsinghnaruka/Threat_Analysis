import joblib

vectorizer = joblib.load("vectorizer.pkl")
print("Vectorizer feature count:", len(vectorizer.get_feature_names_out()))
