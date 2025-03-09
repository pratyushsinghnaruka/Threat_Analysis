import warnings
warnings.filterwarnings("ignore", message=".*does not have valid feature names.*")

import pandas as pd
import numpy as np
import os
import requests
import traceback
from flask import Flask, request, jsonify
import joblib  # For loading AI model
import re
from scipy.sparse import hstack
from urllib.parse import urlparse
import warnings

# Suppress specific warning for feature names
warnings.filterwarnings("ignore", message=".*does not have valid feature names.*")

# Load API keys from environment variables (can be replaced with actual keys if not using env variables)
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "AIzaSyDP_EMegtgOGVC4uNAQ14RYfQInDW_dkLA")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "5c1eb7234408454a3ab51f758cc421b9d8a90816134a5b16b652cade4a2ad95c")

# Load the trained model and vectorizer
model = joblib.load("best_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")  # Load vectorizer

# Initialize Flask app
app = Flask(__name__)

# Set a threshold for the AI model (adjust this value to control sensitivity)
THRESHOLD = 0.9  # URLs with a malicious probability >= 0.5 will be flagged as malicious

# Function to extract numerical features (same as when the model was trained)
def extract_features(url):
    """
    Extract numerical features from a URL.
    """
    parsed_url = urlparse(url)
    return [
        len(url),  # URL length
        url.count('.'),  # Number of dots
        url.count('-'),  # Number of hyphens
        url.count('@'),  # Number of '@' symbols
        url.count('?'),  # Number of query parameters
        url.count('='),  # Number of '=' in URL
        int(bool(re.search(r'https?', url))),  # HTTPS presence
        int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))),  # IP Address presence
        parsed_url.netloc.count('.'),  # Subdomain count
        len(parsed_url.netloc)  # Domain length
    ]

# Google Safe Browsing API Check
def check_google_safe_browsing(url):
    """
    Check if a URL is flagged by Google Safe Browsing.
    """
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
    payload = {
        "client": {"clientId": "your-client-id", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    response = requests.post(api_url, json=payload)
    return response.json() != {}  # Returns True if the URL is flagged as malicious

# VirusTotal API Check
def check_virustotal(url):
    """
    Check if a URL is flagged by VirusTotal.
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})

    if response.status_code != 200:
        return None  # API request failed

    analysis_id = response.json().get("data", {}).get("id")
    if not analysis_id:
        return None  # No analysis ID found

    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    report_response = requests.get(report_url, headers=headers)

    if report_response.status_code != 200:
        return None  # Failed to fetch report

    data = report_response.json()
    malicious_count = data.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0)
    return malicious_count > 0  # Returns True if the URL is flagged as malicious

@app.route('/check_url', methods=['POST'])
def check_url():
    """
    Endpoint to check if a URL is malicious using the AI model, Google Safe Browsing, and VirusTotal.
    """
    try:
        data = request.get_json()
        print("📩 Received Data:", data)  # Logs the data received in the request

        if not data or "url" not in data:
            print("🚨 ERROR: Missing 'url' key in request")
            return jsonify({"error": "Invalid input"}), 400

        url = data["url"]
        print("🌍 Checking URL:", url)  # Logs the URL you are checking

        # Extract numeric features
        numeric_features = np.array([extract_features(url)], dtype=np.float64)
        print("🔢 Numeric Features:", numeric_features)  # Logs numeric features

        # Vectorize the URL text
        url_vectorized = vectorizer.transform([url])
        print("🔠 Vectorized URL Shape:", url_vectorized.shape)  # Logs vectorized URL shape
        print("🔠 Vectorized URL Data:", url_vectorized.toarray())  # Logs vectorized URL data

        # Combine numeric and vectorized features
        features_combined = hstack([numeric_features, url_vectorized])
        print("🛠 Combined Features Shape:", features_combined.shape)  # Logs combined feature shape
        print("🛠 Combined Features Data:", features_combined.toarray())  # Logs combined feature data

        # AI Model Prediction with Probability
        malicious_probability = model.predict_proba(features_combined)[0][1]  # Probability of being malicious
        print("🤖 AI Model Malicious Probability:", malicious_probability)

        # Apply threshold to determine if the URL is malicious
        ai_prediction = malicious_probability >= THRESHOLD
        print("🤖 AI Model Prediction (with threshold):", ai_prediction)

        # Add Google Safe Browsing and VirusTotal Checks
        google_safe = check_google_safe_browsing(url)
        virustotal_threat = check_virustotal(url)

        return jsonify({
            "url": url,
            "threat": bool(ai_prediction),
            "malicious_probability": float(malicious_probability),  # Include probability in response
            "message": "Potentially malicious" if ai_prediction else "Seems safe",
            "google_safe_browsing": google_safe,
            "virustotal": virustotal_threat
        })

    except Exception as e:
        print("🔥 ERROR:", str(e))  # Logs the error message
        traceback.print_exc()  # Print the full traceback
        return jsonify({"error": "Internal Server Error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)