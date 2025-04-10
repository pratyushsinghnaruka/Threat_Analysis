import warnings
warnings.filterwarnings("ignore", message=".does not have valid feature names.")

import pandas as pd
import numpy as np
import os
import requests
import traceback
from flask import Flask, request, jsonify
import joblib
import re
from scipy.sparse import hstack
from urllib.parse import urlparse
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Load API keys securely from environment
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize OpenAI client with the new format
client = OpenAI(api_key=OPENAI_API_KEY)

# Load trained model and vectorizer
model = joblib.load("best_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

app = Flask(__name__)
THRESHOLD = 0.9  # AI sensitivity threshold

# Feature extraction function
def extract_features(url):
    parsed_url = urlparse(url)
    return [
        len(url),
        url.count('.'),
        url.count('-'),
        url.count('@'),
        url.count('?'),
        url.count('='),
        int(bool(re.search(r'https?', url))),
        int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))),
        parsed_url.netloc.count('.'),
        len(parsed_url.netloc)
    ]

# Google Safe Browsing check
def check_google_safe_browsing(url):
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
    return response.json() != {}

# VirusTotal API check
def check_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    if response.status_code != 200:
        return None
    analysis_id = response.json().get("data", {}).get("id")
    if not analysis_id:
        return None
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    report_response = requests.get(report_url, headers=headers)
    if report_response.status_code != 200:
        return None
    data = report_response.json()
    malicious_count = data.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0)
    return malicious_count > 0

# OpenAI GenAI analysis using new format
def analyze_with_genai(url):
    try:
        prompt = (
            f"Analyze the following URL for signs of phishing, malware, or suspicious behavior:\n\n{url}\n\n"
            f"Give a short 2-3 line analysis."
        )
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=100,
            temperature=0.3
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print("⚠ OpenAI GenAI Error:", e)
        return "GenAI analysis not available."

# Main API route
@app.route('/check_url', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        print("📩 Received Data:", data)

        if not data or "url" not in data:
            print("🚨 ERROR: Missing 'url' key in request")
            return jsonify({"error": "Invalid input"}), 400

        url = data["url"]
        print("🌍 Checking URL:", url)

        numeric_features = np.array([extract_features(url)], dtype=np.float64)
        url_vectorized = vectorizer.transform([url])
        features_combined = hstack([numeric_features, url_vectorized])
        malicious_probability = model.predict_proba(features_combined)[0][1]
        ai_prediction = malicious_probability >= THRESHOLD

        google_safe = check_google_safe_browsing(url)
        virustotal_threat = check_virustotal(url)
        genai_analysis = analyze_with_genai(url)

        return jsonify({
            "url": url,
            "threat": bool(ai_prediction),
            "malicious_probability": float(malicious_probability),
            "message": "Potentially malicious" if ai_prediction else "Seems safe",
            "google_safe_browsing": google_safe,
            "virustotal": virustotal_threat,
            "genai_analysis": genai_analysis
        })

    except Exception as e:
        print("🔥 ERROR:", str(e))
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
