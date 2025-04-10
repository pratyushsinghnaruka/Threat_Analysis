import warnings
warnings.filterwarnings("ignore", message="numpy.dtype size changed")

import os
import re
import traceback
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import requests

from flask import Flask, request, jsonify
from flask_cors import CORS

from scipy.sparse import hstack
import joblib

from dotenv import load_dotenv
load_dotenv()

# Load environment variables
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Set up OpenAI (v1.25.1+ syntax)
import openai
openai.api_key = OPENAI_API_KEY

# Load models
model = joblib.load("model.pkl")
vectorizer1 = joblib.load("vectorizer1.pkl")
vectorizer2 = joblib.load("vectorizer2.pkl")

# Flask setup
app = Flask(__name__)
CORS(app)

# Utility: Extract domain
def extract_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return ""

# Threat analysis route
@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        url = data.get("url", "")

        if not url:
            return jsonify({"error": "URL is required"}), 400

        domain = extract_domain(url)

        # === Google Safe Browsing ===
        google_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        google_payload = {
            "client": {
                "clientId": "yourcompanyname",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        google_response = requests.post(google_url, json=google_payload).json()
        google_result = "threat" if "matches" in google_response else "safe"

        # === VirusTotal ===
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        vt_response = requests.get(f"https://www.virustotal.com/api/v3/urls", headers=headers)
        vt_url_id = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers).json()["data"]["id"]
        vt_result_data = requests.get(f"https://www.virustotal.com/api/v3/urls/{vt_url_id}", headers=headers).json()
        positives = sum(1 for engine in vt_result_data["data"]["attributes"]["last_analysis_results"].values()
                        if engine["category"] == "malicious")
        vt_result = "threat" if positives > 0 else "safe"

        # === ML Prediction ===
        url_features = vectorizer1.transform([url])
        domain_features = vectorizer2.transform([domain])
        features = hstack([url_features, domain_features])
        prediction = model.predict(features)[0]
        ml_result = "threat" if prediction == 1 else "safe"

        # === GenAI (OpenAI) ===
        prompt = f"Analyze the following URL and tell if it looks like a phishing, malware, or suspicious website: {url}"
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5
        )
        genai_analysis = response.choices[0].message.content.strip()

        return jsonify({
            "google_result": google_result,
            "virustotal_result": vt_result,
            "ml_result": ml_result,
            "genai_analysis": genai_analysis
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)