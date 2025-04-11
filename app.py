import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import openai
from openai import OpenAI
from dotenv import load_dotenv
import requests

# Load .env
load_dotenv()

# Load API keys from environment
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

# Initialize Flask
app = Flask(__name__)
CORS(app)

# Load model and vectorizer
model = joblib.load("best_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# Set up OpenAI client (v1 syntax, no proxies)
openai_client = OpenAI(api_key=OPENAI_API_KEY)

@app.route("/")
def index():
    return "URL Threat Detection API is running!"

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Vectorize URL
    try:
        features = vectorizer.transform([url])
        prediction = model.predict(features)[0]
        confidence = max(model.predict_proba(features)[0])
    except Exception as e:
        return jsonify({"error": f"Model prediction failed: {str(e)}"}), 500

    # Google Safe Browsing
    google_threat = False
    try:
        google_res = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}",
            json={
                "client": {"clientId": "url-detector", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
        ).json()
        google_threat = "matches" in google_res
    except Exception:
        pass

    # VirusTotal check
    vt_threat = False
    try:
        headers = {"x-apikey": VT_API_KEY}
        scan_url = f"https://www.virustotal.com/api/v3/urls"
        scan_res = requests.post(scan_url, headers=headers, data={"url": url}).json()
        scan_id = scan_res["data"]["id"]

        report = requests.get(f"{scan_url}/{scan_id}", headers=headers).json()
        stats = report["data"]["attributes"]["last_analysis_stats"]
        vt_threat = stats.get("malicious", 0) > 0
    except Exception:
        pass

    # OpenAI GenAI context analysis
    try:
        prompt = f"Analyze this URL: {url}. Could it be suspicious, scammy, or malicious?"
        ai_response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity assistant."},
                {"role": "user", "content": prompt}
            ]
        )
        genai_output = ai_response.choices[0].message.content
    except Exception as e:
        genai_output = f"GenAI analysis failed: {str(e)}"

    final_threat = prediction == 1 or google_threat or vt_threat

    return jsonify({
        "url": url,
        "ai_prediction": "malicious" if prediction == 1 else "safe",
        "confidence": confidence,
        "google_threat": google_threat,
        "vt_threat": vt_threat,
        "genai_analysis": genai_output,
        "final_threat": final_threat
    })

if __name__ == "__main__":
    app.run(debug=True)
