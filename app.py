import warnings
warnings.filterwarnings("ignore", message=".does not have valid feature names.")

import os
import re
import traceback
from urllib.parse import urlparse

import numpy as np
import requests
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS
from scipy.sparse import hstack
from dotenv import load_dotenv
import openai

# Load environment variables
load_dotenv()

openai.api_key = os.getenv("OPENAI_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
HF_API_KEY = os.getenv("HUGGINGFACE_API_KEY")

# Load model and vectorizer
model = joblib.load("best_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

THRESHOLD = 0.9

app = Flask(__name__)
CORS(app)

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
    res = requests.post(api_url, json=payload)
    return res.json() != {}

def check_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    if response.status_code != 200:
        return None
    analysis_id = response.json().get("data", {}).get("id")
    if not analysis_id:
        return None
    report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
    if report.status_code != 200:
        return None
    stats = report.json().get("data", {}).get("attributes", {}).get("stats", {})
    return stats.get("malicious", 0) > 0

@app.route("/")
def home():
    return "URL Threat Detector API is Live!"

@app.route("/analyze", methods=["POST"])
def analyze_url():
    try:
        data = request.get_json()
        url = data.get("url")
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        numeric_features = np.array([extract_features(url)], dtype=np.float64)
        text_features = vectorizer.transform([url])
        features_combined = hstack([numeric_features, text_features])

        malicious_prob = model.predict_proba(features_combined)[0][1]
        ai_threat = malicious_prob >= THRESHOLD

        google_threat = check_google_safe_browsing(url)
        vt_threat = check_virustotal(url)

        # Try OpenAI
        try:
            ai_response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity assistant."},
                    {"role": "user", "content": (
                        f"Analyze this URL: {url}\n\n"
                        "Please give a detailed threat assessment of the domain and page structure. "
                        "Check for signs of phishing, malware, fake logins, and suspicious patterns."
                    )}
                ]
            )
            genai_output = ai_response["choices"][0]["message"]["content"]
            genai_status = "openai_success"

        except Exception as e:
            if "quota" in str(e).lower() or "rate" in str(e).lower():
                try:
                    hf_headers = {
                        "Authorization": f"Bearer {HF_API_KEY}",
                        "Content-Type": "application/json"
                    }
                    hf_prompt = (
                        f"Analyze the following URL and give a detailed cybersecurity assessment. "
                        f"Check for phishing, malware, and fake login signs. Explain why it's suspicious if so.\n\nURL: {url}"
                    )
                    hf_response = requests.post(
                        "https://api-inference.huggingface.co/models/google/flan-t5-large",
                        headers=hf_headers,
                        json={"inputs": hf_prompt}
                    )
                    if hf_response.status_code == 200:
                        hf_result = hf_response.json()
                        genai_output = hf_result[0].get("generated_text", "").strip()
                        genai_status = "huggingface_fallback"
                    else:
                        genai_output = "GenAI analysis failed: Hugging Face API error."
                        genai_status = "huggingface_error"
                except Exception as hf_error:
                    genai_output = f"GenAI analysis failed using Hugging Face: {str(hf_error)}"
                    genai_status = "huggingface_error"
            else:
                genai_output = f"GenAI analysis failed: {str(e)}"
                genai_status = "openai_error"

        # Add clarification if high probability
        if malicious_prob >= THRESHOLD:
            genai_output = (
                f"🚨 This URL is classified as malicious with high confidence (≥ 90%).\n\n"
                + genai_output
            )

        # Adjust phrasings
        genai_output = genai_output.replace("appears to be a legitimate", "appears to be not legitimate")
        genai_output = genai_output.replace("seems to be a legitimate", "seems to be not legitimate")
        genai_output = genai_output.replace("likely a legitimate", "likely not a legitimate")

        # Clean Hugging Face fallback output
        if genai_status == "huggingface_fallback":
            genai_output = re.sub(r"(?i)malicious probability\s*[:=]\s*\d+(\.\d+)?%", "", genai_output).strip()
            genai_output = re.sub(r"(?i)genai source\s*[:=].*", "", genai_output).strip()
            genai_output = re.sub(r"(?i)this website is flagged.systems.", "", genai_output).strip()

        return jsonify({
            "url": str(url),
            "threat": bool(ai_threat),
            "malicious_probability": float(malicious_prob),
            "message": "Potentially malicious" if ai_threat else "Seems safe",
            "google_safe_browsing": bool(google_threat) if google_threat is not None else None,
            "virustotal": bool(vt_threat) if vt_threat is not None else None,
            "genai_analysis": str(genai_output),
            "genai_status": genai_status,
            "genai_source": "OpenAI" if genai_status == "openai_success" else "Hugging Face (Fallback)"
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500


if __name__ == "_main_":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)