import os
import joblib
import requests
import openai
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup Flask app
app = Flask(__name__)
CORS(app)

# Load ML model and vectorizer
model = joblib.load("best_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# API Keys
openai.api_key = os.getenv("OPENAI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

# Safe Browsing API URL
SAFE_BROWSING_API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

# Helper: Google Safe Browsing
def check_google_safe_browsing(url):
    payload = {
        "client": {
            "clientId": GOOGLE_CLIENT_ID,
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(SAFE_BROWSING_API_URL, json=payload)
        if response.status_code == 200:
            result = response.json()
            return bool(result.get("matches"))
    except Exception as e:
        print("Google Safe Browsing Error:", e)
    return False

# Helper: VirusTotal
def check_virustotal(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls", headers=headers, params={"url": url})
        if response.status_code == 200:
            scan_id = response.json()["data"]["id"]
            result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
            if result.status_code == 200:
                analysis = result.json()
                stats = analysis["data"]["attributes"]["stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                return malicious > 0 or suspicious > 0
    except Exception as e:
        print("VirusTotal Error:", e)
    return False

# Helper: GenAI
def analyze_url_with_genai(url):
    prompt = f"Analyze the following URL and determine if it's likely to be safe or malicious. Be honest and cautious:\n\n{url}"
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            temperature=0.2,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert."},
                {"role": "user", "content": prompt}
            ]
        )
        result = response['choices'][0]['message']['content'].strip()
        return result
    except Exception as e:
        print("OpenAI Error:", e)
        return analyze_url_with_huggingface(url)

# Fallback: Hugging Face Mistral
def analyze_url_with_huggingface(url):
    hf_token = os.getenv("HF_TOKEN")
    endpoint = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.1"
    headers = {"Authorization": f"Bearer {hf_token}"}
    payload = {"inputs": f"Analyze this URL for safety: {url}"}
    try:
        response = requests.post(endpoint, headers=headers, json=payload, timeout=10)
        if response.status_code == 200:
            output = response.json()
            return output[0]["generated_text"].strip()
    except Exception as e:
        print("Hugging Face Error:", e)
    return "Unable to analyze URL using GenAI."

# Main route
@app.route("/analyze", methods=["POST"])
def analyze_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "Missing URL"}), 400

    # ML prediction
    features = vectorizer.transform([url])
    prediction = model.predict(features)[0]
    probability = round(model.predict_proba(features)[0][1] * 100, 2)
    in_dataset = bool(prediction)

    # Google + VT
    google_threat = check_google_safe_browsing(url)
    vt_threat = check_virustotal(url)
    external_threat = google_threat or vt_threat

    # GenAI
    genai_text = analyze_url_with_genai(url)

    # Check for vague GenAI
    vague_keywords = [
        "appears to be legitimate",
        "always be cautious",
        "verify the authenticity",
        "check before clicking",
        "important to be cautious",
        "general advice",
        "phishing techniques",
        "always practice caution",
        "safety cannot be guaranteed"
    ]
    vague_genai = any(k in genai_text.lower() for k in vague_keywords) or len(genai_text) < 200
    genai_flagged = probability > 90 and vague_genai

    # Final decision
    is_threat = in_dataset or external_threat or genai_flagged

    return jsonify({
        "url": url,
        "message": "Threat analysis complete.",
        "threat": is_threat,
        "dataset": in_dataset,
        "malicious_probability": probability,
        "genai_analysis": genai_text,
        "genai_flagged": genai_flagged
    })

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
