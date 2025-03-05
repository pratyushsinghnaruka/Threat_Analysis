import os
import requests
from flask import Flask, request, jsonify
import joblib  # For loading AI model

# Load API keys from environment variables
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "AIzaSyDP_EMegtgOGVC4uNAQ14RYfQInDW_dkLA")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "5c1eb7234408454a3ab51f758cc421b9d8a90816134a5b16b652cade4a2ad95c")

# Load AI Model & Vectorizer (Ensure 'vectorizer.pkl' and 'model.pkl' exist)
vectorizer = joblib.load("vectorizer.pkl")
model = joblib.load("model.pkl")

app = Flask(__name__)

# Function to check Google Safe Browsing
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
    return response.json() != {}  # Returns True if URL is a threat

# Function to check VirusTotal
def check_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    # Step 1: Submit URL to VirusTotal
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )
    
    if response.status_code != 200:
        return None  # Error handling
    
    # Extract analysis ID
    analysis_id = response.json().get("data", {}).get("id")
    if not analysis_id:
        return None

    # Step 2: Retrieve analysis report
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    report_response = requests.get(report_url, headers=headers)
    
    if report_response.status_code != 200:
        return None

    data = report_response.json()
    return data.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0) > 0

@app.route("/check_url", methods=["POST"])  # Unified endpoint
def check_url():
    data = request.get_json()
    
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' parameter"}), 400
    
    url = data["url"]

    # AI Model Prediction
    features = vectorizer.transform([url])
    ai_prediction = model.predict(features)[0]

    # External API Checks
    google_threat = check_google_safe_browsing(url)
    vt_threat = check_virustotal(url)

    # Final Decision
    is_threat = bool(ai_prediction) or google_threat or vt_threat

    return jsonify({
        "threat": is_threat,
        "ai_model_prediction": bool(ai_prediction),
        "google_safe_browsing": google_threat,
        "virustotal": vt_threat,
        "message": "Potentially malicious" if is_threat else "Seems safe"
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Render's assigned port
    app.run(host="0.0.0.0", port=port, debug=True)  # Bind to 0.0.0.0
