import os
import requests
from flask import Flask, request, jsonify

# Google Safe Browsing API Key (Ensure you replace it with a valid key)
GOOGLE_API_KEY = "AIzaSyDP_EMegtgOGVC4uNAQ14RYfQInDW_dkLA"

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
app = Flask(__name__)

@app.route('/', methods=['POST'])  # Ensure POST is allowed
def detect_threat():
    print("Received request data:", request.get_json())  # Debugging
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' parameter"}), 400
    
    url = data['url']
    
    if "malicious" in url:
        return jsonify({"threat": True, "message": "This URL is potentially malicious."})
    else:
        return jsonify({"threat": False, "message": "This URL seems safe."})

if __name__ == "__main__":
    app.run(debug=True)
    port = int(os.environ.get("PORT", 10000))  # Use Render's dynamic port
    app.run(host="0.0.0.0", port=port)

