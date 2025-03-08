import os
import traceback
import requests
from flask import Flask, request, jsonify
import joblib  # For loading AI model
import re
from urllib.parse import urlparse

# Load API keys from environment variables
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "AIzaSyDP_EMegtgOGVC4uNAQ14RYfQInDW_dkLA")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "5c1eb7234408454a3ab51f758cc421b9d8a90816134a5b16b652cade4a2ad95c")

# Load AI Model & Vectorizer (Ensure 'vectorizer.pkl' and 'model.pkl' exist)
vectorizer = joblib.load("vectorizer.pkl")
model = joblib.load("model.pkl")

app = Flask(__name__)

# Function to extract numerical features from URL
def extract_features(url):
    """Extract numerical features from the given URL"""
    features = []
    
    # 1. URL Length
    features.append(len(url))
    
    # 2. Count of dots in URL
    features.append(url.count('.'))
    
    # 3. Count of slashes in URL
    features.append(url.count('/'))
    
    # 4. Count of hyphens in URL
    features.append(url.count('-'))
    
    # 5. Count of @ symbols
    features.append(url.count('@'))
    
    # 6. Count of question marks
    features.append(url.count('?'))
    
    # 7. Count of equals signs
    features.append(url.count('='))
    
    # 8. Count of digits in URL
    features.append(sum(c.isdigit() for c in url))
    
    # 9. Count of letters in URL
    features.append(sum(c.isalpha() for c in url))
    
    # 10. Number of unique characters
    features.append(len(set(url)))

    # 11. Whether it uses HTTPS (1 = Yes, 0 = No)
    features.append(1 if url.startswith("https") else 0)
    
    # 12. URL depth (count of `/` in path)
    parsed_url = urlparse(url)
    features.append(parsed_url.path.count('/'))
    
    # 13. Count of subdomains (by counting dots in netloc)
    features.append(parsed_url.netloc.count('.'))
    
    # 14. Length of domain name
    features.append(len(parsed_url.netloc))
    
    # 15. Length of top-level domain (TLD) (e.g., `.com`, `.org`)
    tld = parsed_url.netloc.split('.')[-1]
    features.append(len(tld))
    
    # 16. Is there an IP address in URL? (1 = Yes, 0 = No)
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)
    
    # 17. Is there a `www` in URL? (1 = Yes, 0 = No)
    features.append(1 if 'www' in url else 0)
    
    # 18. Is there a port number? (1 = Yes, 0 = No)
    features.append(1 if ':' in parsed_url.netloc else 0)
    
    # 19. Is there a redirection (`//`) in URL? (1 = Yes, 0 = No)
    features.append(1 if '//' in parsed_url.path else 0)
    
    # 20. Is there a hexadecimal character (like `%20`) in URL? (1 = Yes, 0 = No)
    features.append(1 if re.search(r'%[0-9A-Fa-f]{2}', url) else 0)

    # 21. Is there a sensitive keyword like `secure`, `bank`, `account`? (1 = Yes, 0 = No)
    sensitive_words = ["secure", "account", "bank", "login", "password"]
    features.append(1 if any(word in url.lower() for word in sensitive_words) else 0)

    # 22. Count of suspicious words (like `free`, `click`, `earn`)
    suspicious_words = ["free", "click", "win", "money", "earn", "bonus"]
    features.append(sum(url.lower().count(word) for word in suspicious_words))

    # 23. Does it contain `.exe`, `.zip`, `.rar`? (1 = Yes, 0 = No)
    risky_extensions = [".exe", ".zip", ".rar"]
    features.append(1 if any(url.lower().endswith(ext) for ext in risky_extensions) else 0)

    # 24. Total number of special characters (`-`, `_`, `=`, etc.)
    special_chars = "-_@?=/.%&"
    features.append(sum(url.count(c) for c in special_chars))

    print(f"Extracted Features ({len(features)}):", features)  # ✅ Debugging output
    return features

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
    
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )
    
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
    return data.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0) > 0

@app.route('/check_url', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        print("Received data:", data)  

        if not data or "url" not in data:
            return jsonify({"error": "Invalid input"}), 400
        
        url = data["url"]
        print("Checking URL:", url)  

        # Extract features
        features = extract_features(url)
        features_vectorized = [features]  

        # AI Model Prediction
        ai_prediction = model.predict(features_vectorized)[0]

        print("Feature shape:", len(features))  
        print("Transformed features:", features)  

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

    except Exception as e:
        print("🔥 ERROR:", str(e))
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  
    app.run(host="0.0.0.0", port=port, debug=True)
