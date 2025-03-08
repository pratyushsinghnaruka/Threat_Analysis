import requests
import json

API_KEY = "AIzaSyDP_EMegtgOGVC4uNAQ14RYfQInDW_dkLA"


def check_google_safe_browsing(url):
    payload = {
        "client": {"clientId": "your-client", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    response = requests.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}",
        json=payload
    )
    
    try:
        data = response.json()
        print("Google Safe Browsing API Response:", json.dumps(data, indent=2))  # Debugging print
        return bool(data.get("matches"))  # Returns True if matches exist, else False
    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON response from Google API")
        return False

# Test with a known malicious URL
test_url = "http://malware.testing.google.test/testing/malware/"
print(f"Checking {test_url} with Google Safe Browsing...")
result = check_google_safe_browsing(test_url)
print("Google Safe Browsing Result:", result)
