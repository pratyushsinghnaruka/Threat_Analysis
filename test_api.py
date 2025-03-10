import requests

api_url = "https://threats-analysis.onrender.com/check_url"  # Change to match your server

test_data = {"url": "http://malicious-site.com"}

try:
    response = requests.post(api_url, json=test_data, timeout=5)
    print("Status Code:", response.status_code)

    # If response is empty, print error message
    if not response.text:
        print("Error: Empty response from server")
    else:
        print("Raw Response:", response.text)
        print("Parsed JSON:", response.json())

except requests.exceptions.RequestException as e:
    print("Error connecting to API:", e)
