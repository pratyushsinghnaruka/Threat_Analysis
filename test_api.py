import requests

api_url = "http://127.0.0.1:5000/check_url"  # Change to match your server

test_data = {"url": "https://urlhaus.abuse.ch/url/3465119/"}

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
