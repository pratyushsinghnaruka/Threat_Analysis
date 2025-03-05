import requests

api_url = "https://threats-detection.onrender.com"  # Change this if API is deployed online
test_data = {"url": "http://malicious-site.com"}

response = requests.post(api_url, json=test_data)
print("Response:", response.json())