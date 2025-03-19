import requests
import time

# URL of the target server
target_ip = "172.30.0.2"
target_url = f"http://{target_ip}"

# Headers to simulate a basic HTTP GET request
headers = {
    "Host": "example.com",
    "Connection": "keep-alive",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9"
}

while True:
    try:
        print("Sending GET request to target server...")
        response = requests.get(target_url, headers=headers, timeout=5)
        print(f"Response Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    
    time.sleep(12)  # Wait for 7 seconds before sending the next request
