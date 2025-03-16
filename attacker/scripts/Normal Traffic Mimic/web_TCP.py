import requests

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

# Perform the GET request
response = requests.get(target_url, headers=headers)

# Print response headers and content
print(f"Response Headers:\n{response.headers}\n")
print(f"Response Content:\n{response.text}")

# Save the response content to a file
with open("response.html", "w") as file:
    file.write(response.text)
