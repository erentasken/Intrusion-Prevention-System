import requests
import time

# List of websites to send requests to
websites = [
    "https://www.example.com",
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.amazon.com",
    "https://www.reddit.com",
    "https://www.youtube.com",
    "https://www.microsoft.com",
    "https://www.linkedin.com",
    "https://www.pinterest.com",
    "https://www.netflix.com",
    "https://www.twitch.tv",
    "https://www.yelp.com",
    "https://www.bbc.com",
]

while True:

    for url in websites:
        try:
            # Send GET request
            response_get = requests.get(url)
            print(f"Sent GET request to {url}, Status Code: {response_get.status_code}")

            # Optionally, send POST request with dummy data if needed
            # response_post = requests.post(url, data={"key": "value"})
            # print(f"Sent POST request to {url}, Status Code: {response_post.status_code}")
        
        except requests.RequestException as e:
            print(f"Request failed to {url}: {e}")

    time.sleep(10)