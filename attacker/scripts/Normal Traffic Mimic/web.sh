#!/bin/bash

# URL of the target server
TARGET_IP="172.30.0.2"
TARGET_URL="http://$TARGET_IP"

# Simulate a basic HTTP GET request and show response headers
curl -i -X GET "$TARGET_URL" \
  -H "Host: example.com" \
  -H "Connection: keep-alive" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" \
  -H "Accept: text/html" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -o response.html

