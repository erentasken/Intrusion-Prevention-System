#!/bin/bash

TARGET_IP="172.30.0.2"

echo "[*] Scanning open ports..."
nmap -p- -sV $TARGET_IP
