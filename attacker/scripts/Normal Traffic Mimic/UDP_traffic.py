import socket
import time
import random

# Target IP and Port
UDP_IP = "172.30.0.2"  # Target DNS Server IP
UDP_PORT = 53          # DNS uses UDP port 53

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Simulated DNS query names
domains = [
    "google.com",
    "example.com",
    "facebook.com",
    "github.com",
    "amazon.com",
    "netflix.com",
    "openai.com"
]

while True:
    domain = random.choice(domains)  # Pick a random domain
    query = (
        b'\xaa\xaa'  # Transaction ID
        + b'\x01\x00'  # Standard query
        + b'\x00\x01'  # One question
        + b'\x00\x00'  # No answer RRs
        + b'\x00\x00'  # No authority RRs
        + b'\x00\x00'  # No additional RRs
    )

    for part in domain.split("."):
        query += bytes([len(part)]) + part.encode()
    query += b'\x00'  # End of domain name
    query += b'\x00\x01'  # Type: A (IPv4)
    query += b'\x00\x01'  # Class: IN (Internet)
    
    print(f"Sending to {domain}")
    sock.sendto(query, (UDP_IP, UDP_PORT))
    
    print("sleeping...")
    time.sleep(12)
