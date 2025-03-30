import socket

UDP_IP = "172.30.0.2"  # Bind to all available interfaces (use a specific IP if needed)
UDP_PORT = 12345  # Choose a port (ensure this port is not in use)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024)  # Receive the packet
    pass
