import socket

# Set up the server address and port
UDP_IP = "0.0.0.0"  # Bind to all available interfaces (use a specific IP if needed)
UDP_PORT = 12345  # Choose a port (ensure this port is not in use)

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the address and port
sock.bind((UDP_IP, UDP_PORT))

# Infinite loop to keep listening for UDP packets (mock server)
while True:
    # Receive the data (buffer size set to 1024 bytes)
    data, addr = sock.recvfrom(1024)  # Receive the packet
    # Do nothing, just receive the data
    pass

