import random
import socket
import time
import base64


# Function to generate a random string of a given size in characters
def generate_random_string(length):
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=length))


# Randomize subject and body sizes
subject_size = random.randint(10, 50)  # Random subject length between 10 and 50 characters
body_size = random.randint(100, 1000)  # Random body length between 100 and 1000 characters

# Generate random subject and body
email_subject = generate_random_string(subject_size)
email_body = generate_random_string(body_size)

# Sender and recipient email addresses
sender = "sender@container2.local"
recipient = "root@container1.local"

# Randomize sleep times between commands (between 1 and 3 seconds)
sleep1 = random.randint(1, 3)
sleep2 = random.randint(1, 3)
sleep3 = random.randint(1, 3)
sleep4 = random.randint(1, 3)

# Telnet connection parameters
target_ip = "172.30.0.2"  # Replace with your target IP
target_port = 25  # SMTP port

# Create a socket connection to the target
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to the SMTP server
    sock.connect((target_ip, target_port))

    # Read the server's greeting
    sock.recv(1024)

    # Send EHLO command
    time.sleep(sleep1)
    sock.sendall(b"EHLO localhost\r\n")
    time.sleep(sleep2)

    # Send MAIL FROM command
    sock.sendall(f"MAIL FROM:<{sender}>\r\n".encode())
    time.sleep(sleep3)

    # Send RCPT TO command
    sock.sendall(f"RCPT TO:<{recipient}>\r\n".encode())
    time.sleep(sleep4)

    # Send DATA command
    sock.sendall(b"DATA\r\n")
    time.sleep(sleep1)

    # Send subject and body
    sock.sendall(f"Subject: {email_subject}\r\n\r\n".encode())
    sock.sendall(f"{email_body}\r\n".encode())

    # End the email data
    sock.sendall(b".\r\n")
    time.sleep(sleep2)

    # Close the session
    sock.sendall(b"QUIT\r\n")
    
    # Receive final response
    sock.recv(1024)

finally:
    sock.close()

print("Email sent via telnet (SMTP) successfully.")
