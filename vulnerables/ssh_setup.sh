#!/bin/bash

# Update and install OpenSSH server
apt-get update && apt-get install -y openssh-server  

# Set root password (Change this for security!)
echo 'root:password' | chpasswd  

# Allow root login and enable password authentication
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config  

# Restart SSH service to apply changes
service ssh restart  

# Keep container running with SSH server
exec /usr/sbin/sshd -D
