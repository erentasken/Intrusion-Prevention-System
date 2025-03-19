# FROM kalilinux/kali-rolling

# WORKDIR /attacker_files

# # Install dependencies
# RUN apt update && apt install -y \
#     nmap \
#     metasploit-framework \
#     sqlmap \
#     hydra \
#     hping3 \
#     thc-ipv6 \
#     ettercap-text-only \
#     slowloris \
#     curl \
#     wget \
#     python3-pip \
#     python3-venv \
#     net-tools \
#     iproute2 \
#     dnsutils \
#     telnet \
#     iputils-ping \
#     sshpass \
#     && apt clean

# # Create a virtual environment and install Python packages
# RUN python3 -m venv /venv
# RUN /venv/bin/pip install --upgrade pip
# RUN /venv/bin/pip install scapy requests
# RUN /venv/bin/pip install paramiko



# # Start bash to keep the container running (for manual debugging)
# CMD ["/bin/bash", "-c", "tail -f /dev/null"]



# FROM alpine:latest

# WORKDIR /attacker_files

# # Add the testing repository for missing packages
# RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories

# # Install dependencies (some require testing repo)
# RUN apk add --no-cache \
#     nmap \
#     hydra \
#     curl \
#     wget \
#     python3 \
#     py3-pip \
#     net-tools \
#     iproute2 \
#     bind-tools \
#     iputils \
#     openssh \
#     hping3 \
#     sshpass

# # Install additional tools manually if available
# RUN apk add --no-cache sqlmap || true  # If available, install it

# # Create a virtual environment and install Python packages
# RUN python3 -m venv /venv
# RUN /venv/bin/pip install --upgrade pip scapy requests paramiko
# # Keep container running
# CMD ["/bin/sh", "-c", "tail -f /dev/null"]

FROM alpine:latest

WORKDIR /attacker_files

# Add the testing repository for missing packages
RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories

# Install dependencies (some require testing repo)
RUN apk add --no-cache \
    nmap \
    hydra \
    curl \
    wget \
    python3 \
    py3-pip \
    net-tools \
    iproute2 \
    bind-tools \
    iputils \
    openssh \
    hping3 \
    sshpass \
    doas  # Install doas for privilege escalation

# Configure doas to allow passwordless execution
RUN echo "permit nopass keepenv :wheel" > /etc/doas.conf

# Install additional tools manually if available
RUN apk add --no-cache sqlmap || true  # If available, install it

# Create a virtual environment and install Python packages
RUN python3 -m venv /venv
RUN /venv/bin/pip install --upgrade pip scapy requests paramiko

# Ensure the container runs as root
USER root

# Keep container running
CMD ["/bin/sh", "-c", ". /venv/bin/activate && tail -f /dev/null"]

