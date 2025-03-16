FROM kalilinux/kali-rolling

WORKDIR /attacker_files

# Install dependencies
RUN apt update && apt install -y \
    nmap \
    metasploit-framework \
    sqlmap \
    hydra \
    hping3 \
    thc-ipv6 \
    ettercap-text-only \
    slowloris \
    curl \
    wget \
    python3-pip \
    python3-venv \
    net-tools \
    iproute2 \
    dnsutils \
    telnet \
    iputils-ping \
    sshpass \
    && apt clean

# Create a virtual environment and install Python packages
RUN python3 -m venv /venv
RUN /venv/bin/pip install --upgrade pip
RUN /venv/bin/pip install scapy requests
RUN /venv/bin/pip install paramiko



# Start bash to keep the container running (for manual debugging)
CMD ["/bin/bash", "-c", "tail -f /dev/null"]
