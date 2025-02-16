FROM kalilinux/kali-rolling

WORKDIR /attack-scripts

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
    && apt clean

# Create a virtual environment and install Python packages
RUN python3 -m venv /venv
RUN /venv/bin/pip install --upgrade pip
RUN /venv/bin/pip install scapy requests

# Copy attack scripts
COPY attack-scripts/ /attack-scripts/
RUN chmod +x /attack-scripts/*.sh

# Use the virtual environment when running scripts
CMD ["/bin/bash", "-c", "source /venv/bin/activate && /attack-scripts/run_all.sh"]
