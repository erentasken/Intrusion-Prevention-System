# FROM ubuntu:22.04

# # # First install CA certificates and git
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     ca-certificates \
#     git \
#     && apt-get clean \
#     && rm -rf /var/lib/apt/lists/*

# # Set environment variables
# ENV DEBIAN_FRONTEND=noninteractive \
#     TZ=UTC \
#     PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# # Install runtime dependencies
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     iptables \
#     iputils-ping \
#     openssh-server \
#     apache2 \
#     vsftpd \
#     dnsutils \
#     bind9 \
#     postfix \
#     tcpdump \
#     vim \
#     netcat-openbsd \
#     hping3 \
#     python3 \
#     python3-pip \
#     python3-venv \
#     ca-certificates \
#     wget \
#     dumb-init \
#     libpcap-dev \
#     libpcre3-dev \
#     libnet1-dev \
#     zlib1g-dev \
#     libdumbnet-dev \
#     libhwloc-dev \
#     libluajit-5.1-dev \
#     libssl-dev \
#     liblzma-dev \
#     libmnl-dev \
#     && apt-get clean \
#     && rm -rf /var/lib/apt/lists/*

# # Install Go
# RUN wget https://go.dev/dl/go1.23.7.linux-amd64.tar.gz -O /tmp/go.tar.gz && \
#     tar -C /usr/local -xzf /tmp/go.tar.gz && \
#     rm /tmp/go.tar.gz

# # Install air
# RUN go install github.com/air-verse/air@latest

# # # Copy built artifacts from builder stage
# # COPY --from=builder /usr/local /usr/local

# # Configure system
# RUN echo 'root:password' | chpasswd && \
#     sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
#     echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
#     python3 -m venv /venv && \
#     /venv/bin/pip install --no-cache-dir --upgrade pip requests

# WORKDIR /app
# COPY . .

# RUN mkdir -p /var/www/html && echo '<?php \nif (isset($_GET["q"])) { \n    echo "You searched for: " . htmlspecialchars($_GET["q"]); \n} else { \n    echo "No query received."; \n} \n?>' > /var/www/html/index.php


# # Build Go application
# RUN go build -o inline-ips main.go

# # Expose ports
# EXPOSE 22 80 21 53 25 12345/udp 161/udp

# # Entrypoint
# COPY entrypoint.sh /entrypoint.sh
# RUN chmod +x /entrypoint.sh

# RUN /app/install.sh

# ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# # busy wait
# CMD ["/entrypoint.sh", "&&" ,"tail", "-f", "/dev/null"]



# Use the prebuilt Snort image
FROM eren3050/my_snort:latest

# Install additional tools and runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    iptables \
    iputils-ping \
    openssh-server \
    apache2 \
    vsftpd \
    dnsutils \
    bind9 \
    postfix \
    tcpdump \
    vim \
    netcat-openbsd \
    hping3 \
    python3 \
    python3-pip \
    python3-venv \
    wget \
    dumb-init \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Go
ENV GO_VERSION=1.23.7
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

# # Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install air
RUN go install github.com/air-verse/air@latest

# Configure system
RUN echo 'root:password' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    python3 -m venv /venv && \
    /venv/bin/pip install --no-cache-dir --upgrade pip requests

# Create index.php to listen for 'q' parameter
RUN mkdir -p /var/www/html && echo '<?php \nif (isset($_GET["q"])) { \n    echo "You searched for: " . htmlspecialchars($_GET["q"]); \n} else { \n    echo "No query received."; \n} \n?>' > /var/www/html/index.php

WORKDIR /app
COPY . .

# Build Go application
RUN go build -o inline-ips main.go

# Expose ports
EXPOSE 22 80 21 53 25 12345/udp 161/udp

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# RUN /app/install.sh

ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Busy wait
CMD ["/entrypoint.sh", "&&", "tail", "-f", "/dev/null"]
# CMD ["tail", "-f", "/dev/null"]
