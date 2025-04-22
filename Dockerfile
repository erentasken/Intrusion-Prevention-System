# Use the prebuilt Snort image
FROM eren3050/my_snort:latest

# Install additional tools and runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iputils-ping \
    iptables \
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
    dumb-init \
    curl \
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
# RUN go build -o inline-ips ips.go

# Expose ports
EXPOSE 22 80 21 53 25 12345/udp 161/udp

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN service ssh start \
    service apache2 start \
    service vsftpd start \ 
    service named start \ 
    service postfix start

# RUN /app/install.sh


RUN apt-get update && apt-get install -y \
    x11-apps \
    libxrender1 \
    libxtst6 \
    libxi6 \
    libxext6 \
    libgtk-3-dev \
    pkg-config \
    libwebkit2gtk-4.1-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js and npm (LTS version)
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && \
    apt-get install -y nodejs

# Install Wails CLI
RUN go install github.com/wailsapp/wails/v2/cmd/wails@latest

ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Busy wait
CMD ["/entrypoint.sh", "&&", "tail", "-f", "/dev/null"]
# CMD ["tail", "-f", "/dev/null"]
