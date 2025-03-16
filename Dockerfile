FROM golang:1.23

# Install dependencies including required services
RUN apt-get update && apt-get install -y \
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
    hping3

# Set root password, allow root login, and enable password authentication
RUN echo 'root:password' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Install Go tools (optional, assuming you're using this in your project)
RUN go install github.com/air-verse/air@latest

# Set working directory
WORKDIR /app

# Copy Go modules
COPY go.mod go.sum ./
RUN go mod tidy

# Copy the application files
COPY . .


COPY main.conf /etc/postfix/main.cf

# Build the Go application
RUN go build -o inline-ips main.go

# Expose necessary ports
EXPOSE 22 80 21 53 25


# Expose UDP port 161 for listening
EXPOSE 161/udp

RUN echo '#!/bin/bash\nwhile true; do \
    RESPONSE="DNS Response: example.com A 93.184.216.34"\n\
    echo -n "$RESPONSE" | nc -ul -p 161\n\
    sleep 1\n\
done' > /udpListener.sh && chmod +x /udpListener.sh


# Start services manually and keep the container running
CMD service ssh start && \
    service apache2 start && \
    service vsftpd start && \
    service named start && \
    service postfix start && \
    /udpListener.sh & \
    exec air -c .air.toml
