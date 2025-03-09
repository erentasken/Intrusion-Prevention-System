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

# Build the Go application
RUN go build -o inline-ips main.go

# Expose necessary ports
EXPOSE 22 80 21 53 25

# Start services manually and keep the container running
CMD service ssh start && \
    service apache2 start && \
    service vsftpd start && \
    service named start && \
    service postfix start && \
    air -c .air.toml
