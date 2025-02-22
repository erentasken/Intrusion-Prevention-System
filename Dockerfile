FROM golang:1.23

# Install dependencies including OpenSSH server
RUN apt-get update && apt-get install -y \
    iptables \
    iputils-ping \
    openssh-server

# Set root password, allow root login and enable password authentication
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

# Expose port for SSH
EXPOSE 22

# Start SSH service and application
CMD service ssh start && air -c .air.toml
