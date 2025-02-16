FROM golang:1.23

RUN apt-get update && apt-get install -y iptables

RUN go install github.com/air-verse/air@latest

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod tidy

COPY . .

RUN go build -o inline-ips main.go
CMD ["air", "-c", ".air.toml"]
