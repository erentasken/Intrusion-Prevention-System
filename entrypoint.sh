#!/bin/bash
set -e

# Start services
service ssh start
service apache2 start
service vsftpd start
service named start
service postfix start

# Start background processes
/usr/bin/python3 /app/mock_udp_server.py &
/udpListener.sh &

# Start main application
exec air -c .air.toml