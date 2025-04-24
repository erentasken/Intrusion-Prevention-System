#!/bin/bash
set -e

# Start services
service ssh start
service apache2 start
service vsftpd start
service named start
service postfix start

# Start background processes
# /usr/bin/python3 /app/mock_udp_server.py &
# /udpListener.sh &

# cd /NextApp/frontend

# wails dev -tags webkit2_41 & 

# Start main application
# exec air -c .air.toml


# echo "nameserver 0.0.0.0" > /etc/resolv.conf

# ping -c 5 google.com

# cd /app

# wails dev -tags webkit2_41

tail -f /dev/null
