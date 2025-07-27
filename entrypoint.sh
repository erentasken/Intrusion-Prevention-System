#!/bin/bash
set -e

# Start services
service ssh start
service apache2 start
service vsftpd start
service named start
service postfix start

echo "nameserver 0.0.0.0" >> /etc/resolv.conf

ping -c 5 google.com

cd /app

wails dev -tags webkit2_41

tail -f /dev/null
