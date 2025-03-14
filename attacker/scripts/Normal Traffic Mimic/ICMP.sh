#!/bin/bash

echo "Starting Enhanced Normal ICMP Daily Traffic Simulation on $TARGET_IP..."

NORMAL_ICMP_TRAFFIC=(
    "ping -c 10 $TARGET_IP"
    "ping -c 5 -s 56 $TARGET_IP"
    "ping -c 15 -i 2 $TARGET_IP"
    "ping -c 7 -W 1 $TARGET_IP"
    "ping -c 10 -I eth0 $TARGET_IP"
    "ping -c 20 -s 100 $TARGET_IP"
    "ping -c 30 -i 1 $TARGET_IP"
    "ping -c 10 -t 255 $TARGET_IP"
    "ping -c 5 -i 10 $TARGET_IP"   # Lower frequency
    "ping -c 10 -s 512 $TARGET_IP" # Larger packet size
)

for ((i=0; i<5; i++)); do
    NORMAL_INDEX=$((RANDOM % ${#NORMAL_ICMP_TRAFFIC[@]}))
    
    echo "Executing: ${NORMAL_ICMP_TRAFFIC[$NORMAL_INDEX]}"
    eval "${NORMAL_ICMP_TRAFFIC[$NORMAL_INDEX]}"
    
    SLEEP_TIME=$((RANDOM % 20 + 10))
    echo "Sleeping for $SLEEP_TIME seconds..."
    sleep $SLEEP_TIME
    
    sleep $((RANDOM % 30 + 20))

done

echo "Enhanced Normal ICMP Traffic Simulation Completed!"
