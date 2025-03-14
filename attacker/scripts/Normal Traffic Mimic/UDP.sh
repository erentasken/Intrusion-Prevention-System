#!/bin/bash

echo "Starting Normal UDP Daily Traffic Simulation on $TARGET_IP..."

NORMAL_UDP_TRAFFIC=(
    "hping3 --udp -p 53 -c 20 $TARGET_IP"
    "hping3 --udp -p 123 -c 15 $TARGET_IP"
    "hping3 --udp -p 161 -c 10 $TARGET_IP"
    "hping3 --udp -p 500 -c 12 $TARGET_IP"
    "hping3 --udp -p 67 -c 8 $TARGET_IP"
)

for ((i=0; i<5; i++)); do
    NORMAL_INDEX=$((RANDOM % ${#NORMAL_UDP_TRAFFIC[@]}))
    
    echo "Executing: ${NORMAL_UDP_TRAFFIC[$NORMAL_INDEX]}"
    eval "${NORMAL_UDP_TRAFFIC[$NORMAL_INDEX]}"
    
    SLEEP_TIME=$((RANDOM % 20 + 10))
    echo "Sleeping for $SLEEP_TIME seconds..."
    sleep $SLEEP_TIME
    
    sleep $((RANDOM % 30 + 20))

done

echo "Normal UDP Traffic Simulation Completed!"
