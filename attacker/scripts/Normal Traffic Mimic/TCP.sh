#!/bin/bash

# List of scripts
SCRIPTS=("mail.sh" "ssh.sh" "web.sh")

# Infinite loop
while true; do
    # Pick a random script
    RANDOM_SCRIPT=${SCRIPTS[$RANDOM % ${#SCRIPTS[@]}]}
    
    # Run the script
    echo "Running: $RANDOM_SCRIPT"
    bash "$RANDOM_SCRIPT"
    
    SLEEP_TIME=$((RANDOM % 7 + 15))


    echo "Sleeping for $SLEEP_TIME seconds..."
    sleep $SLEEP_TIME
done
