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
    
    # # Set sleep time based on the selected script
    # if [[ "$RANDOM_SCRIPT" == "ssh.sh" ]]; then
    #     SLEEP_TIME=$((RANDOM % 301 + 300))  # 5 to 10 minutes (300-600 seconds)
    # else
    #     SLEEP_TIME=$((RANDOM % 241 + 60))   # 1 to 5 minutes (60-300 seconds)
    # fi
    SLEEP_TIME=$((RANDOM % 7 + 15))


    echo "Sleeping for $SLEEP_TIME seconds..."
    sleep $SLEEP_TIME
done
