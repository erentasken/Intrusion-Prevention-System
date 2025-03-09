#!/bin/bash

# SSH details
SSH_USER="root"
SSH_HOST="172.30.0.2"
SSH_PASSWORD="password"

# SSH Command (to log into the SSH server)
SSH_CMD="sshpass -p $SSH_PASSWORD ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_USER@$SSH_HOST"

# Run SSH command to login and perform actions within the session
$SSH_CMD << EOF

# Wait for a random time between 1 and 5 minutes (adjust as needed)
RANDOM_WAIT_TIME=\$((RANDOM % 10 + 5))  # random time between 60 and 300 seconds (1 to 5 minutes)
echo "Logged in. Waiting for \$RANDOM_WAIT_TIME seconds..."

# Sleep for the random time
sleep \$RANDOM_WAIT_TIME

# Exit the SSH session
exit

EOF

# End the script
echo "Operation halted."



# ALTERNATIVE ? ? ?? ? ??

# #!/bin/bash

# # SSH details
# SSH_USER="root"
# SSH_HOST="172.30.0.2"
# SSH_PASSWORD="password"  # This can be randomized as needed or fetched from a secure source

# # SSH Command (to log into the SSH server)
# SSH_CMD="sshpass -p $SSH_PASSWORD ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_USER@$SSH_HOST"

# # Function to generate random string for commands and actions
# generate_random_string() {
#     LENGTH=$1
#     head /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c $LENGTH
#     echo
# }

# # Randomize the wait time between 1 and 10 minutes (60 to 600 seconds)
# RANDOM_WAIT_TIME=$((RANDOM % 541 + 60))  # Random time between 60 and 600 seconds (1 to 10 minutes)
# echo "Logged in. Waiting for $RANDOM_WAIT_TIME seconds..."

# # Randomize a session duration (between 1 and 3 minutes)
# SESSION_DURATION=$((RANDOM % 181 + 60))  # Random session time between 1 and 3 minutes (60 to 240 seconds)
# echo "Session will last for $SESSION_DURATION seconds."

# # Randomize the commands to execute after login (e.g., changing directories, listing files, etc.)
# RANDOM_CMD1="cd /tmp && touch $(generate_random_string 8)"
# RANDOM_CMD2="ls -alh /home"
# RANDOM_CMD3="uptime"

# # Run SSH command to login and perform actions within the session
# $SSH_CMD << EOF

# # Sleep for the randomized wait time
# sleep $RANDOM_WAIT_TIME

# # Randomly select and run one of the commands
# RANDOM_ACTION=$((RANDOM % 3 + 1))
# if [ \$RANDOM_ACTION -eq 1 ]; then
#     echo "Executing command: $RANDOM_CMD1"
#     $RANDOM_CMD1
# elif [ \$RANDOM_ACTION -eq 2 ]; then
#     echo "Executing command: $RANDOM_CMD2"
#     $RANDOM_CMD2
# else
#     echo "Executing command: $RANDOM_CMD3"
#     $RANDOM_CMD3
# fi

# # Sleep for the session duration
# sleep $SESSION_DURATION

# # Exit the SSH session
# exit

# EOF

# # End the script
# echo "Operation completed."
