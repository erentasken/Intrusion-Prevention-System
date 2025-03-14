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