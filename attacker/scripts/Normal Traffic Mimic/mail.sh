#!/bin/bash

# Function to generate a random string of a given size in characters
generate_random_string() {
    LENGTH=$1
    head /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c $LENGTH
    echo
}

# Randomize subject and body sizes
SUBJECT_SIZE=$((RANDOM % 50 + 10))  # Random subject length between 10 and 50 characters
BODY_SIZE=$((RANDOM % 1000 + 100))  # Random body length between 100 and 1000 characters

# Generate random subject and body
EMAIL_SUBJECT=$(generate_random_string $SUBJECT_SIZE)
EMAIL_BODY=$(generate_random_string $BODY_SIZE)

# Sender and recipient email addresses
SENDER="sender@container2.local"
RECIPIENT="root@container1.local"
# Randomize sleep times between commands (between 1 and 3 seconds)
sleep1=$((RANDOM % 3 + 1))
sleep2=$((RANDOM % 3 + 1))
sleep3=$((RANDOM % 3 + 1))
sleep4=$((RANDOM % 3 + 1))


# Send the email via telnet (SMTP)
{
     # Wait for the server's greeting
    sleep $sleep1
    echo "EHLO localhost"
    sleep $sleep2

    # Mail From command
    echo "MAIL FROM:<$SENDER>"
    sleep $sleep3

    # Recipient To command
    echo "RCPT TO:<$RECIPIENT>"
    sleep $sleep4

    # Start Data input
    echo "DATA"
    sleep $sleep1

    # Subject and email body
    echo "Subject: $EMAIL_SUBJECT"
    echo ""
    echo "$EMAIL_BODY"

    # End the email data
    echo "."
    sleep $sleep2

    # Close the session
    echo "QUIT"
} | telnet $TARGET_IP 25
