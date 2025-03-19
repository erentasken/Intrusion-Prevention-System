import random
import time
import paramiko

# SSH details
ssh_user = "root"
ssh_host = "172.30.0.2"
ssh_password = "password"

# Create an SSH client instance
ssh_client = paramiko.SSHClient()

# Automatically add the SSH key if not already in known hosts (this is equivalent to -o UserKnownHostsFile=/dev/null)
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:

    ssh_commands = [
        "ls",
        "pwd",
        "whoami",
        "uname -a",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "cat /etc/hosts",
        "cat /etc/resolv.conf",
        "cat /etc/hostname",
        "cat /etc/network/interfaces",
        "cat /etc/issue",
        "cat /etc/os-release",
        "cat /etc/lsb-release",
        "cat /etc/issue.net",
        "cat /etc/motd",
        "cat /etc/ssh/sshd_config",
        "cat /etc/ssh/ssh_config",
        "cat /etc/ssh/ssh_host_rsa_key",
        "cat /etc/ssh/ssh_host_rsa_key.pub",
        "cat /etc/ssh/ssh_host_dsa_key",
        "cat /etc/ssh/ssh_host_dsa_key.pub",
        "cat /etc/ssh/ssh_host_ecdsa_key",
        "cat /etc/ssh/ssh_host_ecdsa"
        "cat /etc/ssh/ssh_host_ecdsa_key.pub"

    ]

    while True:
        ssh_client.connect(ssh_host, username=ssh_user, password=ssh_password)
        command_number = random.randint(1, 10)

        for i in range(command_number):
            # Select a random command from the list
            command_index = random.randint(0, len(ssh_commands) - 1)

            # Execute the chosen command
            print(f"Executing: {ssh_commands[command_index]}")
            stdin, stdout, stderr = ssh_client.exec_command(ssh_commands[command_index])

            # Random sleep between 1000 millisecond and 2000 millisecond
            time.sleep(random.randint(1, 2))
        # print("Session ends,")        

        time.sleep(8)
        ssh_client.close()

except KeyboardInterrupt:
    print("KeyboardInterrupt detected. Closing the SSH session.")

    # Exit the SSH session

finally:
    print("Operation halted.")
    # pass
