import random
import time
import subprocess

# Target IP address
target_ip = "172.30.0.2"  # Replace with your target IP
print(f"Starting Normal UDP Daily Traffic Simulation on {target_ip}...")

while True: 
    
    subprocess.run(f"hping3 --udp -p 161 -c {random.randint(3, 25)} {target_ip}", shell=True)

    print("Sleeping for 8 seconds...")
    time.sleep(8)

