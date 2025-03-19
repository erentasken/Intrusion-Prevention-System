import subprocess
import random
import time

TARGET_IP = "172.30.0.2"  # Replace with your target IP
print(f"Starting Enhanced Normal ICMP Daily Traffic Simulation on {TARGET_IP}...")

NORMAL_ICMP_TRAFFIC = [
    f"ping -c 10 {TARGET_IP}",
    f"ping -c 5 -s 56 {TARGET_IP}",
    f"ping -c 15 -i 2 {TARGET_IP}",
    f"ping -c 7 -W 1 {TARGET_IP}",
    f"ping -c 10 -I eth0 {TARGET_IP}",
    f"ping -c 20 -s 100 {TARGET_IP}",
    f"ping -c 30 -i 1 {TARGET_IP}",
    f"ping -c 10 -t 255 {TARGET_IP}",
    f"ping -c 5 -i 10 {TARGET_IP}",  # Lower frequency
    f"ping -c 10 -s 512 {TARGET_IP}"  # Larger packet size
]

while True:
    normal_index = random.randint(0, len(NORMAL_ICMP_TRAFFIC) - 1)
    
    print(f"Executing: {NORMAL_ICMP_TRAFFIC[normal_index]}")
    subprocess.run(NORMAL_ICMP_TRAFFIC[normal_index], shell=True)
    
    time.sleep(6)

print("Enhanced Normal ICMP Traffic Simulation Completed!")
