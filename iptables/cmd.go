package iptables

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/joho/godotenv"
)

func runCommand(cmd string, args ...string) error {
	command := exec.Command(cmd, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("[ERROR] Command failed: %s %v\nOutput: %s", cmd, args, string(output))
	}
	fmt.Printf("[✔] %s\n", string(output))
	return nil
}

func PrepareNFQueues() error {

	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file:", err)
		os.Exit(1)
	}

	fmt.Println("[*] Flushing existing iptables and arptables rules...")

	flushCommands := [][]string{
		{"iptables", "-F"},
		{"iptables", "-X"},
		{"iptables", "-t", "nat", "-F"},
		{"iptables", "-t", "nat", "-X"},
		{"iptables", "-t", "mangle", "-F"},
		{"iptables", "-t", "mangle", "-X"},
		{"arptables", "-F"},
		{"arptables", "-X"},
	}

	for _, cmd := range flushCommands {
		if err := runCommand(cmd[0], cmd[1:]...); err != nil {
			fmt.Printf("[ERROR] Failed to execute: %v\n", cmd)
		}
	}

	nfqueueRules := [][]string{
		{"iptables", "-A", "INPUT", "-p", "tcp", "!", "--source", "172.30.0.11", "-j", "NFQUEUE", "--queue-num", os.Getenv("TCP_QUEUE")},
		{"iptables", "-A", "OUTPUT", "-p", "tcp", "!", "--destination", "172.30.0.11", "-j", "NFQUEUE", "--queue-num", os.Getenv("TCP_QUEUE")},

		// ICMP rules
		{"iptables", "-A", "INPUT", "-p", "icmp", "!", "--source", "172.30.0.11", "-j", "NFQUEUE", "--queue-num", os.Getenv("ICMP_QUEUE")},
		{"iptables", "-A", "OUTPUT", "-p", "icmp", "!", "--destination", "172.30.0.11", "-j", "NFQUEUE", "--queue-num", os.Getenv("ICMP_QUEUE")},

		// UDP rules
		{"iptables", "-A", "INPUT", "-p", "udp", "!", "--source", "172.30.0.11", "-j", "NFQUEUE", "--queue-num", os.Getenv("UDP_QUEUE")},
		{"iptables", "-A", "OUTPUT", "-p", "udp", "!", "--destination", "172.30.0.11", "-j", "NFQUEUE", "--queue-num", os.Getenv("UDP_QUEUE")},
	}

	fmt.Println("[*] Applying iptables rules...")
	for _, rule := range nfqueueRules {
		if err := runCommand(rule[0], rule[1:]...); err != nil {
			fmt.Printf("[ERROR] Failed to apply rule: %v\n", rule)
		}
	}

	fmt.Println("[*] Ensuring /etc/iptables directory exists...")
	fmt.Println("[ERROR] Failed to create /etc/iptables directory:", err)
	if err := runCommand("mkdir", "-p", "/etc/iptables"); err != nil {
	}

	fmt.Println("[*] Saving iptables rules for persistence...")
	saveCmd := exec.Command("iptables-save")
	rulesFile, err := os.Create("/etc/iptables/rules.v4")
	if err != nil {
		fmt.Println("[ERROR] Failed to open rules file:", err)
		return err
	}
	defer rulesFile.Close()

	saveCmd.Stdout = rulesFile
	if err := saveCmd.Run(); err != nil {
		fmt.Println("[ERROR] Failed to save iptables rules:", err)
		return err
	}

	fmt.Println("[✔] iptables rules saved successfully.")
	return nil
}

// BlockIP inserts DROP rules in INPUT, OUTPUT, and FORWARD chains to block all traffic to/from a specific IP
func BlockIP(ip string) error {
	fmt.Printf("[*] Blocking IP: %s\n", ip)

	blockRules := [][]string{
		{"iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"},
		{"iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"},
		{"iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"},
		{"iptables", "-I", "FORWARD", "1", "-d", ip, "-j", "DROP"},
	}

	for _, rule := range blockRules {
		if err := runCommand(rule[0], rule[1:]...); err != nil {
			return fmt.Errorf("[ERROR] Failed to block IP %s: %v", ip, err)
		}
	}

	fmt.Printf("[✔] IP %s blocked successfully.\n", ip)
	return nil
}

// UnblockIP deletes any DROP rules for a specific IP in INPUT, OUTPUT, and FORWARD chains
func UnblockIP(ip string) error {
	fmt.Printf("[*] Unblocking IP: %s\n", ip)

	unblockRules := [][]string{
		{"iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"},
		{"iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"},
		{"iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"},
		{"iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"},
	}

	for _, rule := range unblockRules {
		if err := runCommand(rule[0], rule[1:]...); err != nil {
			fmt.Printf("[WARNING] Could not delete rule: %v (possibly already removed)\n", rule)
		}
	}

	fmt.Printf("[✔] IP %s unblocked successfully.\n", ip)
	return nil
}
