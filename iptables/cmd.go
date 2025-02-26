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
		{"iptables", "-A", "INPUT", "-p", "icmp", "-j", "NFQUEUE", "--queue-num", os.Getenv("ICMP_QUEUE")}, // ICMP (Ping Floods)
		{"iptables", "-A", "INPUT", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", os.Getenv("TCP_QUEUE")},   // General TCP (Port Scanning, Buffer Overflow)
		{"iptables", "-A", "INPUT", "-p", "udp", "-j", "NFQUEUE", "--queue-num", os.Getenv("UDP_QUEUE")},   // UDP (DDoS, Amplification)
		// outgoing for tcp handshake
		{"iptables", "-A", "OUTPUT", "-p", "tcp", "-j", "NFQUEUE", "--queue-num", os.Getenv("TCP_OUT_QUEUE")}, // TCP RST
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
