package service

import (
	"bufio"
	"fmt"
	"io"
	"main/model"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"syscall"
)

var snortCmd *exec.Cmd

func StartSnort(alert chan<- model.Detection) {
	// Define the Snort command with stdbuf to disable buffering
	snortCmd = exec.Command(
		"stdbuf", "-oL", "-eL", "snort",
		"-c", "/usr/local/etc/snort/snort.lua",
		"-i", "eth0",
		"-A", "alert_fast",
		"-k", "none",
		"--daq-batch-size", "1",
	)

	stdoutPipe, err := snortCmd.StdoutPipe()
	if err != nil {
		fmt.Println("❌ Failed to create stdout pipe:", err)
		return
	}
	stderrPipe, err := snortCmd.StderrPipe()
	if err != nil {
		fmt.Println("❌ Failed to create stderr pipe:", err)
		return
	}

	if err := snortCmd.Start(); err != nil {
		fmt.Println("❌ Failed to start Snort:", err)
		return
	}

	pid := snortCmd.Process.Pid
	fmt.Println("🚀 Snort started with PID:", pid)

	// Goroutines to handle output
	go printAfterLine("STDOUT", stdoutPipe, 315, alert)
	go printAfterLine("STDERR", stderrPipe, 145, alert)

	// Handle interrupt signals in a separate goroutine
	go func(pid int) {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan

		fmt.Println("🛑 Interrupt received. Stopping Snort...")
		StopSnort()
	}(pid)
}



func StopSnort() bool {
	if snortCmd != nil && snortCmd.Process != nil {
		pid := snortCmd.Process.Pid
		if err := snortCmd.Process.Kill(); err != nil {
			fmt.Printf("❌ Failed to stop Snort (PID %d): %v\n", pid, err)
			return false
		}
		fmt.Printf("✅ Snort (PID %d) successfully stopped.\n", pid)
		snortCmd = nil
		return true
	}
	fmt.Println("⚠️ No Snort process is currently running.")
	return false
}

func printAfterLine(prefix string, pipe io.Reader, threshold int, alert chan<- model.Detection) {
	scanner := bufio.NewScanner(pipe)
	lineCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		// Buffer first 145 lines
		if lineCount <= threshold {
			continue
		}

		re := regexp.MustCompile(`\[\*\*\] \[.*?\] "(.*?)" \[\*\*\].*?\{(\w+)\} (\d+\.\d+\.\d+\.\d+):(\d+)(?: ->|,) (\d+\.\d+\.\d+\.\d+):(\d+)`)

		// Find matches
		matches := re.FindStringSubmatch(line)

		if len(matches) >= 7 { // We now expect 7 groups (including protocol)
			alertMessage := matches[1]
			protocol := matches[2] // Protocol from between {}
			srcIP := matches[3]
			// srcPort := matches[4]
			// destIP := matches[5]
			destPort := matches[6]

			if srcIP != "172.30.0.2" {
				attack_alert := model.Detection{
					Method:      "Rule Detection",
					Protocol:    protocol,
					AttackerIP: srcIP,
					TargetPort: destPort,
					Message:     alertMessage,
				}
				alert <- attack_alert
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[%s] Error reading output: %v\n", prefix, err)
	}
}
