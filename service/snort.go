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
	"strconv"
	"syscall"
)

func StartSnort(alert chan<- model.Detection) {
	// Use stdbuf to disable Snort's output buffering
	cmd := exec.Command("stdbuf", "-oL", "-eL", "snort", "-c", "/usr/local/etc/snort/snort.lua", "-i", "eth0", "-A", "alert_fast", "-k", "none", "--daq-batch-size", "1")

	// Capture Snort's output
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Failed to create stdout pipe:", err)
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		fmt.Println("Failed to create stderr pipe:", err)
		return
	}

	// Start the Snort process
	if err := cmd.Start(); err != nil {
		fmt.Println("Failed to start Snort:", err)
		return
	}

	// Store Snort's PID in runtime
	pid := cmd.Process.Pid
	fmt.Println("Snort started with PID:", pid)

	// Goroutine to print Snort's stdout after line 145
	go printAfterLine("STDOUT", stdoutPipe, 315, alert)
	// Goroutine to print Snort's stderr after line 145
	go printAfterLine("STDERR", stderrPipe, 145, alert)

	// Create a channel to listen for OS interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Wait for an interrupt signal
	<-sigChan
	fmt.Println("\nInterrupt received, forcefully stopping Snort...")

	// Kill Snort using `kill -9 {pid}`
	killCmd := exec.Command("kill", "-9", strconv.Itoa(pid))
	if err := killCmd.Run(); err != nil {
		fmt.Println("Error forcefully terminating Snort:", err)
	} else {
		fmt.Println("Snort process forcefully stopped.")
	}
}

// printAfterLine prints output after the given line threshold
func printAfterLine(prefix string, pipe io.Reader, threshold int, alert chan<- model.Detection) {
	scanner := bufio.NewScanner(pipe)
	lineCount := 0
	buffer := make([]string, 0, threshold) // Buffer to store the first 145 lines

	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		// Buffer first 145 lines
		if lineCount <= threshold {
			buffer = append(buffer, line)
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
					Attacker_ip: srcIP,
					Target_port: destPort,
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
