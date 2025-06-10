package service

import (
	"bufio"
	"encoding/json"
	"fmt"
	"main/model"
	"os/exec"
	"syscall"
)

var cmd *exec.Cmd

// Run Python unsw_runner.py and read prediction JSON lines
func StartUNSWRunnable(alert chan<- model.Detection) error {
	cmd = exec.Command("python3", "/app/service/unsw_runner.py")

	// Create pipe to capture stdout
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}
	cmd.Stderr = cmd.Stdout // merge stderr to stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start python script: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	go func() {
		for scanner.Scan() {
			line := scanner.Text()

			if len(line) == 0 || (line[0] != '{' && line[0] != '[') {
				continue
			}

			var preds []model.Detection
			err := json.Unmarshal([]byte(line), &preds)
			if err != nil {
				fmt.Println("Failed to parse prediction JSON:", err, "line:", line)
				continue
			}

			for _, p := range preds {
				if p.Message != "Benign" { 
					alert <- model.Detection{
						AttackerIP:  p.AttackerIP,
						Method:      "AI Detection ( UNSWB )",
						Protocol:    "TCP",
						TargetPort: "",
						Message:     string(p.Message),
					}
				}
				
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading python output:", err)
		}
	}()


	// Optional: wait for process to finish in background (or handle termination elsewhere)
	go func() {
		err := cmd.Wait()
		if err != nil {
			fmt.Println("Python script exited with error:", err)
		} else {
			fmt.Println("Python script exited cleanly")
		}
	}()

	return nil
}


// StopUNSWRunnable sends SIGTERM to the Python subprocess
func StopUNSWRunnable() error {
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("invalid command or process")
	}

	// Send SIGTERM to allow graceful shutdown
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to send SIGTERM: %w", err)
	}

	fmt.Println("stoppign the unsw")
	return nil
}
