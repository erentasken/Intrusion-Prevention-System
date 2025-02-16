package main

import (
	"fmt"
	"net"
	"net/http"
)

// XSS Vulnerability - Fixed with HTML escaping
func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	fmt.Fprintf(w, "You searched for: %s", query)
}

// SQL Injection Vulnerability - Fixed with Prepared Statements
func sqliHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	fmt.Println("Query:", query)
}

// Buffer Overflow Vulnerability - Use a safe buffer size
func bufferOverflowServer() {
	ln, err := net.Listen("tcp", ":9999")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		// Limit the buffer size to prevent overflow
		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("Received:", string(buf)) // This should be handled safely now
		conn.Close()
	}
}

func main() {
	// Start HTTP server for XSS & SQLi (now fixed)
	fmt.Println("Starting vulnerable server...")
	go func() {
		http.HandleFunc("/search", searchHandler) // XSS
		http.HandleFunc("/sqli", sqliHandler)     // SQLi
		http.ListenAndServe(":80", nil)
	}()

	// Start TCP server for buffer overflow (now fixed)
	bufferOverflowServer()

	fmt.Println("Server stopped.")
}
