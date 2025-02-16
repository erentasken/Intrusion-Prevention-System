package main

import (
	"database/sql"
	"fmt"
	"net"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

// Initialize database and create users table if it doesn't exist
func initDatabase() {
	db, err := sql.Open("sqlite3", "./vulnerable.db")
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	// Create users table if it doesn't exist
	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL
	);
	`
	_, err = db.Exec(createTable)
	if err != nil {
		fmt.Println("Error creating table:", err)
		return
	}

	// Insert default users if table is empty
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil || count == 0 {
		insertUsers := `
		INSERT INTO users (name) VALUES 
		('admin'), ('user1'), ('user2'), ('test');
		`
		_, err = db.Exec(insertUsers)
		if err != nil {
			fmt.Println("Error inserting data:", err)
		}
	}
}

// XSS Vulnerability
func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	fmt.Fprintf(w, "You searched for: %s", query) // Vulnerable to XSS
}

// SQL Injection Vulnerability
func sqliHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	db, _ := sql.Open("sqlite3", "./vulnerable.db")
	defer db.Close()

	rows, _ := db.Query("SELECT name FROM users WHERE name = '" + query + "'") // Vulnerable to SQL Injection
	for rows.Next() {
		var name string
		rows.Scan(&name)
		fmt.Fprintf(w, "Found: %s\n", name)
	}
}

// Buffer Overflow Vulnerability
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
		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Println("Received:", string(buf)) // Vulnerable to buffer overflow
		conn.Close()
	}
}

func main() {
	// Ensure the database is initialized
	initDatabase()

	// Start HTTP server for XSS & SQLi
	go func() {
		http.HandleFunc("/search", searchHandler) // XSS
		http.HandleFunc("/sqli", sqliHandler)     // SQLi
		http.ListenAndServe(":80", nil)
	}()

	// Start TCP server for buffer overflow
	bufferOverflowServer()
}
