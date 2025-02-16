package analyzer

import (
	"fmt"
)

// AnalyzePortScan detects network scanning activities.
func AnalyzePortScan(packetID uint32, payload []byte) {
	fmt.Printf("[Port Scan] Packet ID: %d, Length: %d bytes\n", packetID, len(payload))
	// Detect rapid connection attempts on multiple ports
}
