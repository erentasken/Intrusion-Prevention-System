package handler

import (
	"fmt"
)

// AnalyzeHttp is a function that analyzes HTTP packets.
func AnalyzeICMP(packetID uint32, payload []byte) {
	fmt.Println("ICMP Packet")
}
