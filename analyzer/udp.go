package analyzer

import (
	"encoding/binary"
	"fmt"
	"main/model"
	"net"
)

// AnalyzeUDP analyzes both IPv4 and IPv6 UDP packets and returns a structured result.
func AnalyzeUDP(packetID uint32, payload []byte) {
	// Check if the packet length is large enough to be a valid packet
	if len(payload) < 40 {
		fmt.Printf("[WARNING] Packet ID %d: Malformed packet (too short)\n", packetID)
		return
	}

	// Determine if the packet is IPv4 or IPv6 based on the first byte (version field)
	versionIHL := payload[0]
	version := versionIHL >> 4 // Get the IP version (4 or 6)

	var packetAnalysis model.PacketAnalysisUDP
	packetAnalysis.PacketID = packetID

	if version == 4 { // IPv4 Packet
		// Extract IPv4 header fields
		ihl := (versionIHL & 0x0F) * 4 // IHL is in 32-bit words, convert to bytes
		packetAnalysis.IPv4 = &model.IPv4Info{
			Version:             version,
			IHL:                 ihl,
			TotalLength:         binary.BigEndian.Uint16(payload[2:4]),
			Identification:      binary.BigEndian.Uint16(payload[4:6]),
			FlagsFragmentOffset: binary.BigEndian.Uint16(payload[6:8]),
			TTL:                 payload[8],
			Protocol:            payload[9],
			SourceIP:            net.IP(payload[12:16]).String(),
			DestinationIP:       net.IP(payload[16:20]).String(),
		}

		// Extract UDP header fields (starting after the IP header)
		udpStart := ihl
		packetAnalysis.UDP = &model.UDPInfo{
			SourcePort:      binary.BigEndian.Uint16(payload[udpStart : udpStart+2]),
			DestinationPort: binary.BigEndian.Uint16(payload[udpStart+2 : udpStart+4]),
			Length:          binary.BigEndian.Uint16(payload[udpStart+4 : udpStart+6]),
			Checksum:        binary.BigEndian.Uint16(payload[udpStart+6 : udpStart+8]),
		}

	} else if version == 6 { // IPv6 Packet
		// Extract IPv6 header fields
		packetAnalysis.IPv6 = &model.IPv6Info{
			Version:       version,
			PayloadLength: binary.BigEndian.Uint16(payload[4:6]),
			NextHeader:    payload[6],
			HopLimit:      payload[7],
			SourceIP:      net.IP(payload[8:24]).String(),
			DestinationIP: net.IP(payload[24:40]).String(),
		}

		// Extract UDP header fields (starting after the IPv6 header)
		udpStart := 40 // IPv6 header is 40 bytes
		packetAnalysis.UDP = &model.UDPInfo{
			SourcePort:      binary.BigEndian.Uint16(payload[udpStart : udpStart+2]),
			DestinationPort: binary.BigEndian.Uint16(payload[udpStart+2 : udpStart+4]),
			Length:          binary.BigEndian.Uint16(payload[udpStart+4 : udpStart+6]),
			Checksum:        binary.BigEndian.Uint16(payload[udpStart+6 : udpStart+8]),
		}

	} else {
		// Unsupported IP version
		fmt.Printf("[WARNING] Unsupported IP version %d in packet ID %d\n", version, packetID)
		return
	}

	// Print the detailed packet analysis (IPv4 or IPv6 + UDP)
	printUDP(&packetAnalysis)
}

// PrintPacketAnalysis prints a formatted output for the packet analysis.
func printUDP(analysis *model.PacketAnalysisUDP) {
	if analysis == nil {
		return
	}

	// Print IPv4 or IPv6 information
	if analysis.IPv4 != nil {
		fmt.Printf("[IPv4] Packet ID: %d | Version: %d | IHL: %d bytes | Total Length: %d | TTL: %d | Protocol: %d\n",
			analysis.PacketID, analysis.IPv4.Version, analysis.IPv4.IHL, analysis.IPv4.TotalLength,
			analysis.IPv4.TTL, analysis.IPv4.Protocol)

		fmt.Printf("[IPv4] Source: %s → Destination: %s | Identification: %d | Flags & Offset: %d\n",
			analysis.IPv4.SourceIP, analysis.IPv4.DestinationIP, analysis.IPv4.Identification, analysis.IPv4.FlagsFragmentOffset)
	} else if analysis.IPv6 != nil {
		fmt.Printf("[IPv6] Packet ID: %d | Version: %d | Payload Length: %d | Hop Limit: %d | Next Header: %d\n",
			analysis.PacketID, analysis.IPv6.Version, analysis.IPv6.PayloadLength, analysis.IPv6.HopLimit,
			analysis.IPv6.NextHeader)

		fmt.Printf("[IPv6] Source: %s → Destination: %s\n",
			analysis.IPv6.SourceIP, analysis.IPv6.DestinationIP)
	}

	// Print UDP information
	if analysis.UDP.SourcePort != 0 && analysis.UDP.DestinationPort != 0 {
		fmt.Printf("[UDP] Packet ID: %d | %s:%d → %s:%d | Length: %d | Checksum: 0x%X\n",
			analysis.PacketID, analysis.IPv4.SourceIP, analysis.UDP.SourcePort,
			analysis.IPv4.DestinationIP, analysis.UDP.DestinationPort,
			analysis.UDP.Length, analysis.UDP.Checksum)
	}

	fmt.Println()
}
