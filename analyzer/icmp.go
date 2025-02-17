package analyzer

import (
	"encoding/binary"
	"fmt"
	"main/model"
	"net"
)

// AnalyzeICMP analyzes both IPv4 and IPv6 ICMP packets and returns a structured result.
func AnalyzeICMP(packetID uint32, payload []byte) {
	// Check if the packet length is large enough to be a valid packet
	if len(payload) < 40 {
		fmt.Printf("[WARNING] Packet ID %d: Malformed packet (too short)\n", packetID)
		return
	}

	// Determine if the packet is IPv4 or IPv6 based on the first byte (version field)
	versionIHL := payload[0]
	version := versionIHL >> 4 // Get the IP version (4 or 6)

	var packetAnalysis model.PacketAnalysisICMP
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

		// Extract ICMP header fields (starting after the IP header)
		icmpStart := ihl
		packetAnalysis.ICMP = &model.ICMPInfo{
			Type:     payload[icmpStart],
			Code:     payload[icmpStart+1],
			Checksum: binary.BigEndian.Uint16(payload[icmpStart+2 : icmpStart+4]),
			// Optional data depending on ICMP type
			// For example, Echo Request/Reply have ID and Sequence Number
			ID:       binary.BigEndian.Uint16(payload[icmpStart+4 : icmpStart+6]),
			Sequence: binary.BigEndian.Uint16(payload[icmpStart+6 : icmpStart+8]),
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

		// Extract ICMPv6 header fields (starting after the IPv6 header)
		icmpStart := 40 // IPv6 header is 40 bytes
		packetAnalysis.ICMP = &model.ICMPInfo{
			Type:     payload[icmpStart],
			Code:     payload[icmpStart+1],
			Checksum: binary.BigEndian.Uint16(payload[icmpStart+2 : icmpStart+4]),
			// For Echo Request/Reply in ICMPv6
			ID:       binary.BigEndian.Uint16(payload[icmpStart+4 : icmpStart+6]),
			Sequence: binary.BigEndian.Uint16(payload[icmpStart+6 : icmpStart+8]),
		}

	} else {
		// Unsupported IP version
		fmt.Printf("[WARNING] Unsupported IP version %d in packet ID %d\n", version, packetID)
		return
	}

	// Print the detailed packet analysis (IPv4 or IPv6 + ICMP)
	printICMP(&packetAnalysis)
}

// PrintPacketAnalysis prints a formatted output for the packet analysis.
func printICMP(analysis *model.PacketAnalysisICMP) {
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

	// Print ICMP information
	if analysis.ICMP.Type != 0 || analysis.ICMP.Code != 0 {
		fmt.Printf("[ICMP] Packet ID: %d | Type: %d | Code: %d | Checksum: 0x%X | ID: %d | Sequence: %d\n",
			analysis.PacketID, analysis.ICMP.Type, analysis.ICMP.Code,
			analysis.ICMP.Checksum, analysis.ICMP.ID, analysis.ICMP.Sequence)
	}

	fmt.Println()
}
