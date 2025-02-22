package service

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"main/config"
	"main/model"
	"net"
	"net/http"
	"strings"
)

type TCP struct {
	redisWrapper *config.RedisWrapper
}

func NewTCP(redisWrapper *config.RedisWrapper) *TCP {
	return &TCP{redisWrapper: redisWrapper}
}

func (t *TCP) AnalyzeTCP(payload []byte) {
	if len(payload) < 40 {
		return
	}

	// Determine if the packet is IPv4 or IPv6 based on the first byte (version field)
	versionIHL := payload[0]
	version := versionIHL >> 4 // Get the IP version (4 or 6)

	var packetAnalysis model.PacketAnalysisTCP

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

		// Extract TCP header fields (starting after the IP header)
		tcpStart := ihl
		packetAnalysis.TCP = &model.TCPInfo{
			SourcePort:           binary.BigEndian.Uint16(payload[tcpStart : tcpStart+2]),
			DestinationPort:      binary.BigEndian.Uint16(payload[tcpStart+2 : tcpStart+4]),
			SequenceNumber:       binary.BigEndian.Uint32(payload[tcpStart+4 : tcpStart+8]),
			AcknowledgmentNumber: binary.BigEndian.Uint32(payload[tcpStart+8 : tcpStart+12]),
			SYN:                  payload[tcpStart+13]&0x02 != 0,
			ACK:                  payload[tcpStart+13]&0x10 != 0,
			FIN:                  payload[tcpStart+13]&0x01 != 0,
			RST:                  payload[tcpStart+13]&0x04 != 0,
		}

		// Extract payload (application data)
		tcpHeaderLength := (payload[tcpStart+12] >> 4) * 4 // Get TCP header length (in bytes)
		payloadData := payload[tcpStart+tcpHeaderLength:]  // Data starts after the TCP header
		packetAnalysis.TCP.Payload = payloadData
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

		// Extract TCP header fields (starting after the IPv6 header)
		tcpStart := 40 // IPv6 header is 40 bytes
		packetAnalysis.TCP = &model.TCPInfo{
			SourcePort:           binary.BigEndian.Uint16(payload[tcpStart : tcpStart+2]),
			DestinationPort:      binary.BigEndian.Uint16(payload[tcpStart+2 : tcpStart+4]),
			SequenceNumber:       binary.BigEndian.Uint32(payload[tcpStart+4 : tcpStart+8]),
			AcknowledgmentNumber: binary.BigEndian.Uint32(payload[tcpStart+8 : tcpStart+12]),
			SYN:                  payload[tcpStart+13]&0x02 != 0,
			ACK:                  payload[tcpStart+13]&0x10 != 0,
			FIN:                  payload[tcpStart+13]&0x01 != 0,
			RST:                  payload[tcpStart+13]&0x04 != 0,
		}

		tcpHeaderLength := int((payload[tcpStart+12] >> 4) * 4)
		payloadData := payload[tcpStart+tcpHeaderLength:] // Data starts after the TCP header
		packetAnalysis.TCP.Payload = payloadData
	} else {
		fmt.Printf("[WARNING] Unsupported IP version %d\n", version)
		return
	}

	// Print the detailed packet analysis (IPv4 or IPv6 + TCP)
	printTCP(&packetAnalysis)

}

// PrintPacketAnalysis prints a formatted output for the packet analysis.
func printTCP(analysis *model.PacketAnalysisTCP) {
	if analysis == nil {
		return
	}

	// Print IPv4 or IPv6 information
	if analysis.IPv4 != nil {
		fmt.Printf("[IPv4] Packet ID: %d | Version: %d | IHL: %d bytes | Total Length: %d | TTL: %d | Protocol: %d\n",
			analysis.IPv4.Version, analysis.IPv4.IHL, analysis.IPv4.TotalLength,
			analysis.IPv4.TTL, analysis.IPv4.Protocol)

		fmt.Printf("[IPv4] Source: %s → Destination: %s | Identification: %d | Flags & Offset: %d\n",
			analysis.IPv4.SourceIP, analysis.IPv4.DestinationIP, analysis.IPv4.Identification, analysis.IPv4.FlagsFragmentOffset)

	} else if analysis.IPv6 != nil {
		fmt.Printf("[IPv6] Version: %d | Payload Length: %d | Hop Limit: %d | Next Header: %d\n",
			analysis.IPv6.Version, analysis.IPv6.PayloadLength, analysis.IPv6.HopLimit,
			analysis.IPv6.NextHeader)

		fmt.Printf("[IPv6] Source: %s → Destination: %s\n",
			analysis.IPv6.SourceIP, analysis.IPv6.DestinationIP)
	}

	// Print TCP information
	if analysis.TCP.SourcePort != 0 && analysis.TCP.DestinationPort != 0 {
		fmt.Printf("%s:%d → %s:%d | Seq: %d | Ack: %d | SYN:%t ACK:%t FIN:%t RST:%t\n",
			analysis.IPv4.SourceIP, analysis.TCP.SourcePort,
			analysis.IPv4.DestinationIP, analysis.TCP.DestinationPort,
			analysis.TCP.SequenceNumber, analysis.TCP.AcknowledgmentNumber,
			analysis.TCP.SYN, analysis.TCP.ACK, analysis.TCP.FIN, analysis.TCP.RST)

		if len(analysis.TCP.Payload) != 0 {
			switch analysis.TCP.DestinationPort {
			case 80:
				AnalyzeHttp(analysis)
			case 443:
				AnalyzeHttps(analysis)
			default:
				fmt.Println("Protocol: Unknown")
			}
		}

	}

	fmt.Println()

}

func AnalyzeHttp(analysis *model.PacketAnalysisTCP) {
	reader := bufio.NewReader(strings.NewReader(string(analysis.TCP.Payload)))

	// Parse the request
	req, err := http.ReadRequest(reader)
	if err != nil {
		fmt.Println("Error parsing request:", err)
		return
	}

	// Print extracted detailsA
	fmt.Println("Method:", req.Method)
	fmt.Println("URL Path:", req.URL.Path)
	fmt.Println("Query Params:", req.URL.RawQuery)
	fmt.Println("Host:", req.Host)
	fmt.Println("User-Agent:", req.Header.Get("User-Agent"))
}

func AnalyzeHttps(analysis *model.PacketAnalysisTCP) {
	reader := bufio.NewReader(strings.NewReader(string(analysis.TCP.Payload)))

	// Parse the request
	req, err := http.ReadRequest(reader)
	if err != nil {
		fmt.Println("Error parsing request:", err)
		return
	}

	// Print extracted details
	fmt.Println("Method:", req.Method)
	fmt.Println("URL Path:", req.URL.Path)
	fmt.Println("Query Params:", req.URL.RawQuery)
	fmt.Println("Host:", req.Host)
	fmt.Println("User-Agent:", req.Header.Get("User-Agent"))
}

// AnalyzeHttp is a function that analyzes HTTP packets.
func AnalyzeICMP(packetID uint32, payload []byte) {
	fmt.Println("ICMP Packet")
}

// package analyzer

// import (
// 	"encoding/binary"
// 	"fmt"
// 	"net"
// 	"sync"
// 	"time"
// )

// // Flow structure to track statistics
// type Flow struct {
// 	FlowStartTime    time.Time
// 	FlowLastSeen     time.Time
// 	FlowDuration     time.Duration
// 	TotalFwdPackets  int             // Total number of packets sent in the forward direction (client → server)
// 	TotalBwdPackets  int             // Total number of packets sent in the backward direction (server → client)
// 	TotalFwdBytes    int             // Total number of bytes sent in the forward direction
// 	TotalBwdBytes    int             // Total number of bytes sent in the backward direction
// 	FwdPacketLengths []int           // List of sizes of individual forward packets
// 	BwdPacketLengths []int           // List of sizes of individual backward packets
// 	FwdIAT           []time.Duration // Inter-Arrival Times (IAT) for forward packets (time between consecutive packets)
// 	BwdIAT           []time.Duration // Inter-Arrival Times (IAT) for backward packets
// 	LastFwdTimestamp time.Time       // Timestamp of the last forward packet seen
// 	LastBwdTimestamp time.Time       // Timestamp of the last backward packet seen
// 	Flags            map[string]int
// }

// // Flow table
// var (
// 	flowTable = make(map[string]*Flow)
// 	mu        sync.Mutex
// )

// // AnalyzeTCP processes a TCP packet and updates flow statistics
// func AnalyzeTCP(packetID uint32, payload []byte) {
// 	timestamp := time.Now()

// 	if len(payload) < 40 {
// 		fmt.Printf("[WARNING] Packet ID %d: Malformed packet (too short)\n", packetID)
// 		return
// 	}

// 	version := payload[0] >> 4
// 	var sourceIP, destinationIP string
// 	var sourcePort, destinationPort uint16
// 	var payloadSize int

// 	if version == 4 {
// 		ihl := (payload[0] & 0x0F) * 4
// 		sourceIP = net.IP(payload[12:16]).String()
// 		destinationIP = net.IP(payload[16:20]).String()
// 		tcpStart := ihl
// 		sourcePort = binary.BigEndian.Uint16(payload[tcpStart : tcpStart+2])
// 		destinationPort = binary.BigEndian.Uint16(payload[tcpStart+2 : tcpStart+4])
// 		tcpHeaderLength := (payload[tcpStart+12] >> 4) * 4
// 		payloadSize = len(payload[tcpStart+tcpHeaderLength:])
// 	} else if version == 6 {
// 		sourceIP = net.IP(payload[8:24]).String()
// 		destinationIP = net.IP(payload[24:40]).String()
// 		tcpStart := 40
// 		sourcePort = binary.BigEndian.Uint16(payload[tcpStart : tcpStart+2])
// 		destinationPort = binary.BigEndian.Uint16(payload[tcpStart+2 : tcpStart+4])
// 		tcpHeaderLength := (payload[tcpStart+12] >> 4) * 4
// 		payloadSize = len(payload[byte(tcpStart)+tcpHeaderLength:])
// 	} else {
// 		fmt.Printf("[WARNING] Unsupported IP version %d in packet ID %d\n", version, packetID)
// 		return
// 	}

// 	// Generate Flow Key
// 	flowKey := fmt.Sprintf("%s:%d-%s:%d", sourceIP, sourcePort, destinationIP, destinationPort)
// 	mu.Lock()
// 	defer mu.Unlock()

// 	flow, exists := flowTable[flowKey]
// 	if !exists {
// 		flow = &Flow{
// 			FlowStartTime: timestamp,
// 			Flags:         make(map[string]int),
// 		}
// 		flowTable[flowKey] = flow
// 	}

// 	// Update flow metrics
// 	flow.FlowLastSeen = timestamp
// 	flow.FlowDuration = timestamp.Sub(flow.FlowStartTime)

// 	if sourceIP < destinationIP { // Forward direction
// 		flow.TotalFwdPackets++
// 		flow.TotalFwdBytes += payloadSize
// 		flow.FwdPacketLengths = append(flow.FwdPacketLengths, payloadSize)
// 		if !flow.LastFwdTimestamp.IsZero() {
// 			flow.FwdIAT = append(flow.FwdIAT, timestamp.Sub(flow.LastFwdTimestamp))
// 		}
// 		flow.LastFwdTimestamp = timestamp
// 	} else { // Backward direction
// 		flow.TotalBwdPackets++
// 		flow.TotalBwdBytes += payloadSize
// 		flow.BwdPacketLengths = append(flow.BwdPacketLengths, payloadSize)
// 		if !flow.LastBwdTimestamp.IsZero() {
// 			flow.BwdIAT = append(flow.BwdIAT, timestamp.Sub(flow.LastBwdTimestamp))
// 		}
// 		flow.LastBwdTimestamp = timestamp
// 	}

// 	// Update TCP Flags
// 	flags := payload[13]
// 	if flags&0x01 != 0 {
// 		flow.Flags["FIN"]++
// 	}
// 	if flags&0x02 != 0 {
// 		flow.Flags["SYN"]++
// 	}
// 	if flags&0x04 != 0 {
// 		flow.Flags["RST"]++
// 	}
// 	if flags&0x08 != 0 {
// 		flow.Flags["PSH"]++
// 	}
// 	if flags&0x10 != 0 {
// 		flow.Flags["ACK"]++
// 	}
// 	if flags&0x20 != 0 {
// 		flow.Flags["URG"]++
// 	}

// 	// Expire old flows
// 	expireInactiveFlows()
// }

// // Expire inactive flows
// func expireInactiveFlows() {
// 	timeout := 30 * time.Second // Expire flows after 30s of inactivity
// 	now := time.Now()
// 	for key, flow := range flowTable {
// 		if now.Sub(flow.FlowLastSeen) > timeout {
// 			fmt.Printf("[INFO] Expiring flow %s\n", key)
// 			delete(flowTable, key)
// 		}
// 	}
// }

// // Print summary of flow statistics
// func PrintFlowStatistics() {
// 	mu.Lock()
// 	defer mu.Unlock()

// 	for key, flow := range flowTable {
// 		fmt.Printf("Flow: %s\n", key)
// 		fmt.Printf("  Duration: %v\n", flow.FlowDuration)
// 		fmt.Printf("  Forward Packets: %d, Bytes: %d\n", flow.TotalFwdPackets, flow.TotalFwdBytes)
// 		fmt.Printf("  Backward Packets: %d, Bytes: %d\n", flow.TotalBwdPackets, flow.TotalBwdBytes)
// 		fmt.Printf("  Fwd Mean Packet Length: %d\n", mean(flow.FwdPacketLengths))
// 		fmt.Printf("  Bwd Mean Packet Length: %d\n", mean(flow.BwdPacketLengths))
// 		fmt.Printf("  Flags: SYN=%d, ACK=%d, FIN=%d, RST=%d, PSH=%d, URG=%d\n",
// 			flow.Flags["SYN"], flow.Flags["ACK"], flow.Flags["FIN"], flow.Flags["RST"], flow.Flags["PSH"], flow.Flags["URG"])
// 		fmt.Println()
// 	}
// }

// // Helper function to compute mean
// func mean(arr []int) int {
// 	if len(arr) == 0 {
// 		return 0
// 	}
// 	sum := 0
// 	for _, v := range arr {
// 		sum += v
// 	}
// 	return sum / len(arr)
// }
