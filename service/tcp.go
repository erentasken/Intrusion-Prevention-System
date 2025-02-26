package service

import (
	"encoding/binary"
	"fmt"
	"main/model"
	"net"
)

type TCP struct {
	FeatureAnalyzer map[string]*FeatureAnalyzer
}

func NewTCP() *TCP {
	return &TCP{
		FeatureAnalyzer: make(map[string]*FeatureAnalyzer),
	} // TODO
}

func (t *TCP) AnalyzeTCP(payload []byte) {
	if len(payload) < 40 { // Ensure packet is large enough for analysis
		fmt.Println("[ERROR] Payload size is too small to analyze.")
		return
	}

	versionIHL := payload[0]
	version := versionIHL >> 4 // Get the IP version (4 or 6)

	var packetAnalysis model.PacketAnalysisTCP

	switch version {
	case 4:
		t.analyzeIPv4(payload, &packetAnalysis)
	default:
		fmt.Printf("[WARNING] Unsupported IP version %d\n", version)
		return
	}

	forwardKey := fmt.Sprintf("%s:%d-%s:%d", packetAnalysis.IPv4.SourceIP, packetAnalysis.TCP.SourcePort, packetAnalysis.IPv4.DestinationIP, packetAnalysis.TCP.DestinationPort)
	backwardKey := fmt.Sprintf("%s:%d-%s:%d", packetAnalysis.IPv4.DestinationIP, packetAnalysis.TCP.DestinationPort, packetAnalysis.IPv4.SourceIP, packetAnalysis.TCP.SourcePort)

	fmt.Println("forward key ", forwardKey)

	if featureAnalyzer, ok := t.FeatureAnalyzer[forwardKey]; ok {
		featureAnalyzer.updateFeatures(&packetAnalysis, "forward")
	} else if featureAnalyzer, ok := t.FeatureAnalyzer[backwardKey]; ok {
		featureAnalyzer.updateFeatures(&packetAnalysis, "backward")

	} else {
		t.FeatureAnalyzer[forwardKey] = GetFeatureAnalyzerInstance(&packetAnalysis)
	}

}

func (t *TCP) analyzeIPv4(payload []byte, packetAnalysis *model.PacketAnalysisTCP) {
	ihl := int((payload[0] & 0x0F) * 4)
	if len(payload) < ihl+20 {
		fmt.Println("[ERROR] Invalid IPv4 header length")
		return
	}

	packetAnalysis.IPv4 = &model.IPv4Info{
		TotalLength:   binary.BigEndian.Uint16(payload[2:4]),
		Protocol:      payload[9],
		SourceIP:      net.IP(payload[12:16]).String(),
		DestinationIP: net.IP(payload[16:20]).String(),
	}

	tcpStart := ihl
	t.analyzeTCPHeader(payload[tcpStart:], packetAnalysis)
}

func (t *TCP) analyzeTCPHeader(payload []byte, packetAnalysis *model.PacketAnalysisTCP) {
	if len(payload) < 20 { // Ensure that there is enough data for the TCP header
		fmt.Println("[ERROR] Invalid TCP header length")
		return
	}

	sourcePort := binary.BigEndian.Uint16(payload[0:2])
	destinationPort := binary.BigEndian.Uint16(payload[2:4])

	packetAnalysis.TCP = &model.TCPInfo{
		SourcePort:      uint64(sourcePort),
		DestinationPort: uint64(destinationPort),
		SYN:             payload[13]&0x02 != 0,
		ACK:             payload[13]&0x10 != 0,
		FIN:             payload[13]&0x01 != 0,
		RST:             payload[13]&0x04 != 0,
		PSH:             payload[13]&0x08 != 0,
		URG:             payload[13]&0x20 != 0,
		CWR:             payload[13]&0x80 != 0,
		ECE:             payload[13]&0x40 != 0,
	}

	fmt.Println("source port ", packetAnalysis.TCP.SourcePort)

	tcpHeaderLength := (payload[12] >> 4) * 4 // Header length in 32-bit words
	if len(payload) < int(tcpHeaderLength) {
		fmt.Println("[ERROR] Invalid TCP header length")
		return
	}

	packetAnalysis.TCP.Payload = payload[tcpHeaderLength:]
	packetAnalysis.TCP.HeaderLength = uint64(tcpHeaderLength)

}
