package service

import (
	"encoding/binary"
	"fmt"
	"main/model"
	"net"
	"sync"
	"time"
)

type TCP struct {
	FeatureAnalyzer  map[string]*FeatureAnalyzer
	timeoutSignal    chan string
	mutexLock        sync.Mutex
	lastPredictionTS map[string]time.Time
}

func NewTCP() *TCP {

	tcp := &TCP{
		FeatureAnalyzer:  make(map[string]*FeatureAnalyzer),
		timeoutSignal:    make(chan string),
		lastPredictionTS: make(map[string]time.Time),
	}

	go tcp.FlowMapTimeout()

	return tcp
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

	forwardKey := fmt.Sprintf("%s-%s:%d", packetAnalysis.IPv4.SourceIP, packetAnalysis.IPv4.DestinationIP, packetAnalysis.TCP.DestinationPort)
	backwardKey := fmt.Sprintf("%s-%s:%d", packetAnalysis.IPv4.DestinationIP, packetAnalysis.IPv4.SourceIP, packetAnalysis.TCP.SourcePort)

	t.mutexLock.Lock()
	defer t.mutexLock.Unlock()

	// AI PREDICTION
	// var key string
	var direction string
	var featureAnalyzer *FeatureAnalyzer
	var ok bool

	if featureAnalyzer, ok = t.FeatureAnalyzer[forwardKey]; ok {
		// AI PREDICTION
		// key = forwardKey
		direction = "forward"
	} else if featureAnalyzer, ok = t.FeatureAnalyzer[backwardKey]; ok {
		// AI PREDICTION
		// key = backwardKey
		direction = "backward"
	} else {
		t.FeatureAnalyzer[forwardKey] = GetFeatureAnalyzerInstance(&packetAnalysis, forwardKey, t.timeoutSignal)
		return
	}

	featureAnalyzer.updateFeatures(&packetAnalysis, direction)

	// AI PREDICTION
	// if int(featureAnalyzer.features.FlowDuration/1e6)%7 == 6 {
	// 	lastTS, exists := t.lastPredictionTS[key]
	// 	now := time.Now()

	// 	// Ensure at least 1 second has passed since the last prediction
	// 	if !exists || now.Sub(lastTS) >= time.Second {
	// 		fmt.Println("precision for : ", key)
	// 		t.lastPredictionTS[key] = now
	// 		dataString := returnDataIntoString(featureAnalyzer)
	// 		_, err := getPrediction(dataString)
	// 		if err != nil {
	// 			fmt.Println("Error getting prediction:", err)
	// 		}

	// 	}
	// }

}

func (t *TCP) FlowMapTimeout() {
	var key string
	for {
		select {
		case key = <-t.timeoutSignal:
			// fmt.Println("Timeout signal received for key: ", key)

			// normal := "tcp_features_normal"
			// // attack := "tcp_features"

			err := WriteToCSV("test", t.FeatureAnalyzer[key])
			if err != nil {
				fmt.Println("Error writing to CSV file: ", err)
			}

			fmt.Println("[ TCP ] Timeout signal received for key: ", key)

			// AI Prediction
			// _, err = getPrediction(returnDataIntoString(t.FeatureAnalyzer[key]))
			// if err != nil {
			// 	fmt.Println("Error getting prediction: ", err)
			// }

			delete(t.FeatureAnalyzer, key)
		case <-time.After(10 * time.Second): // Prevent blocking forever
			// PASS
		}
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

	tcpHeaderLength := (payload[12] >> 4) * 4 // Header length in 32-bit words
	if len(payload) < int(tcpHeaderLength) {
		fmt.Println("[ERROR] Invalid TCP header length")
		return
	}

	packetAnalysis.TCP.Payload = payload[tcpHeaderLength:]
	packetAnalysis.TCP.HeaderLength = uint64(tcpHeaderLength)

}
