package service

import (
	"encoding/binary"
	"fmt"
	"main/model"
	"net"
	"sync"
	"time"
)

type ICMP struct {
	FeatureAnalyzer  map[string]*FeatureAnalyzer
	timeoutSignal    chan string
	mutexLock        sync.Mutex
	lastPredictionTS map[string]time.Time
}

func NewICMP() *ICMP {

	icmp := &ICMP{
		FeatureAnalyzer:  make(map[string]*FeatureAnalyzer),
		timeoutSignal:    make(chan string),
		lastPredictionTS: make(map[string]time.Time),
	}

	go icmp.FlowMapTimeout()

	return icmp
}

func (i *ICMP) AnalyzeICMP(payload []byte) {
	if len(payload) < 20 { // Ensure packet is large enough for analysis
		fmt.Println("[ERROR] Payload size is too small to analyze.")
		return
	}

	versionIHL := payload[0]
	version := versionIHL >> 4 // Get the IP version (4 or 6)

	var packetAnalysis model.PacketAnalysisICMP

	switch version {
	case 4:
		i.analyzeIPv4(payload, &packetAnalysis)
	default:
		fmt.Printf("[WARNING] Unsupported IP version %d\n", version)
		return
	}

	forwardKey := fmt.Sprintf("%s-%s", packetAnalysis.IPv4.SourceIP, packetAnalysis.IPv4.DestinationIP)
	backwardKey := fmt.Sprintf("%s-%s", packetAnalysis.IPv4.DestinationIP, packetAnalysis.IPv4.SourceIP)

	i.mutexLock.Lock()
	defer i.mutexLock.Unlock()

	// AI PREDICTION
	// var key string
	var direction string
	var featureAnalyzer *FeatureAnalyzer
	var ok bool

	if featureAnalyzer, ok = i.FeatureAnalyzer[forwardKey]; ok {
		// AI PREDICTION
		// key = forwardKey
		direction = "forward"
	} else if featureAnalyzer, ok = i.FeatureAnalyzer[backwardKey]; ok {
		// AI PREDICTION
		// key = backwardKey
		direction = "backward"
	} else {
		i.FeatureAnalyzer[forwardKey] = GetFeatureAnalyzerInstanceICMP(&packetAnalysis, forwardKey, i.timeoutSignal)
		return
	}

	featureAnalyzer.updateFeaturesICMP(&packetAnalysis, direction)

	// AI PREDICTION :

	// if int(featureAnalyzer.features.FlowDuration/1e6)%7 == 6 {
	// 	lastTS, exists := i.lastPredictionTS[key]
	// 	now := time.Now()

	// 	// Ensure at least 1 second has passed since the last prediction
	// 	if !exists || now.Sub(lastTS) >= time.Second {
	// 		fmt.Println("precision for : ", key)
	// 		i.lastPredictionTS[key] = now
	// 		dataString := returnDataIntoString(featureAnalyzer)
	// 		_, err := getPrediction(dataString)
	// 		if err != nil {
	// 			fmt.Println("Error getting prediction:", err)
	// 		}
	// 	}
	// }

}

func (i *ICMP) FlowMapTimeout() {
	var key string
	for {
		select {
		case key = <-i.timeoutSignal:
			// fmt.Println("Timeout signal received for key: ", key)

			err := WriteToCSV("test", i.FeatureAnalyzer[key])
			if err != nil {
				fmt.Println("Error writing to CSV file: ", err)
			}

			fmt.Println("[ ICMP ]Timeout signal received for key: ", key)

			// AI PREDICTION
			// _, err = getPrediction(returnDataIntoString(i.FeatureAnalyzer[key]))
			// if err != nil {
			// 	fmt.Println("Error getting prediction: ", err)
			// }

			delete(i.FeatureAnalyzer, key)
		case <-time.After(10 * time.Second): // Prevent blocking forever
			// PASS
		}
	}
}

func (i *ICMP) analyzeIPv4(payload []byte, packetAnalysis *model.PacketAnalysisICMP) {
	ihl := int((payload[0] & 0x0F) * 4)
	if len(payload) < ihl+4 {
		fmt.Println("[ERROR] Invalid IPv4 header length")
		return
	}

	packetAnalysis.IPv4 = &model.IPv4Info{
		TotalLength:   binary.BigEndian.Uint16(payload[2:4]),
		Protocol:      payload[9],
		SourceIP:      net.IP(payload[12:16]).String(),
		DestinationIP: net.IP(payload[16:20]).String(),
	}

	i.analyzeICMPHeader(payload[ihl:], packetAnalysis)
}

func (i *ICMP) analyzeICMPHeader(payload []byte, packetAnalysis *model.PacketAnalysisICMP) {
	if len(payload) < 4 { // Ensure there is enough data for the ICMP header
		fmt.Println("[ERROR] Invalid ICMP header length")
		return
	}

	packetAnalysis.ICMP = &model.ICMPInfo{
		Type: uint64(payload[0]),
		Code: uint64(payload[1]),
	}

	// If it's an ICMP echo request/reply, capture the additional data
	if packetAnalysis.ICMP.Type == 8 || packetAnalysis.ICMP.Type == 0 {
		packetAnalysis.ICMP.Payload = payload[4:] // ICMP data starts after header
	}
}
