package service

import (
	"encoding/binary"
	"fmt"
	"main/model"
	"net"
	"strings"
	"sync"
	"time"
)

var csvToggleIcmp = false

type ICMP struct {
	FeatureAnalyzer  map[string]*FeatureAnalyzer
	timeoutSignal    chan string
	mutexLock        sync.Mutex
	lastPredictionTS map[string]time.Time
	alert            chan model.Detection
}

func NewICMP(alert chan model.Detection) *ICMP {

	icmp := &ICMP{
		FeatureAnalyzer:  make(map[string]*FeatureAnalyzer),
		timeoutSignal:    make(chan string),
		lastPredictionTS: make(map[string]time.Time),
		alert:            alert,
	}

	go icmp.FlowMapTimeout()

	return icmp
}

func CsvToggleICMP() {
	if csvToggleIcmp {
		csvToggleIcmp = false
	} else {
		csvToggleIcmp = true
	}
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
	var key string
	var direction string
	var featureAnalyzer *FeatureAnalyzer
	var ok bool

	if featureAnalyzer, ok = i.FeatureAnalyzer[forwardKey]; ok {
		// AI PREDICTION
		key = forwardKey
		direction = "forward"
	} else if featureAnalyzer, ok = i.FeatureAnalyzer[backwardKey]; ok {
		// AI PREDICTION
		key = backwardKey
		direction = "backward"
	} else {
		i.FeatureAnalyzer[forwardKey] = GetFeatureAnalyzerInstanceICMP(&packetAnalysis, forwardKey, i.timeoutSignal)
		return
	}

	featureAnalyzer.updateFeaturesICMP(&packetAnalysis, direction)

	// AI PREDICTION :
	if int(featureAnalyzer.features.FlowDuration/1e6)%3 == 2 {
		lastTS, exists := i.lastPredictionTS[key]
		now := time.Now()

		// Ensure at least 1 second has passed since the last prediction
		if !exists || now.Sub(lastTS) >= time.Second {
			i.lastPredictionTS[key] = now
			dataString := returnDataIntoString(featureAnalyzer)

			i.PredictAndAlert(dataString, key)
		}
	}

}

func (i *ICMP) PredictAndAlert(dataString []string, key string){ 
	pred, err := getPrediction(dataString)
	if err != nil {
		fmt.Println("Error getting prediction:", err)
	}

	splitted := strings.Split(key, "-")
	attackerIp := splitted[0]
	// fmt.Println(key, " : ", pred)

	count := strings.Count(pred, "1")

	if count > 5 {
		attack_alert := model.Detection{
			Method:      "AI Detection",
			Protocol:    "ICMP",
			AttackerIP: attackerIp,
			TargetPort: "",
			Message:     "DDOS Attack Detected",
		}

		i.alert <- attack_alert

	}
}

func (i *ICMP) FlowMapTimeout() {
	var key string
	for {
		select {
		case key = <-i.timeoutSignal:
			// fmt.Println("Timeout signal received for key: ", key)
			i.mutexLock.Lock()

			if csvToggleIcmp {
				err := WriteToCSV("icmp", i.FeatureAnalyzer[key])
				if err != nil {
					fmt.Println("Error writing to CSV file: ", err)
				}
			}

			var dataString = returnDataIntoString(i.FeatureAnalyzer[key])

			i.PredictAndAlert(dataString, key)

			delete(i.FeatureAnalyzer, key)
			i.mutexLock.Unlock()
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

	i.analyzeHeader(payload[ihl:], packetAnalysis)
}

func (i *ICMP) analyzeHeader(payload []byte, packetAnalysis *model.PacketAnalysisICMP) {
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
