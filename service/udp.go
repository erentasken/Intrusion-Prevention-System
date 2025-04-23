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

var csvToggleUdp = false

type UDP struct {
	FeatureAnalyzer  map[string]*FeatureAnalyzer
	timeoutSignal    chan string
	mutexLock        sync.Mutex
	lastPredictionTS map[string]time.Time
	alert            chan model.Detection
}

func NewUDP(alert chan model.Detection) *UDP {
	udp := &UDP{
		FeatureAnalyzer:  make(map[string]*FeatureAnalyzer),
		timeoutSignal:    make(chan string),
		lastPredictionTS: make(map[string]time.Time),
		alert:            alert,
	}

	go udp.FlowMapTimeout()

	return udp
}

func CsvToggleUDP() {
	if csvToggleUdp {
		csvToggleUdp = false
	} else {
		csvToggleUdp = true
	}
}

func (u *UDP) AnalyzeUDP(payload []byte) {
	if len(payload) < 28 { // Ensure packet is large enough for analysis
		fmt.Println("[ERROR] Payload size is too small to analyze.")
		return
	}

	versionIHL := payload[0]
	version := versionIHL >> 4 // Get the IP version (4 or 6)

	var packetAnalysis model.PacketAnalysisUDP

	switch version {
	case 4:
		u.analyzeIPv4ForUDP(payload, &packetAnalysis)

		// if packetAnalysis.IPv4.SourceIP == "127.0.0.1" {
		// 	return
		// }

	default:
		fmt.Printf("[WARNING] Unsupported IP version %d\n", version)
		return
	}

	forwardKey := fmt.Sprintf("%s-%s", packetAnalysis.IPv4.SourceIP, packetAnalysis.IPv4.DestinationIP)
	backwardKey := fmt.Sprintf("%s-%s", packetAnalysis.IPv4.DestinationIP, packetAnalysis.IPv4.SourceIP)

	u.mutexLock.Lock()
	defer u.mutexLock.Unlock()

	// AI PREDICTION
	var key string
	var direction string
	var featureAnalyzer *FeatureAnalyzer
	var ok bool

	if featureAnalyzer, ok = u.FeatureAnalyzer[forwardKey]; ok {
		// AI PREDICTION
		key = forwardKey
		direction = "forward"
	} else if featureAnalyzer, ok = u.FeatureAnalyzer[backwardKey]; ok {
		// AI PREDICTION
		key = backwardKey
		direction = "backward"
	} else {
		u.FeatureAnalyzer[forwardKey] = GetFeatureAnalyzerInstanceUDP(&packetAnalysis, forwardKey, u.timeoutSignal)
		return
	}

	if featureAnalyzer.port != fmt.Sprint(packetAnalysis.UDP.DestinationPort) {
		featureAnalyzer.multiplePort = true
	}

	featureAnalyzer.updateFeaturesUDP(&packetAnalysis, direction)

	// AI PREDICTION
	if int(featureAnalyzer.features.FlowDuration/1e6)%7 == 4 {
		lastTS, exists := u.lastPredictionTS[key]
		now := time.Now()

		// Ensure at least 1 second has passed since the last prediction
		if !exists || now.Sub(lastTS) >= time.Second {
			u.lastPredictionTS[key] = now
			dataString := returnDataIntoString(featureAnalyzer)
			pred, err := getPrediction(dataString)
			if err != nil {
				fmt.Println("Error getting prediction:", err)
			}

			fmt.Println(key, " : ", pred)
			splitted := strings.Split(key, "-")
			attackerIp := splitted[0]
			// targetPort := strings.Split(splitted[1], ":")[1]

			if strings.Count(pred, "1") >= 3 {
				attack_alert := model.Detection{
					Method:      "AI Detection",
					Protocol:    "UDP",
					Attacker_ip: attackerIp,
					Target_port: featureAnalyzer.port,
					Message:     "DDOS Attack Detected",
				}

				if featureAnalyzer.multiplePort {
					attack_alert.Message = "Targeted on multiple port"
				}

				if attackerIp == "127.0.0.1" || attackerIp == "172.30.0.2" {
					return
				}

				u.alert <- attack_alert
			}
		}
	}
}

func (u *UDP) FlowMapTimeout() {
	var key string
	for {
		select {
		case key = <-u.timeoutSignal:
			u.mutexLock.Lock()

			if csvToggleUdp {
				err := WriteToCSV("udp", u.FeatureAnalyzer[key])
				if err != nil {
					fmt.Println("Error writing to CSV file: ", err)
				}
			}

			// fmt.Println("[ UDP ] Timeout signal received for key: ", key)

			// AI Prediction
			pred, err := getPrediction(returnDataIntoString(u.FeatureAnalyzer[key]))
			if err != nil {
				fmt.Println("Error getting prediction: ", err)
			}

			fmt.Println(key, " : ", pred)
			splitted := strings.Split(key, "-")
			attackerIp := splitted[0]
			// targetPort := strings.Split(splitted[1], ":")[1]

			if strings.Count(pred, "1") >= 3 {
				attack_alert := model.Detection{
					Method:      "AI Detection",
					Protocol:    "UDP",
					Attacker_ip: attackerIp,
					Target_port: u.FeatureAnalyzer[key].port,
					Message:     "DDOS Attack Detected",
				}

				if u.FeatureAnalyzer[key].multiplePort {
					attack_alert.Message = "Targeted on multiple port"
				}

				if attackerIp != "127.0.0.1" && attackerIp != "172.30.0.2" {
					u.alert <- attack_alert
				}

			}

			delete(u.FeatureAnalyzer, key)

			u.mutexLock.Unlock()

		case <-time.After(5 * time.Second): // Prevent blocking forever
			// PASS
		}
	}
}

func (u *UDP) analyzeIPv4ForUDP(payload []byte, packetAnalysis *model.PacketAnalysisUDP) {
	ihl := int((payload[0] & 0x0F) * 4)
	if len(payload) < ihl+8 {
		fmt.Println("[ERROR] Invalid IPv4 header length")
		return
	}

	packetAnalysis.IPv4 = &model.IPv4Info{
		TotalLength:   binary.BigEndian.Uint16(payload[2:4]),
		Protocol:      payload[9],
		SourceIP:      net.IP(payload[12:16]).String(),
		DestinationIP: net.IP(payload[16:20]).String(),
	}

	udpStart := ihl
	u.analyzeUDPHeader(payload[udpStart:], packetAnalysis)
}

func (u *UDP) analyzeUDPHeader(payload []byte, packetAnalysis *model.PacketAnalysisUDP) {
	if len(payload) < 8 { // Ensure that there is enough data for the UDP header
		fmt.Println("[ERROR] Invalid UDP header length")
		return
	}

	sourcePort := binary.BigEndian.Uint16(payload[0:2])
	destinationPort := binary.BigEndian.Uint16(payload[2:4])
	length := binary.BigEndian.Uint16(payload[4:6])

	packetAnalysis.UDP = &model.UDPInfo{
		SourcePort:      uint64(sourcePort),
		DestinationPort: uint64(destinationPort),
		Length:          uint64(length),
		Payload:         payload[8:], // UDP payload starts after 8-byte header
	}
}
