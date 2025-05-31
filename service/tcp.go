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

var csvToggleTcp = false

type TCP struct {
	FeatureAnalyzer  map[string]*FeatureAnalyzer
	timeoutSignal    chan string
	mutexLock        sync.Mutex
	lastPredictionTS map[string]time.Time
	alert            chan<- model.Detection
}

func NewTCP(alert chan model.Detection) *TCP {

	tcp := &TCP{
		FeatureAnalyzer:  make(map[string]*FeatureAnalyzer),
		timeoutSignal:    make(chan string),
		lastPredictionTS: make(map[string]time.Time),
		alert:            alert,
	}

	go tcp.FlowMapTimeout()

	return tcp
}

func CsvToggleTCP() {
	if csvToggleTcp {
		csvToggleTcp = false
	} else {
		csvToggleTcp = true
	}
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

	forwardKey := fmt.Sprintf("%s-%s", packetAnalysis.IPv4.SourceIP, packetAnalysis.IPv4.DestinationIP)
	backwardKey := fmt.Sprintf("%s-%s", packetAnalysis.IPv4.DestinationIP, packetAnalysis.IPv4.SourceIP)

	t.mutexLock.Lock()
	defer t.mutexLock.Unlock()

	// AI PREDICTION
	var key string
	var direction string
	var featureAnalyzer *FeatureAnalyzer
	var ok bool

	if featureAnalyzer, ok = t.FeatureAnalyzer[forwardKey]; ok {
		// AI PREDICTION
		key = forwardKey
		direction = "forward"
	} else if featureAnalyzer, ok = t.FeatureAnalyzer[backwardKey]; ok {
		// AI PREDICTION
		key = backwardKey
		direction = "backward"
	} else {
		t.FeatureAnalyzer[forwardKey] = GetFeatureAnalyzerInstance(&packetAnalysis, forwardKey, t.timeoutSignal)
		return
	}

	if featureAnalyzer.port != fmt.Sprint(packetAnalysis.TCP.DestinationPort) && direction == "forward" {
		featureAnalyzer.multiplePort = true
	}

	featureAnalyzer.updateFeatures(&packetAnalysis, direction)

	// AI PREDICTION
	if int(featureAnalyzer.features.FlowDuration/1e6)%3 == 2 {
		lastTS, exists := t.lastPredictionTS[key]
		now := time.Now()

		// Ensure at least 1 second has passed since the last prediction
		if !exists || now.Sub(lastTS) >= time.Second {
			t.lastPredictionTS[key] = now	
			dataString := returnDataIntoString(featureAnalyzer)
			
			t.PredictAndAlert(dataString, key)
		}
	}
}

func (t *TCP) FlowMapTimeout() {
	var key string
	for {
		select {
		case key = <-t.timeoutSignal:
			t.mutexLock.Lock()

			if csvToggleTcp {
				err := WriteToCSV("tcp", t.FeatureAnalyzer[key])
				if err != nil {
					fmt.Println("Error writing to CSV file: ", err)
				}
			}
			dataString := returnDataIntoString(t.FeatureAnalyzer[key])

			t.PredictAndAlert(dataString, key)

			delete(t.FeatureAnalyzer, key)
			t.mutexLock.Unlock()
		case <-time.After(3 * time.Second): // Prevent blocking forever
			// PASS
		}
	}
}

func (t *TCP) PredictAndAlert(dataString []string, key string){
	// AI Prediction
	pred, err := getPrediction(dataString)
	if err != nil {
		fmt.Println("Error getting prediction: ", err)
	}

	fmt.Println(key, " : ", pred)
	splitted := strings.Split(key, "-")
	attackerIp := splitted[0]
	// targetPort := strings.Split(splitted[1], ":")[1]

	if strings.Count(pred, "1") > 4 {
		attack_alert := model.Detection{
			Method:      "AI Detection",
			Protocol:    "TCP",
			AttackerIP: attackerIp,
			TargetPort: t.FeatureAnalyzer[key].port,
			Message:     "DDOS Attack Detected",
		}

		if t.FeatureAnalyzer[key].multiplePort {
			attack_alert.Message = "Targeted on multiple port"
		}

		// if attackerIp != "127.0.0.1" && attackerIp != "172.30.0.2" {
		// 	t.alert <- attack_alert
		// }
		t.alert <- attack_alert

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
	t.analyzeHeader(payload[tcpStart:], packetAnalysis)
}

func (t *TCP) analyzeHeader(payload []byte, packetAnalysis *model.PacketAnalysisTCP) {
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
