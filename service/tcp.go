package service

import (
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"main/model"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TCP struct {
	FeatureAnalyzer map[string]*FeatureAnalyzer
	timeoutSignal   chan string
	mutexLock       sync.Mutex
}

func NewTCP() *TCP {

	tcp := &TCP{
		FeatureAnalyzer: make(map[string]*FeatureAnalyzer),
		timeoutSignal:   make(chan string),
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

	var dataString []string
	if featureAnalyzer, ok := t.FeatureAnalyzer[forwardKey]; ok {
		featureAnalyzer.updateFeatures(&packetAnalysis, "forward")

		if int(featureAnalyzer.features.FlowDuration)%5 == 0 {
			dataString = returnDataIntoString(featureAnalyzer)
			_, err := getPrediction(dataString)
			if err != nil {
				fmt.Println("Error getting prediction: ", err)
			}
		}

	} else if featureAnalyzer, ok := t.FeatureAnalyzer[backwardKey]; ok {
		featureAnalyzer.updateFeatures(&packetAnalysis, "backward")

		if int(featureAnalyzer.features.FlowDuration)%7 == 0 {
			dataString = returnDataIntoString(featureAnalyzer)
			_, err := getPrediction(dataString)
			if err != nil {
				fmt.Println("Error getting prediction: ", err)
			}
		}

	} else {
		t.FeatureAnalyzer[forwardKey] = GetFeatureAnalyzerInstance(&packetAnalysis, forwardKey, t.timeoutSignal)
	}

	t.mutexLock.Unlock()
}

func getPrediction(dataString []string) ([]float64, error) {
	// Connect to the Python server over TCP
	// fmt.Println("Connecting to server...")
	conn, err := net.Dial("tcp", "172.30.0.11:50051")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %v", err)
	}
	defer conn.Close()

	// fmt.Println("connection successful")

	// Serialize data using JSON
	data, err := json.Marshal(dataString)
	if err != nil {
		return nil, fmt.Errorf("failed to encode data: %v", err)
	}

	// Send the serialized data to the server
	_, err = conn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to send data: %v", err)
	}

	// Set a timeout to read the response
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	// Receive predictions from the server
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Deserialize the response
	var predictions []float64
	err = json.Unmarshal(resp[:n], &predictions)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	model_names := []string{
		"SVM", "Random Forest", "Logistic Regression",
		"Gradient Boosting", "XGBoost", "K-Nearest Neighbors", "Naïve Bayes", "NN",
	}

	var predictionString string
	for i, v := range model_names {
		predictionString += fmt.Sprintf("%s: %.2f  ", v, predictions[i])
	}

	fmt.Println(predictionString)

	return predictions, nil
}

func (t *TCP) FlowMapTimeout() {
	var key string
	for {
		select {
		case key = <-t.timeoutSignal:
			fmt.Println("Timeout signal received for key: ", key)

			// normal := "tcp_features_normal"
			// // attack := "tcp_features"

			// err := WriteToCSV(normal, t.FeatureAnalyzer[key])
			// if err != nil {
			// 	fmt.Println("Error writing to CSV file: ", err)
			// }

			delete(t.FeatureAnalyzer, key)
		case <-time.After(30 * time.Second): // Prevent blocking forever
			fmt.Println("No timeout signals received, continuing...")
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

func WriteToCSV(filename string, features *FeatureAnalyzer) error {

	// append to file do not rewrite

	csvName := filename + ".csv"

	file, err := os.OpenFile(csvName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	fileInfo, _ := file.Stat()
	if fileInfo.Size() == 0 {
		// header := []string{
		// 	"Destination Port", "Flow Duration",

		// 	"Total Fwd Packets", "Total Backward Packets",
		// 	"Total Length of Fwd Packets", "Total Length of Bwd Packets",

		// 	"Fwd Packet Length Max", "Fwd Packet Length Min",
		// 	"Fwd Packet Length Mean", "Fwd Packet Length Std",

		// 	"Bwd Packet Length Max", "Bwd Packet Length Min",
		// 	"Bwd Packet Length Mean", "Bwd Packet Length Std",

		// 	"Flow Bytes/s", "Flow Packets/s",

		// 	"Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
		// 	"Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
		// 	"Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",

		// 	"Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",

		// 	"Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
		// 	"Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",

		// 	"FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
		// 	"CWE Flag Count", "ECE Flag Count",

		// 	"Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
		// 	"Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",

		// 	"Subflow Fwd Packets", "Subflow Fwd Bytes",
		// 	"Subflow Bwd Packets", "Subflow Bwd Bytes",

		// 	"Active Mean", "Idle Mean",
		// }

		// header := []string{"Flow Duration", "Total Fwd Packets", "Total Backward Packets",
		// 	"Total Length of Fwd Packets", "Total Length of Bwd Packets",
		// 	"Fwd Packet Length Max", "Fwd Packet Length Min",
		// 	"Fwd Packet Length Mean", "Fwd Packet Length Std",
		// 	"Bwd Packet Length Max", "Bwd Packet Length Min",
		// 	"Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s",
		// 	"Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
		// 	"Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
		// 	"Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
		// 	"Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd Header Length",
		// 	"Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
		// 	"Min Packet Length", "Max Packet Length", "Packet Length Mean",
		// 	"Packet Length Std", "FIN Flag Count", "SYN Flag Count",
		// 	"RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
		// 	"Active Mean", "Idle Mean"}

		header := []string{"Flow Duration", "Total Fwd Packets", "Total Backward Packets",
			"Total Length of Fwd Packets", "Total Length of Bwd Packets",
			"Fwd Packet Length Mean", "Fwd Packet Length Std",
			"Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s",
			"Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
			"Fwd IAT Mean", "Fwd IAT Std",
			"Bwd IAT Mean", "Bwd IAT Std",

			"Fwd Packets/s", "Bwd Packets/s",

			"Packet Length Mean", "Packet Length Std",

			"FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",

			"Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
			"Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",

			"Subflow Fwd Packets", "Subflow Fwd Bytes",
			"Subflow Bwd Packets", "Subflow Bwd Bytes",

			"Active Mean", "Idle Mean"}

		writer.Write(header)
	}

	data := []string{
		// strconv.FormatUint(features.features.DestinationPort, 10),
		strconv.FormatFloat(features.features.FlowDuration, 'f', 3, 64),

		strconv.FormatUint(features.features.TotalFwdPackets, 10),
		strconv.FormatUint(features.features.TotalBwdPackets, 10),
		strconv.FormatUint(features.features.TotalLengthFwdPackets, 10),
		strconv.FormatUint(features.features.TotalLengthBwdPackets, 10),

		// strconv.FormatUint(features.features.FwdPacketLengthMax, 10),
		// strconv.FormatUint(features.features.FwdPacketLengthMin, 10),
		strconv.FormatFloat(features.features.FwdPacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.FwdPacketLengthStd, 'f', 3, 64),

		// strconv.FormatUint(features.features.BwdPacketLengthMax, 10),
		// strconv.FormatUint(features.features.BwdPacketLengthMin, 10),
		strconv.FormatFloat(features.features.BwdPacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.BwdPacketLengthStd, 'f', 3, 64),

		strconv.FormatFloat(features.features.FlowBytesPerSec, 'f', 3, 64),
		strconv.FormatFloat(features.features.FlowPacketsPerSec, 'f', 3, 64),

		strconv.FormatFloat(features.features.IATFeatures.FlowIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.FlowIATStd, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.FlowIATMax, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.FlowIATMin, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATTotal, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATStd, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATMax, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATMin, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATTotal, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATStd, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATMax, 'f', 3, 64),
		// strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATMin, 'f', 3, 64),

		// strconv.FormatUint(features.features.FlagFeatures.FwdPSHFlags, 10),
		// strconv.FormatUint(features.features.FlagFeatures.BwdPSHFlags, 10),
		// strconv.FormatUint(features.features.FlagFeatures.FwdURGFlags, 10),
		// strconv.FormatUint(features.features.FlagFeatures.BwdURGFlags, 10),

		// strconv.FormatUint(features.features.FwdHeaderLength, 10),
		// strconv.FormatUint(features.features.BwdHeaderLength, 10),
		strconv.FormatFloat(features.features.FwdPacketsPerSec, 'f', 3, 64),
		strconv.FormatFloat(features.features.BwdPacketsPerSec, 'f', 3, 64),

		// strconv.FormatUint(features.features.MinPacketLength, 10),
		// strconv.FormatUint(features.features.MaxPacketLength, 10),
		strconv.FormatFloat(features.features.PacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.PacketLengthStd, 'f', 3, 64),

		strconv.FormatUint(features.features.FlagFeatures.FinFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.SynFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.RstFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.PshFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.AckFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.UrgFlagCount, 10),

		// strconv.FormatUint(features.features.FlagFeatures.CweFlagCount, 10),
		// strconv.FormatUint(features.features.FlagFeatures.EceFlagCount, 10),

		strconv.FormatFloat(features.features.BulkTransferFeatures.FwdAvgBytesBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.FwdAvgPacketsBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.BwdAvgBytesBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.BwdAvgPacketsBulk, 'f', 3, 64),

		strconv.FormatUint(features.features.SubflowFeatures.SubflowFwdPackets, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowFwdBytes, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowBwdPackets, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowBwdBytes, 10),

		strconv.FormatFloat(features.features.ActiveMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IdleMean, 'f', 3, 64),
	}
	writer.Write(data)

	txtName := filename + ".txt"

	WriteToTXT(txtName, data)
	return nil
}

func returnDataIntoString(features *FeatureAnalyzer) []string {
	return []string{
		strconv.FormatFloat(features.features.FlowDuration, 'f', 3, 64),

		strconv.FormatUint(features.features.TotalFwdPackets, 10),
		strconv.FormatUint(features.features.TotalBwdPackets, 10),
		strconv.FormatUint(features.features.TotalLengthFwdPackets, 10),
		strconv.FormatUint(features.features.TotalLengthBwdPackets, 10),

		strconv.FormatFloat(features.features.FwdPacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.FwdPacketLengthStd, 'f', 3, 64),

		strconv.FormatFloat(features.features.BwdPacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.BwdPacketLengthStd, 'f', 3, 64),

		strconv.FormatFloat(features.features.FlowBytesPerSec, 'f', 3, 64),
		strconv.FormatFloat(features.features.FlowPacketsPerSec, 'f', 3, 64),

		strconv.FormatFloat(features.features.IATFeatures.FlowIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.FlowIATStd, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATStd, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATStd, 'f', 3, 64),

		strconv.FormatFloat(features.features.FwdPacketsPerSec, 'f', 3, 64),
		strconv.FormatFloat(features.features.BwdPacketsPerSec, 'f', 3, 64),

		strconv.FormatFloat(features.features.PacketLengthMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.PacketLengthStd, 'f', 3, 64),

		strconv.FormatUint(features.features.FlagFeatures.FinFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.SynFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.RstFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.PshFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.AckFlagCount, 10),
		strconv.FormatUint(features.features.FlagFeatures.UrgFlagCount, 10),

		strconv.FormatFloat(features.features.BulkTransferFeatures.FwdAvgBytesBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.FwdAvgPacketsBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.BwdAvgBytesBulk, 'f', 3, 64),
		strconv.FormatFloat(features.features.BulkTransferFeatures.BwdAvgPacketsBulk, 'f', 3, 64),

		strconv.FormatUint(features.features.SubflowFeatures.SubflowFwdPackets, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowFwdBytes, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowBwdPackets, 10),
		strconv.FormatUint(features.features.SubflowFeatures.SubflowBwdBytes, 10),

		strconv.FormatFloat(features.features.ActiveMean, 'f', 3, 64),
		strconv.FormatFloat(features.features.IdleMean, 'f', 3, 64),
	}
}
func WriteToTXT(filename string, data []string) error {
	// Open file for appending or creating a new one if not exists
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Join the data slice into a single string with commas and space between each element
	dataStr := fmt.Sprintf("data = [%s]", strings.Join(data, ", "))

	// Write the data to the file
	_, err = file.WriteString(dataStr + "\n")
	if err != nil {
		return err
	}

	return nil
}
