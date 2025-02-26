package service

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"main/model"
	"net"
	"os"
	"strconv"
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

	forwardKey := fmt.Sprintf("%s-%s:%d", packetAnalysis.IPv4.SourceIP, packetAnalysis.IPv4.DestinationIP, packetAnalysis.TCP.DestinationPort)
	backwardKey := fmt.Sprintf("%s-%s:%d", packetAnalysis.IPv4.DestinationIP, packetAnalysis.IPv4.SourceIP, packetAnalysis.TCP.SourcePort)

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

	tcpHeaderLength := (payload[12] >> 4) * 4 // Header length in 32-bit words
	if len(payload) < int(tcpHeaderLength) {
		fmt.Println("[ERROR] Invalid TCP header length")
		return
	}

	packetAnalysis.TCP.Payload = payload[tcpHeaderLength:]
	packetAnalysis.TCP.HeaderLength = uint64(tcpHeaderLength)

}

func WriteToCSV(filename string, featureAnalyzers map[string]*FeatureAnalyzer) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	fileInfo, _ := file.Stat()
	if fileInfo.Size() == 0 {
		header := []string{
			"destination_port", "flow_duration",

			"total_fwd_packets", "total_bwd_packets",
			"total_length_fwd_packets", "total_length_bwd_packets",

			"fwd_packet_length_max", "fwd_packet_length_min",
			"fwd_packet_length_mean", "fwd_packet_length_std",

			"bwd_packet_length_max", "bwd_packet_length_min",
			"bwd_packet_length_mean", "bwd_packet_length_std",

			"flow_bytes_per_sec", "flow_packets_per_sec",

			"fwd_header_length", "bwd_header_length",
			"fwd_packets_per_sec", "bwd_packets_per_sec",

			"min_packet_length", "max_packet_length",
			"packet_length_mean", "packet_length_std",

			"active_mean", "idle_mean",

			"fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",

			"fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
			"ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",

			"flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",

			"fwd_iat_total", "fwd_iat_mean",
			"fwd_iat_std", "fwd_iat_max", "fwd_iat_min",

			"bwd_iat_total", "bwd_iat_mean",
			"bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
		}

		writer.Write(header)
	}

	for k, features := range featureAnalyzers {
		fmt.Println(" key: ", k)
		data := []string{
			strconv.FormatUint(features.features.DestinationPort, 10),
			strconv.FormatUint(features.features.FlowDuration, 10),

			strconv.FormatUint(features.features.TotalFwdPackets, 10),
			strconv.FormatUint(features.features.TotalBwdPackets, 10),
			strconv.FormatUint(features.features.TotalLengthFwdPackets, 10),
			strconv.FormatUint(features.features.TotalLengthBwdPackets, 10),

			strconv.FormatUint(features.features.FwdPacketLengthMax, 10),
			strconv.FormatUint(features.features.FwdPacketLengthMin, 10),
			strconv.FormatFloat(features.features.FwdPacketLengthMean, 'f', 6, 64),
			strconv.FormatFloat(features.features.FwdPacketLengthStd, 'f', 6, 64),

			strconv.FormatUint(features.features.BwdPacketLengthMax, 10),
			strconv.FormatUint(features.features.BwdPacketLengthMin, 10),
			strconv.FormatFloat(features.features.BwdPacketLengthMean, 'f', 6, 64),
			strconv.FormatFloat(features.features.BwdPacketLengthStd, 'f', 6, 64),

			strconv.FormatFloat(features.features.FlowBytesPerSec, 'f', 6, 64),
			strconv.FormatFloat(features.features.FlowPacketsPerSec, 'f', 6, 64),

			strconv.FormatUint(features.features.FwdHeaderLength, 10),
			strconv.FormatUint(features.features.BwdHeaderLength, 10),
			strconv.FormatFloat(features.features.FwdPacketsPerSec, 'f', 6, 64),
			strconv.FormatFloat(features.features.BwdPacketsPerSec, 'f', 6, 64),

			strconv.FormatUint(features.features.MinPacketLength, 10),
			strconv.FormatUint(features.features.MaxPacketLength, 10),
			strconv.FormatFloat(features.features.PacketLengthMean, 'f', 6, 64),
			strconv.FormatFloat(features.features.PacketLengthStd, 'f', 6, 64),

			strconv.FormatFloat(features.features.ActiveMean, 'f', 6, 64),
			strconv.FormatFloat(features.features.IdleMean, 'f', 6, 64),

			strconv.FormatUint(features.features.FlagFeatures.FwdPSHFlags, 10),
			strconv.FormatUint(features.features.FlagFeatures.BwdPSHFlags, 10),
			strconv.FormatUint(features.features.FlagFeatures.FwdURGFlags, 10),
			strconv.FormatUint(features.features.FlagFeatures.BwdURGFlags, 10),

			strconv.FormatUint(features.features.FlagFeatures.FinFlagCount, 10),
			strconv.FormatUint(features.features.FlagFeatures.SynFlagCount, 10),
			strconv.FormatUint(features.features.FlagFeatures.RstFlagCount, 10),
			strconv.FormatUint(features.features.FlagFeatures.PshFlagCount, 10),
			strconv.FormatUint(features.features.FlagFeatures.AckFlagCount, 10),
			strconv.FormatUint(features.features.FlagFeatures.UrgFlagCount, 10),
			strconv.FormatUint(features.features.FlagFeatures.CweFlagCount, 10),
			strconv.FormatUint(features.features.FlagFeatures.EceFlagCount, 10),

			strconv.FormatFloat(features.features.IATFeatures.FlowIATMean, 'f', 6, 64),
			strconv.FormatFloat(features.features.IATFeatures.FlowIATStd, 'f', 6, 64),
			strconv.FormatUint(features.features.IATFeatures.FlowIATMax, 10),
			strconv.FormatUint(features.features.IATFeatures.FlowIATMin, 10),

			strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATTotal, 'f', 6, 64),
			strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATMean, 'f', 6, 64),
			strconv.FormatFloat(features.features.IATFeatures.ForwardIATFeatures.FwdIATStd, 'f', 6, 64),
			strconv.FormatUint(features.features.IATFeatures.ForwardIATFeatures.FwdIATMax, 10),
			strconv.FormatUint(features.features.IATFeatures.ForwardIATFeatures.FwdIATMin, 10),

			strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATTotal, 'f', 6, 64),
			strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATMean, 'f', 6, 64),
			strconv.FormatFloat(features.features.IATFeatures.BackwardIATFeatures.BwdIATStd, 'f', 6, 64),
			strconv.FormatUint(features.features.IATFeatures.BackwardIATFeatures.BwdIATMax, 10),
			strconv.FormatUint(features.features.IATFeatures.BackwardIATFeatures.BwdIATMin, 10),
		}
		writer.Write(data)
	}

	return nil
}
