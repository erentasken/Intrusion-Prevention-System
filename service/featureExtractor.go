package service

import (
	"encoding/csv"
	"fmt"
	"main/model"
	"math"
	"os"
	"strconv"
	"sync"
	"time"
)

type FeatureAnalyzer struct {
	features       *model.FlowFeatures
	startTime      time.Time
	lastPacketTime time.Time
	packetSizes    []uint64
	mu             sync.Mutex
}

var instance *FeatureAnalyzer

func GetFeatureAnalyzerInstance(packetAnalysis *model.PacketAnalysisTCP) *FeatureAnalyzer {
	if instance == nil {
		tcpHeaderLen := packetAnalysis.TCP.HeaderLength

		packetLength := uint64(len(packetAnalysis.TCP.Payload))

		fmt.Println("destination port ", packetAnalysis.TCP.DestinationPort)

		return &FeatureAnalyzer{
			startTime:      time.Now(),
			lastPacketTime: time.Now(),
			packetSizes:    []uint64{packetLength},
			features: &model.FlowFeatures{
				DestinationPort: packetAnalysis.TCP.DestinationPort,
				FlowDuration:    0,

				TotalFwdPackets: 1,
				TotalBwdPackets: 0,

				TotalLengthFwdPackets: packetLength,
				TotalLengthBwdPackets: 0,
				FwdPacketLengthMax:    packetLength,
				FwdPacketLengthMin:    packetLength,
				FwdPacketLengthMean:   float64(packetLength),
				FwdPacketLengthStd:    0,
				BwdPacketLengthMax:    0,
				BwdPacketLengthMin:    0,
				BwdPacketLengthMean:   0,
				BwdPacketLengthStd:    0,

				FlowBytesPerSec:   0,
				FlowPacketsPerSec: 0,

				FwdHeaderLength:  tcpHeaderLen,
				BwdHeaderLength:  0,
				FwdPacketsPerSec: 0,
				BwdPacketsPerSec: 0,

				MinPacketLength:      packetLength,
				MaxPacketLength:      packetLength,
				PacketLengthMean:     float64(packetLength),
				PacketLengthStd:      0,
				PacketLengthVariance: 0,

				ActiveMean: 0,
				IdleMean:   0,

				FlagFeatures: &model.FlagFeatures{
					FinFlagCount: boolToInt(packetAnalysis.TCP.FIN),
					SynFlagCount: boolToInt(packetAnalysis.TCP.SYN),
					RstFlagCount: boolToInt(packetAnalysis.TCP.RST),
					PshFlagCount: boolToInt(packetAnalysis.TCP.PSH),
					AckFlagCount: boolToInt(packetAnalysis.TCP.ACK),
					UrgFlagCount: boolToInt(packetAnalysis.TCP.URG),
					CweFlagCount: boolToInt(packetAnalysis.TCP.CWR),
					EceFlagCount: boolToInt(packetAnalysis.TCP.ECE),
				},
			},
		}
	}
	return instance
}

func boolToInt(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func (f *FeatureAnalyzer) updateFeatures(packetAnalysis *model.PacketAnalysisTCP, flowDirection string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	//Timing updates.

	// Update flow duration
	f.features.FlowDuration = uint64(time.Since(f.startTime).Nanoseconds())

	//Update idle mean
	timeSinceLastPacket := uint64(time.Since(f.lastPacketTime).Nanoseconds())
	if f.features.IdleMean == 0 {
		f.features.IdleMean = float64(timeSinceLastPacket) / float64(f.features.FlowDuration)
	}

	// Update active mean.Nanoseconds()
	if f.features.ActiveMean == 0 {
		f.features.ActiveMean = float64((f.features.FlowDuration - timeSinceLastPacket) / f.features.FlowDuration)
	}

	f.lastPacketTime = time.Now()
	packetSize := uint64(len(packetAnalysis.TCP.Payload)) // Extract packet size

	// Add packet size to list of packet sizes
	f.packetSizes = append(f.packetSizes, packetSize)

	tcpHeaderLen := packetAnalysis.TCP.HeaderLength

	switch flowDirection {
	case "forward":
		f.features.TotalFwdPackets++
		f.features.TotalLengthFwdPackets += uint64(packetSize)

		f.features.FwdPacketLengthMax = max(f.features.FwdPacketLengthMax, uint64(packetSize))
		f.features.FwdPacketLengthMin = minNonZero(f.features.FwdPacketLengthMin, uint64(packetSize))

		f.features.FlagFeatures.FwdPSHFlags += boolToInt(packetAnalysis.TCP.PSH)
		f.features.FlagFeatures.FwdURGFlags += boolToInt(packetAnalysis.TCP.URG)

		f.features.FwdHeaderLength += tcpHeaderLen
		f.features.FwdPacketsPerSec = float64(f.features.TotalFwdPackets / (f.features.FlowDuration / 1e9))

		f.features.FwdPacketLengthMean = float64(f.features.TotalLengthFwdPackets) / float64(f.features.TotalFwdPackets)
		f.features.FwdPacketLengthStd = calculateStdDeviation(f.packetSizes, f.features.FwdPacketLengthMean)

	case "backward":
		f.features.TotalBwdPackets++
		f.features.TotalLengthBwdPackets += uint64(packetSize)

		f.features.BwdPacketLengthMax = max(f.features.BwdPacketLengthMax, uint64(packetSize))
		f.features.BwdPacketLengthMin = minNonZero(f.features.BwdPacketLengthMin, uint64(packetSize))

		f.features.FlagFeatures.BwdPSHFlags += boolToInt(packetAnalysis.TCP.PSH)
		f.features.FlagFeatures.BwdURGFlags += boolToInt(packetAnalysis.TCP.URG)

		f.features.BwdHeaderLength += tcpHeaderLen
		f.features.BwdPacketsPerSec = float64(f.features.TotalBwdPackets) / float64(f.features.FlowDuration/1e9)

		f.features.BwdPacketLengthMean = float64(f.features.TotalLengthBwdPackets) / float64(f.features.TotalBwdPackets)
		f.features.BwdPacketLengthStd = calculateStdDeviation(f.packetSizes, f.features.BwdPacketLengthMean)
	}

	// Update TCP flag counts
	f.features.FlagFeatures.FinFlagCount += boolToInt(packetAnalysis.TCP.FIN)
	f.features.FlagFeatures.SynFlagCount += boolToInt(packetAnalysis.TCP.SYN)
	f.features.FlagFeatures.RstFlagCount += boolToInt(packetAnalysis.TCP.RST)
	f.features.FlagFeatures.PshFlagCount += boolToInt(packetAnalysis.TCP.PSH)
	f.features.FlagFeatures.AckFlagCount += boolToInt(packetAnalysis.TCP.ACK)
	f.features.FlagFeatures.UrgFlagCount += boolToInt(packetAnalysis.TCP.URG)
	f.features.FlagFeatures.CweFlagCount += boolToInt(packetAnalysis.TCP.CWR)
	f.features.FlagFeatures.EceFlagCount += boolToInt(packetAnalysis.TCP.ECE)

	// Compute flow-based metrics
	if (f.features.FlowDuration / 1e9) > 0 {
		f.features.FlowBytesPerSec = float64(f.features.TotalLengthFwdPackets + f.features.TotalLengthBwdPackets/(f.features.FlowDuration/1e9))
		f.features.FlowPacketsPerSec = float64(f.features.TotalFwdPackets + f.features.TotalBwdPackets/f.features.FlowDuration/1e9)
	}

	f.features.MinPacketLength = minNonZero(f.features.MinPacketLength, packetSize)
	f.features.MaxPacketLength = max(f.features.MaxPacketLength, packetSize)
	f.features.PacketLengthMean = float64((f.features.TotalLengthFwdPackets + f.features.TotalLengthBwdPackets) / (f.features.TotalFwdPackets + f.features.TotalBwdPackets))
	f.features.PacketLengthStd = calculateStdDeviation(f.packetSizes, f.features.PacketLengthMean)
	f.features.PacketLengthVariance = math.Pow(f.features.PacketLengthStd, 2)

}

func calculateStdDeviation(data []uint64, mean float64) float64 {
	var sum float64
	for _, value := range data {
		sum += math.Pow(float64(value)-mean, 2)
	}
	return math.Sqrt(sum / float64(len(data)))
}

func minNonZero(a, b uint64) uint64 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func WriteToCSV(features *model.FlowFeatures, filename string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Check if file is empty and write header
	fileInfo, _ := file.Stat()
	if fileInfo.Size() == 0 {
		header := []string{
			"destination_port", "flow_duration", "total_fwd_packets", "total_bwd_packets",
			"total_length_fwd_packets", "total_length_bwd_packets", "fwd_packet_length_max", "fwd_packet_length_min",
			"fwd_packet_length_mean", "fwd_packet_length_std", "bwd_packet_length_max", "bwd_packet_length_min",
			"bwd_packet_length_mean", "bwd_packet_length_std", "flow_bytes_per_sec", "flow_packets_per_sec",
			"fwd_header_length", "bwd_header_length", "fwd_packets_per_sec", "bwd_packets_per_sec",
			"min_packet_length", "max_packet_length", "packet_length_mean", "packet_length_std", "packet_length_variance",
			"active_mean", "idle_mean",
			"fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
			"ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
		}
		writer.Write(header)
	}

	// Write feature values
	data := []string{
		// strconv.FormatUint(features.DestinationPort, 10),
		strconv.FormatUint(features.FlowDuration, 10),
		strconv.FormatUint(features.TotalFwdPackets, 10),
		strconv.FormatUint(features.TotalBwdPackets, 10),
		strconv.FormatUint(features.TotalLengthFwdPackets, 10),
		strconv.FormatUint(features.TotalLengthBwdPackets, 10),
		strconv.FormatUint(features.FwdPacketLengthMax, 10),
		strconv.FormatUint(features.FwdPacketLengthMin, 10),
		strconv.FormatFloat(features.FwdPacketLengthMean, 'f', 6, 64),
		strconv.FormatFloat(features.FwdPacketLengthStd, 'f', 6, 64),
		strconv.FormatUint(features.BwdPacketLengthMax, 10),
		strconv.FormatUint(features.BwdPacketLengthMin, 10),
		strconv.FormatFloat(features.BwdPacketLengthMean, 'f', 6, 64),
		strconv.FormatFloat(features.BwdPacketLengthStd, 'f', 6, 64),
		strconv.FormatFloat(features.FlowBytesPerSec, 'f', 6, 64),
		strconv.FormatFloat(features.FlowPacketsPerSec, 'f', 6, 64),
		strconv.FormatUint(features.FwdHeaderLength, 10),
		strconv.FormatUint(features.BwdHeaderLength, 10),
		strconv.FormatFloat(features.FwdPacketsPerSec, 'f', 6, 64),
		strconv.FormatFloat(features.BwdPacketsPerSec, 'f', 6, 64),
		strconv.FormatUint(features.MinPacketLength, 10),
		strconv.FormatUint(features.MaxPacketLength, 10),
		strconv.FormatFloat(features.PacketLengthMean, 'f', 6, 64),
		strconv.FormatFloat(features.PacketLengthStd, 'f', 6, 64),
		strconv.FormatFloat(features.PacketLengthVariance, 'f', 6, 64),
		strconv.FormatFloat(features.ActiveMean, 'f', 6, 64),
		strconv.FormatFloat(features.IdleMean, 'f', 6, 64),
		strconv.FormatUint(features.FlagFeatures.FinFlagCount, 10),
		strconv.FormatUint(features.FlagFeatures.SynFlagCount, 10),
		strconv.FormatUint(features.FlagFeatures.RstFlagCount, 10),
		strconv.FormatUint(features.FlagFeatures.PshFlagCount, 10),
		strconv.FormatUint(features.FlagFeatures.AckFlagCount, 10),
		strconv.FormatUint(features.FlagFeatures.UrgFlagCount, 10),
		strconv.FormatUint(features.FlagFeatures.CweFlagCount, 10),
		strconv.FormatUint(features.FlagFeatures.EceFlagCount, 10),
	}

	return writer.Write(data)
}
