package service

import (
	"main/model"
	"math"
	"slices"
	"sync"
	"time"
)

type FeatureAnalyzer struct {
	features       *model.FlowFeatures
	startTime      time.Time
	lastPacketTime time.Time
	packetSizes    []uint64

	lastForwardPacketTime      time.Time
	lastBackwardPacketTime     time.Time
	timeBetweenForwardPackets  []uint64
	timeBetweenBackwardPackets []uint64
	mu                         sync.Mutex
}

var instance *FeatureAnalyzer

func GetFeatureAnalyzerInstance(packetAnalysis *model.PacketAnalysisTCP) *FeatureAnalyzer {
	if instance == nil {
		tcpHeaderLen := packetAnalysis.TCP.HeaderLength

		packetLength := uint64(len(packetAnalysis.TCP.Payload))

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

				MinPacketLength:  packetLength,
				MaxPacketLength:  packetLength,
				PacketLengthMean: float64(packetLength),
				PacketLengthStd:  0,

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

				IATFeatures: &model.IATFeatures{
					FlowIATMean: 0,
					FlowIATStd:  0,
					FlowIATMax:  0,
					FlowIATMin:  0,
					ForwardIATFeatures: &model.ForwardIATFeatures{
						FwdIATTotal: 0,
						FwdIATMean:  0,
						FwdIATStd:   0,
						FwdIATMax:   0,
						FwdIATMin:   0,
					},
					BackwardIATFeatures: &model.BackwardIATFeatures{
						BwdIATMean: 0,
						BwdIATStd:  0,
						BwdIATMax:  0,
						BwdIATMin:  0,
					},
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
	f.features.FlowDuration = uint64(time.Since(f.startTime).Seconds())

	//Update idle mean
	timeSinceLastPacket := uint64(time.Since(f.lastPacketTime).Seconds())
	if f.features.IdleMean == 0 && f.features.FlowDuration > 0 {
		f.features.IdleMean = float64(timeSinceLastPacket / (f.features.FlowDuration))
	}

	// Update active mean.Nanoseconds()
	if f.features.ActiveMean == 0 && f.features.FlowDuration > 0 {
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

		if f.features.FlowDuration > 0 {
			f.features.FwdPacketsPerSec = float64(f.features.TotalFwdPackets / (f.features.FlowDuration))
		}

		if f.features.TotalFwdPackets > 0 {
			f.features.FwdPacketLengthMean = float64(f.features.TotalLengthFwdPackets) / float64(f.features.TotalFwdPackets)
		}

		f.features.FwdPacketLengthStd = calculateStdDeviation(f.packetSizes, f.features.FwdPacketLengthMean)

		timeSinceForwardPacket := uint64(time.Since(f.lastForwardPacketTime).Seconds())
		if timeSinceForwardPacket > 0 {
			f.timeBetweenForwardPackets = append(f.timeBetweenForwardPackets, timeSinceForwardPacket)
		}

		f.lastForwardPacketTime = time.Now()

		//Compute IAT features
		if len(f.timeBetweenForwardPackets) > 1 {
			f.features.IATFeatures.ForwardIATFeatures.FwdIATTotal += float64(f.timeBetweenForwardPackets[len(f.timeBetweenForwardPackets)-1])
			f.features.IATFeatures.ForwardIATFeatures.FwdIATMean = float64(f.features.IATFeatures.ForwardIATFeatures.FwdIATTotal) / float64(len(f.timeBetweenForwardPackets))
			f.features.IATFeatures.ForwardIATFeatures.FwdIATStd = calculateStdDeviation(f.timeBetweenForwardPackets, f.features.IATFeatures.ForwardIATFeatures.FwdIATMean)
			f.features.IATFeatures.ForwardIATFeatures.FwdIATMax = max(f.features.IATFeatures.ForwardIATFeatures.FwdIATMax, f.timeBetweenForwardPackets[len(f.timeBetweenForwardPackets)-1])
			f.features.IATFeatures.ForwardIATFeatures.FwdIATMin = minNonZero(f.features.IATFeatures.ForwardIATFeatures.FwdIATMin, f.timeBetweenForwardPackets[len(f.timeBetweenForwardPackets)-1])
		}
	case "backward":
		f.features.TotalBwdPackets++
		f.features.TotalLengthBwdPackets += uint64(packetSize)

		f.features.BwdPacketLengthMax = max(f.features.BwdPacketLengthMax, uint64(packetSize))
		f.features.BwdPacketLengthMin = minNonZero(f.features.BwdPacketLengthMin, uint64(packetSize))

		f.features.FlagFeatures.BwdPSHFlags += boolToInt(packetAnalysis.TCP.PSH)
		f.features.FlagFeatures.BwdURGFlags += boolToInt(packetAnalysis.TCP.URG)

		f.features.BwdHeaderLength += tcpHeaderLen

		if f.features.FlowDuration > 0 {
			f.features.BwdPacketsPerSec = float64(f.features.TotalBwdPackets) / float64(f.features.FlowDuration)
		}

		if f.features.TotalBwdPackets > 0 {
			f.features.BwdPacketLengthMean = float64(f.features.TotalLengthBwdPackets) / float64(f.features.TotalBwdPackets)
		}

		f.features.BwdPacketLengthStd = calculateStdDeviation(f.packetSizes, f.features.BwdPacketLengthMean)

		timeSinceBackwardPacket := uint64(time.Since(f.lastBackwardPacketTime).Seconds())
		if timeSinceBackwardPacket > 0 {
			f.timeBetweenBackwardPackets = append(f.timeBetweenBackwardPackets, timeSinceBackwardPacket)
		}

		f.lastBackwardPacketTime = time.Now()

		//Compute IAT features
		if len(f.timeBetweenBackwardPackets) > 1 {
			f.features.IATFeatures.BackwardIATFeatures.BwdIATMean = float64(f.features.IATFeatures.BackwardIATFeatures.BwdIATTotal) / float64(len(f.timeBetweenBackwardPackets))
			f.features.IATFeatures.BackwardIATFeatures.BwdIATStd = calculateStdDeviation(f.timeBetweenBackwardPackets, f.features.IATFeatures.BackwardIATFeatures.BwdIATMean)
			f.features.IATFeatures.BackwardIATFeatures.BwdIATMax = max(f.features.IATFeatures.BackwardIATFeatures.BwdIATMax, f.timeBetweenBackwardPackets[len(f.timeBetweenBackwardPackets)-1])
			f.features.IATFeatures.BackwardIATFeatures.BwdIATMin = minNonZero(f.features.IATFeatures.BackwardIATFeatures.BwdIATMin, f.timeBetweenBackwardPackets[len(f.timeBetweenBackwardPackets)-1])
		}
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
	if (f.features.FlowDuration) > 0 {
		f.features.FlowBytesPerSec = float64(f.features.TotalLengthFwdPackets + f.features.TotalLengthBwdPackets/(f.features.FlowDuration))
		f.features.FlowPacketsPerSec = float64(f.features.TotalFwdPackets + f.features.TotalBwdPackets/(f.features.FlowDuration))
	}

	f.features.MinPacketLength = minNonZero(f.features.MinPacketLength, packetSize)
	f.features.MaxPacketLength = max(f.features.MaxPacketLength, packetSize)
	f.features.PacketLengthMean = float64((f.features.TotalLengthFwdPackets + f.features.TotalLengthBwdPackets) / (f.features.TotalFwdPackets + f.features.TotalBwdPackets))
	f.features.PacketLengthStd = calculateStdDeviation(f.packetSizes, f.features.PacketLengthMean)

	// Compute IAT features
	totalIAT := (f.features.IATFeatures.BackwardIATFeatures.BwdIATTotal + f.features.IATFeatures.ForwardIATFeatures.FwdIATTotal)
	f.features.IATFeatures.FlowIATMean = totalIAT / float64(f.features.TotalBwdPackets+f.features.TotalFwdPackets)
	listIAT := append(f.timeBetweenBackwardPackets, f.timeBetweenForwardPackets...)

	f.features.IATFeatures.FlowIATStd = calculateStdDeviation(listIAT, f.features.IATFeatures.FlowIATMean)
	f.features.IATFeatures.FlowIATMax = max(f.features.IATFeatures.FlowIATMax, slices.Max(listIAT))
	f.features.IATFeatures.FlowIATMin = minNonZero(f.features.IATFeatures.FlowIATMin, slices.Min(listIAT))

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
