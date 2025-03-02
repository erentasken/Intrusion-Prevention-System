package service

import (
	"main/model"
	"math"
	"slices"
	"sync"
	"time"
)

// Check the correctness of IAT features, and check the correctness.
// Check for the idle mean and active mean.
// Check the found databases, compare the results with the computed datas.

type FeatureAnalyzer struct {
	features       *model.FlowFeatures
	startTime      time.Time
	lastPacketTime time.Time
	packetSizes    []uint64

	idleTimesSum float64

	backwardPacketSizes []uint64
	forwardPacketSizes  []uint64

	totalBulkByteFwd    uint64
	totalBulkPacketsFwd uint64

	totalBulkByteBwd    uint64
	totalBulkPacketsBwd uint64

	lastForwardPacketTime      time.Time
	lastBackwardPacketTime     time.Time
	timeBetweenForwardPackets  []float64
	timeBetweenBackwardPackets []float64

	mu           sync.Mutex
	subflowMutex sync.Mutex

	isSubflow bool

	forwardKey    string
	timeoutSignal chan string
}

const subflowTimeout = 3 * time.Second // Define subflow timeout (adjust as needed)

func (f *FeatureAnalyzer) analyzerTimeoutChecks() {
	for {
		f.subflowMutex.Lock()
		if time.Since(f.lastPacketTime) < subflowTimeout {
			f.isSubflow = true
		} else {
			f.isSubflow = false
		}
		f.subflowMutex.Unlock()

		// check the timeout for the flow analysis
		if time.Since(f.lastPacketTime) > 10*time.Second {
			// set the active as false
			// write to database
			// remove from map

			f.timeoutSignal <- f.forwardKey

			break
		}
	}
}

func GetFeatureAnalyzerInstance(packetAnalysis *model.PacketAnalysisTCP, forwardKey string, timeoutSignal chan string) *FeatureAnalyzer {
	tcpHeaderLen := packetAnalysis.TCP.HeaderLength

	packetLength := uint64(len(packetAnalysis.TCP.Payload))

	featureAnalyzer := &FeatureAnalyzer{
		startTime:      time.Now(),
		lastPacketTime: time.Now(),
		packetSizes:    []uint64{packetLength},
		idleTimesSum:   0,
		isSubflow:      false,
		forwardKey:     forwardKey,
		timeoutSignal:  timeoutSignal,

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
			BulkTransferFeatures: &model.BulkTransferFeatures{
				FwdAvgBytesBulk:   0,
				FwdAvgPacketsBulk: 0,
				BwdAvgBytesBulk:   0,
				BwdAvgPacketsBulk: 0,
			},
			SubflowFeatures: &model.SubflowFeatures{
				SubflowFwdPackets: 1,
				SubflowFwdBytes:   packetLength,
				SubflowBwdPackets: 0,
				SubflowBwdBytes:   0,
			},
		},
	}

	go featureAnalyzer.analyzerTimeoutChecks()

	return featureAnalyzer
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

	const bulkThreshold = 1000

	// Update flow duration
	f.features.FlowDuration = float64(time.Since(f.startTime).Milliseconds() / 1000)

	//Update idle mean
	timeSinceLastPacket := float64(time.Since(f.lastPacketTime).Milliseconds() / 1000)
	if f.features.FlowDuration > 0 {
		f.idleTimesSum += timeSinceLastPacket
		f.features.IdleMean = float64(f.idleTimesSum / (f.features.FlowDuration))
	}

	// Update active mean
	if f.features.FlowDuration > 0 {
		f.features.ActiveMean = float64((f.features.FlowDuration - f.idleTimesSum) / f.features.FlowDuration)
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

		f.forwardPacketSizes = append(f.forwardPacketSizes, packetSize)

		f.features.FwdPacketLengthMax = max(f.features.FwdPacketLengthMax, uint64(packetSize))
		f.features.FwdPacketLengthMin = minNonZero(f.features.FwdPacketLengthMin, uint64(packetSize))

		f.features.FlagFeatures.FwdPSHFlags += boolToInt(packetAnalysis.TCP.PSH)
		f.features.FlagFeatures.FwdURGFlags += boolToInt(packetAnalysis.TCP.URG)

		f.features.FwdHeaderLength += tcpHeaderLen

		if f.features.FlowDuration > 0 {
			f.features.FwdPacketsPerSec = float64(f.features.TotalFwdPackets) / (f.features.FlowDuration)
		}

		if f.features.TotalFwdPackets > 0 {
			f.features.FwdPacketLengthMean = float64(f.features.TotalLengthFwdPackets / f.features.TotalFwdPackets)
		}

		f.features.FwdPacketLengthStd = calculateStdDeviation(f.forwardPacketSizes, f.features.FwdPacketLengthMean)

		//Compute IAT features
		timeSinceForwardPacket := float64(time.Since(f.lastForwardPacketTime).Milliseconds() / 1000)
		if timeSinceForwardPacket > 0 && f.features.TotalFwdPackets > 2 {
			f.timeBetweenForwardPackets = append(f.timeBetweenForwardPackets, timeSinceForwardPacket)
			f.features.IATFeatures.ForwardIATFeatures.FwdIATMean = float64(f.features.IATFeatures.ForwardIATFeatures.FwdIATTotal) / float64(len(f.timeBetweenForwardPackets))
			f.features.IATFeatures.ForwardIATFeatures.FwdIATStd = calculateStdDeviationFloat(f.timeBetweenForwardPackets, f.features.IATFeatures.ForwardIATFeatures.FwdIATMean)
			f.features.IATFeatures.ForwardIATFeatures.FwdIATMax = max(f.features.IATFeatures.ForwardIATFeatures.FwdIATMax, f.timeBetweenForwardPackets[len(f.timeBetweenForwardPackets)-1])
			f.features.IATFeatures.ForwardIATFeatures.FwdIATMin = minNonZeroFloat(f.features.IATFeatures.ForwardIATFeatures.FwdIATMin, f.timeBetweenForwardPackets[len(f.timeBetweenForwardPackets)-1])
		}
		f.lastForwardPacketTime = time.Now()

		//Bulk transfer features
		if packetSize > bulkThreshold {
			f.totalBulkByteFwd += packetSize
			f.totalBulkPacketsFwd++

			f.features.BulkTransferFeatures.FwdAvgBytesBulk = float64(f.totalBulkByteFwd / f.totalBulkPacketsFwd)
			f.features.BulkTransferFeatures.FwdAvgPacketsBulk = float64(f.totalBulkPacketsFwd)
		}

		f.subflowMutex.Lock()
		// Subflow features
		if f.isSubflow {
			f.features.SubflowFeatures.SubflowFwdPackets++
			f.features.SubflowFeatures.SubflowFwdBytes += packetSize
		}
		f.subflowMutex.Unlock()
	case "backward":
		f.features.TotalBwdPackets++
		f.features.TotalLengthBwdPackets += uint64(packetSize)

		f.backwardPacketSizes = append(f.backwardPacketSizes, packetSize)

		f.features.BwdPacketLengthMax = max(f.features.BwdPacketLengthMax, uint64(packetSize))
		f.features.BwdPacketLengthMin = minNonZero(f.features.BwdPacketLengthMin, uint64(packetSize))

		f.features.FlagFeatures.BwdPSHFlags += boolToInt(packetAnalysis.TCP.PSH)
		f.features.FlagFeatures.BwdURGFlags += boolToInt(packetAnalysis.TCP.URG)

		f.features.BwdHeaderLength += tcpHeaderLen

		if f.features.FlowDuration > 0 {
			f.features.BwdPacketsPerSec = float64(f.features.TotalBwdPackets) / (f.features.FlowDuration)
		}

		if f.features.TotalBwdPackets > 0 {
			f.features.BwdPacketLengthMean = float64(f.features.TotalLengthBwdPackets / f.features.TotalBwdPackets)
		}

		f.features.BwdPacketLengthStd = calculateStdDeviation(f.backwardPacketSizes, f.features.BwdPacketLengthMean)

		//Compute IAT features
		timeSinceBackwardPacket := float64(time.Since(f.lastBackwardPacketTime).Milliseconds() / 1000)
		if timeSinceBackwardPacket > 0 && f.features.TotalBwdPackets > 1 {
			f.timeBetweenBackwardPackets = append(f.timeBetweenBackwardPackets, timeSinceBackwardPacket)
			f.features.IATFeatures.BackwardIATFeatures.BwdIATMean = float64(f.features.IATFeatures.BackwardIATFeatures.BwdIATTotal) / float64(len(f.timeBetweenBackwardPackets))
			f.features.IATFeatures.BackwardIATFeatures.BwdIATStd = calculateStdDeviationFloat(f.timeBetweenBackwardPackets, f.features.IATFeatures.BackwardIATFeatures.BwdIATMean)
			f.features.IATFeatures.BackwardIATFeatures.BwdIATMax = max(f.features.IATFeatures.BackwardIATFeatures.BwdIATMax, f.timeBetweenBackwardPackets[len(f.timeBetweenBackwardPackets)-1])
			f.features.IATFeatures.BackwardIATFeatures.BwdIATMin = minNonZeroFloat(f.features.IATFeatures.BackwardIATFeatures.BwdIATMin, f.timeBetweenBackwardPackets[len(f.timeBetweenBackwardPackets)-1])
		}
		f.lastBackwardPacketTime = time.Now()

		//Bulk transfer features
		if packetSize > bulkThreshold {
			f.totalBulkByteBwd += packetSize
			f.totalBulkPacketsBwd++
			f.features.BulkTransferFeatures.BwdAvgBytesBulk = float64(f.totalBulkByteBwd / f.totalBulkPacketsBwd)
			f.features.BulkTransferFeatures.BwdAvgPacketsBulk = float64(f.totalBulkPacketsBwd)
		}

		f.subflowMutex.Lock()
		// Subflow features
		if f.isSubflow {
			f.features.SubflowFeatures.SubflowBwdPackets++
			f.features.SubflowFeatures.SubflowBwdBytes += packetSize
		}
		f.subflowMutex.Unlock()
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
		f.features.FlowBytesPerSec = float64(f.features.TotalLengthFwdPackets+f.features.TotalLengthBwdPackets) / (f.features.FlowDuration)
		f.features.FlowPacketsPerSec = float64(f.features.TotalFwdPackets+f.features.TotalBwdPackets) / (f.features.FlowDuration)
	}

	f.features.MinPacketLength = minNonZero(f.features.MinPacketLength, packetSize)
	f.features.MaxPacketLength = max(f.features.MaxPacketLength, packetSize)
	f.features.PacketLengthMean = float64((f.features.TotalLengthFwdPackets + f.features.TotalLengthBwdPackets) / (f.features.TotalFwdPackets + f.features.TotalBwdPackets))
	f.features.PacketLengthStd = calculateStdDeviation(f.packetSizes, f.features.PacketLengthMean)

	// Compute IAT features
	f.features.IATFeatures.FlowIATMean = float64((f.features.IATFeatures.BackwardIATFeatures.BwdIATTotal + f.features.IATFeatures.ForwardIATFeatures.FwdIATTotal) / float64(f.features.TotalBwdPackets+f.features.TotalFwdPackets))

	listIAT := append(f.timeBetweenBackwardPackets, f.timeBetweenForwardPackets...)

	if len(listIAT) > 1 {
		f.features.IATFeatures.FlowIATStd = calculateStdDeviationFloat(listIAT, f.features.IATFeatures.FlowIATMean)
		f.features.IATFeatures.FlowIATMax = max(f.features.IATFeatures.FlowIATMax, slices.Max(listIAT))
		f.features.IATFeatures.FlowIATMin = minNonZeroFloat(f.features.IATFeatures.FlowIATMin, slices.Min(listIAT))
	}
}

func calculateStdDeviation(data []uint64, mean float64) float64 {
	var sum float64
	for _, value := range data {
		sum += math.Pow(float64(value)-mean, 2)
	}
	return math.Sqrt(sum / float64(len(data)))
}

func calculateStdDeviationFloat(data []float64, mean float64) float64 {
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

func minNonZeroFloat(a, b float64) float64 {
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
