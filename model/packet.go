package model

type FlowFeatures struct {
	// Basic Flow Information
	DestinationPort uint64  `json:"Destination Port"` // Destination port of the connection
	FlowDuration    float64 `json:"Flow Duration"`    // Total duration of the flow in microseconds

	// Packet Count Features ---------------  DONE
	TotalFwdPackets       uint64 `json:"Total Fwd Packets"`
	TotalBwdPackets       uint64 `json:"Total Backward Packets"`
	TotalLengthFwdPackets uint64 `json:"Total Length of Fwd Packets"`
	TotalLengthBwdPackets uint64 `json:"Total Length of Bwd Packets"`

	// Packet Length Features ---------------  DONE
	FwdPacketLengthMax  uint64  `json:"Fwd Packet Length Max"`
	FwdPacketLengthMin  uint64  `json:"Fwd Packet Length Min"`
	FwdPacketLengthMean float64 `json:"Fwd Packet Length Mean"`
	FwdPacketLengthStd  float64 `json:"Fwd Packet Length Std"`
	BwdPacketLengthMax  uint64  `json:"Bwd Packet Length Max"`
	BwdPacketLengthMin  uint64  `json:"Bwd Packet Length Min"`
	BwdPacketLengthMean float64 `json:"Bwd Packet Length Mean"`
	BwdPacketLengthStd  float64 `json:"Bwd Packet Length Std"`

	// Flow-Based Features ---------------  DONE
	FlowBytesPerSec   float64 `json:"Flow Bytes/s"`
	FlowPacketsPerSec float64 `json:"Flow Packets/s"`

	IATFeatures *IATFeatures

	// Header & Packet Rate Features ---------------  DONE
	FwdHeaderLength  uint64  `json:"Fwd Header Length"`
	BwdHeaderLength  uint64  `json:"Bwd Header Length"`
	FwdPacketsPerSec float64 `json:"Fwd Packets/s"`
	BwdPacketsPerSec float64 `json:"Bwd Packets/s"`

	// Packet Size Distribution ---------------  DONE
	MinPacketLength  uint64  `json:"Min Packet Length"`
	MaxPacketLength  uint64  `json:"Max Packet Length"`
	PacketLengthMean float64 `json:"Packet Length Mean"`
	PacketLengthStd  float64 `json:"Packet Length Std"`

	// Activity & Idle Time Features
	ActiveMean float64 `json:"Active Mean"`
	IdleMean   float64 `json:"Idle Mean"`

	FlagFeatures *FlagFeatures

	BulkTransferFeatures *BulkTransferFeatures

	SubflowFeatures *SubflowFeatures
}

type BulkTransferFeatures struct {
	// Bulk Transfer Features
	FwdAvgBytesBulk   float64 `json:"Fwd Avg Bytes/Bulk"`
	FwdAvgPacketsBulk float64 `json:"Fwd Avg Packets/Bulk"`
	BwdAvgBytesBulk   float64 `json:"Bwd Avg Bytes/Bulk"`
	BwdAvgPacketsBulk float64 `json:"Bwd Avg Packets/Bulk"`
}

type SubflowFeatures struct {
	// Subflow Features
	SubflowFwdPackets uint64 `json:"Subflow Fwd Packets"`
	SubflowFwdBytes   uint64 `json:"Subflow Fwd Bytes"`
	SubflowBwdPackets uint64 `json:"Subflow Bwd Packets"`
	SubflowBwdBytes   uint64 `json:"Subflow Bwd Bytes"`
}

type IATFeatures struct {
	// Inter-Arrival Time (IAT) Features
	FlowIATMean float64 `json:"Flow IAT Mean"`
	FlowIATStd  float64 `json:"Flow IAT Std"`
	FlowIATMax  float64 `json:"Flow IAT Max"`
	FlowIATMin  float64 `json:"Flow IAT Min"`

	ForwardIATFeatures  *ForwardIATFeatures
	BackwardIATFeatures *BackwardIATFeatures
}

type ForwardIATFeatures struct {
	// Forward Inter-Arrival Time Features
	FwdIATTotal float64 `json:"Fwd IAT Total"`
	FwdIATMean  float64 `json:"Fwd IAT Mean"`
	FwdIATStd   float64 `json:"Fwd IAT Std"`
	FwdIATMax   float64 `json:"Fwd IAT Max"`
	FwdIATMin   float64 `json:"Fwd IAT Min"`
}

type BackwardIATFeatures struct {
	// Backward Inter-Arrival Time Features
	BwdIATTotal float64 `json:"Bwd IAT Total"`
	BwdIATMean  float64 `json:"Bwd IAT Mean"`
	BwdIATStd   float64 `json:"Bwd IAT Std"`
	BwdIATMax   float64 `json:"Bwd IAT Max"`
	BwdIATMin   float64 `json:"Bwd IAT Min"`
}

type FlagFeatures struct {
	FwdPSHFlags uint64 `json:"Fwd PSH Flags"`
	BwdPSHFlags uint64 `json:"Bwd PSH Flags"`
	FwdURGFlags uint64 `json:"Fwd URG Flags"`
	BwdURGFlags uint64 `json:"Bwd URG Flags"`

	// TCP Control Flags
	FinFlagCount uint64 `json:"FIN Flag Count"`
	SynFlagCount uint64 `json:"SYN Flag Count"`
	RstFlagCount uint64 `json:"RST Flag Count"`
	PshFlagCount uint64 `json:"PSH Flag Count"`
	AckFlagCount uint64 `json:"ACK Flag Count"`
	UrgFlagCount uint64 `json:"URG Flag Count"`
	CweFlagCount uint64 `json:"CWE Flag Count"`
	EceFlagCount uint64 `json:"ECE Flag Count"`
}

// Define a struct to represent IPv4 information
type IPv4Info struct {
	TotalLength   uint16 // Total Length of the packet
	Protocol      uint8  // Protocol (e.g., 6 for TCP)
	SourceIP      string
	DestinationIP string
}

// Define a struct to represent TCP header information
type TCPInfo struct {
	SourcePort      uint64
	DestinationPort uint64
	SYN             bool
	ACK             bool
	FIN             bool
	RST             bool
	PSH             bool
	URG             bool
	CWR             bool
	ECE             bool
	Payload         []byte // Store TCP payload data
	HeaderLength    uint64 // Length of the TCP header
}

// Define a struct to represent the analysis of a TCP packet
type PacketAnalysisTCP struct {
	IPv4 *IPv4Info
	TCP  *TCPInfo
}
