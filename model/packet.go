package model

type FlowFeatures struct {
	// Basic Flow Information
	DestinationPort uint64 `json:"destination_port"` // Destination port of the connection
	FlowDuration    uint64 `json:"flow_duration"`    // Total duration of the flow in microseconds

	// Packet Count Features
	TotalFwdPackets uint64 `json:"total_fwd_packets"` // Number of packets sent in the forward direction
	TotalBwdPackets uint64 `json:"total_bwd_packets"` // Number of packets sent in the backward direction

	// Packet Size Features
	TotalLengthFwdPackets uint64  `json:"total_length_fwd_packets"` // Total size of forward packets
	TotalLengthBwdPackets uint64  `json:"total_length_bwd_packets"` // Total size of backward packets
	FwdPacketLengthMax    uint64  `json:"fwd_packet_length_max"`    // Maximum length of forward packets
	FwdPacketLengthMin    uint64  `json:"fwd_packet_length_min"`    // Minimum length of forward packets
	FwdPacketLengthMean   float64 `json:"fwd_packet_length_mean"`   // Mean length of forward packets
	FwdPacketLengthStd    float64 `json:"fwd_packet_length_std"`    // Standard deviation of forward packet length
	BwdPacketLengthMax    uint64  `json:"bwd_packet_length_max"`    // Maximum length of backward packets
	BwdPacketLengthMin    uint64  `json:"bwd_packet_length_min"`    // Minimum length of backward packets
	BwdPacketLengthMean   float64 `json:"bwd_packet_length_mean"`   // Mean length of backward packets
	BwdPacketLengthStd    float64 `json:"bwd_packet_length_std"`    // Standard deviation of backward packet length

	// Flow-Based Features
	FlowBytesPerSec   float64 `json:"flow_bytes_per_sec"`   // Data transfer rate in bytes per second
	FlowPacketsPerSec float64 `json:"flow_packets_per_sec"` // Packet transfer rate per second

	// Header & Packet Rate Features
	FwdHeaderLength  uint64  `json:"fwd_header_length"`   // Header length of forward packets
	BwdHeaderLength  uint64  `json:"bwd_header_length"`   // Header length of backward packets
	FwdPacketsPerSec float64 `json:"fwd_packets_per_sec"` // Forward packet transmission rate
	BwdPacketsPerSec float64 `json:"bwd_packets_per_sec"` // Backward packet transmission rate

	// Packet Size Distribution
	MinPacketLength      uint64  `json:"min_packet_length"`      // Minimum packet size in the flow
	MaxPacketLength      uint64  `json:"max_packet_length"`      // Maximum packet size in the flow
	PacketLengthMean     float64 `json:"packet_length_mean"`     // Mean packet size
	PacketLengthStd      float64 `json:"packet_length_std"`      // Standard deviation of packet size
	PacketLengthVariance float64 `json:"packet_length_variance"` // Variance of packet size

	// Activity & Idle Time Features
	ActiveMean float64 `json:"active_mean"` // Mean active time
	IdleMean   float64 `json:"idle_mean"`   // Mean idle time

	FlagFeatures *FlagFeatures

	//TODO

	// DownUpRatio       float64 `json:"down_up_ratio"`        // Ratio of downloaded to uploaded data
	// AveragePacketSize float64 `json:"average_packet_size"`  // Average size of packets in the flow
	// AvgFwdSegmentSize float64 `json:"avg_fwd_segment_size"` // Average segment size in forward packets
	// AvgBwdSegmentSize float64 `json:"avg_bwd_segment_size"` // Average segment size in backward packets

	// IATFeatures *IATFeatures

	// BulkTransferFeatures *BulkTransferFeatures

	// SubflowFeatures *SubflowFeatures
}

type BulkTransferFeatures struct {
	// Bulk Transfer Features
	FwdAvgBytesBulk   float64 `json:"fwd_avg_bytes_bulk"`   // Average bulk transfer size for forward direction
	FwdAvgPacketsBulk float64 `json:"fwd_avg_packets_bulk"` // Average bulk packet count for forward direction
	FwdAvgBulkRate    float64 `json:"fwd_avg_bulk_rate"`    // Bulk data rate in forward direction
	BwdAvgBytesBulk   float64 `json:"bwd_avg_bytes_bulk"`   // Average bulk transfer size for backward direction
	BwdAvgPacketsBulk float64 `json:"bwd_avg_packets_bulk"` // Average bulk packet count for backward direction
	BwdAvgBulkRate    float64 `json:"bwd_avg_bulk_rate"`    // Bulk data rate in backward directions
}

type SubflowFeatures struct {
	// Subflow Features
	SubflowFwdPackets uint64 `json:"subflow_fwd_packets"` // Number of forward packets in subflow
	SubflowFwdBytes   uint64 `json:"subflow_fwd_bytes"`   // Number of bytes in forward subflow
	SubflowBwdPackets uint64 `json:"subflow_bwd_packets"` // Number of backward packets in subflow
	SubflowBwdBytes   uint64 `json:"subflow_bwd_bytes"`   // Number of bytes in backward subflow

}

type FlagFeatures struct {
	FwdPSHFlags uint64 `json:"fwd_psh_flags"` // Number of PSH flags in forward packets
	BwdPSHFlags uint64 `json:"bwd_psh_flags"` // Number of PSH flags in backward packets
	FwdURGFlags uint64 `json:"fwd_urg_flags"` // Number of URG flags in forward packets
	BwdURGFlags uint64 `json:"bwd_urg_flags"` // Number of URG flags in backward packets

	// TCP Control Flags
	FinFlagCount uint64 `json:"fin_flag_count"` // Count of FIN flags
	SynFlagCount uint64 `json:"syn_flag_count"` // Count of SYN flags
	RstFlagCount uint64 `json:"rst_flag_count"` // Count of RST flags
	PshFlagCount uint64 `json:"psh_flag_count"` // Count of PSH flags
	AckFlagCount uint64 `json:"ack_flag_count"` // Count of ACK flags
	UrgFlagCount uint64 `json:"urg_flag_count"` // Count of URG flags
	CweFlagCount uint64 `json:"cwe_flag_count"` // Count of CWE flags
	EceFlagCount uint64 `json:"ece_flag_count"` // Count of ECE flags
}

type IATFeatures struct {
	// Inter-Arrival Time (IAT) Features
	FlowIATMean float64 `json:"flow_iat_mean"` // Mean Inter-Arrival Time between packets in the flow
	FlowIATStd  float64 `json:"flow_iat_std"`  // Standard deviation of packet Inter-Arrival Time
	FlowIATMax  float64 `json:"flow_iat_max"`  // Maximum Inter-Arrival Time in the flow
	FlowIATMin  float64 `json:"flow_iat_min"`  // Minimum Inter-Arrival Time in the flow

	ForwardIATFeatures  *ForwardIATFeatures
	BackwardIATFeatures *BackwardIATFeatures
}

type ForwardIATFeatures struct {
	// Forward Inter-Arrival Time Features
	FwdIATTotal float64 `json:"fwd_iat_total"` // Total Inter-Arrival Time for forward packets
	FwdIATMean  float64 `json:"fwd_iat_mean"`  // Mean Inter-Arrival Time of forward packets
	FwdIATStd   float64 `json:"fwd_iat_std"`   // Standard deviation of forward packet Inter-Arrival Time
	FwdIATMax   float64 `json:"fwd_iat_max"`   // Maximum Inter-Arrival Time of forward packets
	FwdIATMin   float64 `json:"fwd_iat_min"`   // Minimum Inter-Arrival Time of forward packets
}

type BackwardIATFeatures struct {
	// Backward Inter-Arrival Time Features
	BwdIATTotal float64 `json:"bwd_iat_total"` // Total Inter-Arrival Time for backward packets
	BwdIATMean  float64 `json:"bwd_iat_mean"`  // Mean Inter-Arrival Time of backward packets
	BwdIATStd   float64 `json:"bwd_iat_std"`   // Standard deviation of backward packet Inter-Arrival Time
	BwdIATMax   float64 `json:"bwd_iat_max"`   // Maximum Inter-Arrival Time of backward packets
	BwdIATMin   float64 `json:"bwd_iat_min"`   // Minimum Inter-Arrival Time of backward packets
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
