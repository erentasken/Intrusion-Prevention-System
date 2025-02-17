package model

// Define a struct to represent IPv4 information
type IPv4Info struct {
	Version             uint8
	IHL                 uint8  // Internet Header Length in bytes
	TotalLength         uint16 // Total Length of the packet
	Identification      uint16 // Identification field
	FlagsFragmentOffset uint16
	TTL                 uint8 // Time to Live
	Protocol            uint8 // Protocol (e.g., 6 for TCP)
	SourceIP            string
	DestinationIP       string
}

// Define a struct to represent IPv6 information
type IPv6Info struct {
	Version       uint8
	PayloadLength uint16 // Payload length (not including IPv6 header)
	NextHeader    uint8  // Next header (e.g., 6 for TCP)
	HopLimit      uint8  // Hop Limit (equivalent to TTL in IPv4)
	SourceIP      string
	DestinationIP string
}

// Define a struct to represent TCP header information
type TCPInfo struct {
	SourcePort           uint16
	DestinationPort      uint16
	SequenceNumber       uint32
	AcknowledgmentNumber uint32
	SYN                  bool
	ACK                  bool
	FIN                  bool
	RST                  bool
}

// Define a struct to represent UDP header information
type UDPInfo struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
	Payload         []byte // Store UDP payload data
}

// Define a struct to represent the analysis of a TCP packet
type PacketAnalysisTCP struct {
	PacketID uint32
	IPv4     *IPv4Info
	IPv6     *IPv6Info
	TCP      *TCPInfo
}

// Define a struct to represent the analysis of a UDP packet
type PacketAnalysisUDP struct {
	PacketID uint32
	IPv4     *IPv4Info
	IPv6     *IPv6Info
	UDP      *UDPInfo
}
