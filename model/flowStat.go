package model

// FlowStats represents the network flow statistics in a nested form.
type FlowStats struct {
	// FlowDetails contains general flow statistics.
	FlowDetails struct {
		Duration     float64 // Duration of the flow
		TotalFwPk    int     // Total packets in the forward direction
		TotalBwPk    int     // Total packets in the backward direction
		TotalLFwPkt  int     // Total size of packets in the forward direction
		FlowByteRate float64 // Flow byte rate (packets per second)
		FlowPktRate  float64 // Flow packet rate (bytes per second)
		FlowIatAvg   float64 // Average inter-arrival time between flows
		FlowIatStd   float64 // Standard deviation of inter-arrival time between flows
		FlowIatMax   float64 // Maximum inter-arrival time between flows
		FlowIatMin   float64 // Minimum inter-arrival time between flows
	}

	// PacketDetails holds the statistics related to packet sizes and lengths.
	PacketDetails struct {
		FwPktLMax  int     // Maximum size of packets in the forward direction
		FwPktLMin  int     // Minimum size of packets in the forward direction
		FwPktLAvg  float64 // Average size of packets in the forward direction
		FwPktLStd  float64 // Standard deviation of packet size in the forward direction
		BwPktLMax  int     // Maximum size of packets in the backward direction
		BwPktLMin  int     // Minimum size of packets in the backward direction
		BwPktLAvg  float64 // Average size of packets in the backward direction
		BwPktLStd  float64 // Standard deviation of packet size in the backward direction
		PktLenMin  int     // Minimum length of a flow
		PktLenMax  int     // Maximum length of a flow
		PktLenAvg  float64 // Average length of a flow
		PktLenStd  float64 // Standard deviation of length in a flow
		PktLenVa   float64 // Minimum inter-arrival time of packets
		PktSizeAvg float64 // Average size of packets
	}

	// SegmentDetails contains statistics related to packet segments.
	SegmentDetails struct {
		FwSegAvg     float64 // Average segment size in the forward direction
		BwSegAvg     float64 // Average segment size in the backward direction
		FwSegMin     int     // Minimum segment size observed in the forward direction
		FwBlkRateAvg float64 // Average bulk rate in the forward direction
		BwBlkRateAvg float64 // Average bulk rate in the backward direction
	}

	// FlagCounts stores counts of various flags in the TCP packets.
	FlagCounts struct {
		FwPshFlag int // Number of PSH flags in forward direction
		BwPshFlag int // Number of PSH flags in backward direction
		FwUrgFlag int // Number of URG flags in forward direction
		BwUrgFlag int // Number of URG flags in backward direction
		FinCnt    int // Number of FIN flags
		SynCnt    int // Number of SYN flags
		RstCnt    int // Number of RST flags
		PstCnt    int // Number of PUSH flags
		AckCnt    int // Number of ACK flags
		UrgCnt    int // Number of URG flags
		CweCnt    int // Number of CWE flags
		EceCnt    int // Number of ECE flags
	}

	// SubFlowDetails provides statistics about the sub-flows in the forward and backward directions.
	SubFlowDetails struct {
		SubflFwPk  float64 // Average number of packets in a sub-flow in the forward direction
		SubflFwByt float64 // Average number of bytes in a sub-flow in the forward direction
		SubflBwPkt float64 // Average number of packets in a sub-flow in the backward direction
		SubflBwByt float64 // Average number of bytes in a sub-flow in the backward direction
	}

	// TimeDetails stores various time-related statistics such as inter-arrival time and activity time.
	TimeDetails struct {
		FwIatTot float64 // Total time between packets in the forward direction
		FwIatAvg float64 // Average time between packets in the forward direction
		FwIatStd float64 // Standard deviation of time between packets in the forward direction
		FwIatMax float64 // Maximum time between packets in the forward direction
		FwIatMin float64 // Minimum time between packets in the forward direction
		BwIatTot float64 // Total time between packets in the backward direction
		BwIatAvg float64 // Average time between packets in the backward direction
		BwIatStd float64 // Standard deviation of time between packets in the backward direction
		BwIatMax float64 // Maximum time between packets in the backward direction
		BwIatMin float64 // Minimum time between packets in the backward direction
		AtvAvg   float64 // Average time a flow was active before becoming idle
		AtvStd   float64 // Standard deviation of active time before becoming idle
		AtvMax   float64 // Maximum time a flow was active before becoming idle
		AtvMin   float64 // Minimum time a flow was active before becoming idle
		IdlAvg   float64 // Average idle time before a flow becomes active
		IdlStd   float64 // Standard deviation of idle time before becoming active
		IdlMax   float64 // Maximum idle time before becoming active
		IdlMin   float64 // Minimum idle time before becoming active
	}

	// WindowDetails contains the number of bytes sent in the initial window for forward and backward directions.
	WindowDetails struct {
		FwWinByt int // Number of bytes sent in initial window in the forward direction
		BwWinByt int // Number of bytes sent in initial window in the backward direction
	}

	// ActivityDetails stores the number of active packets in the forward direction.
	ActivityDetails struct {
		FwActPkt int // Number of active packets in the forward direction
	}

	// DownUpRatio stores the ratio of download to upload packets.
	DownUpRatio float64 // Download to upload ratio
}
