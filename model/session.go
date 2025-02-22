package model

type Session struct {
	ID        SessionID
	FlowStats *FlowStats
}

type SessionID struct {
	SourceIP      string
	DestinationIP string
}
