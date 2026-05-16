package model

import "time"

type IPStats struct {
	IP             string
	Requests       int
	RequestsPerSec int
	FailedAtt      int

	Ports map[int]bool

	LastSeen  time.Time
	FirstSeen time.Time
	LastReset time.Time
}
type ALERT_TYPE int

const (
	PORT_SCAN ALERT_TYPE = iota
	FLOOD
	BRUTE_FORCE
	SUSPICIOUS
	ANOMALY_DETECTED
)

var AlertTypeName = map[ALERT_TYPE]string{
	PORT_SCAN:        "PORT_SCAN",
	FLOOD:            "FLOOD",
	BRUTE_FORCE:      "BRUTE_FORCE",
	SUSPICIOUS:       "SUSPICIOUS",
	ANOMALY_DETECTED: "ANOMALY_DETECTED",
}

type STATUS int

const (
	FAIL STATUS = iota
	SUCCESS
)

var StatusTypeName = map[STATUS]string{
	FAIL:    "FAIL",
	SUCCESS: "SUCCESS",
}

type Alert struct {
	ID        string
	IP        string
	Type      ALERT_TYPE
	Risk      float64
	Timestamp int64
	Message   string
}

type Event struct {
	SrcIP     string
	DstIP     string
	DstPort   int
	Syn       bool
	Size      int
	Timestamp int64
}

type SysSnapshot struct {
	TotalReq   int
	ActiveIPs  int
	AlertCount int
}

type Severity int

const (
	Low Severity = iota
	Medium
	High
	Critical
)

var severityName = map[Severity]string{
	Low:      "LOW",
	Medium:   "MEDIUM",
	High:     "HIGH",
	Critical: "CRITICAL",
}

type MLEvent struct {
	SrcIP string

	PacketRate     int
	Requests       int
	RequestsPerSec int

	UniquePorts int
	FailedAtt   int

	ByteCount int
	Timestamp int64
}
type LlmExplanation struct {
	AlertId  string
	Text     string
	Severity Severity
}
