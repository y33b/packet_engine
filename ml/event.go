package ml

import (
	"nexus/model"
	"time"
)

type MLEvent struct {
	SrcIP string

	PacketRate  float64
	UniquePorts float64
	FailedAtt   float64

	Timestamp int64
}

func BuildMLEvent(s *model.IPStats) MLEvent {
	return MLEvent{
		SrcIP: s.IP,

		PacketRate:  float64(s.RequestsPerSec) * 10.0,
		UniquePorts: float64(len(s.Ports)) * 5.0,
		FailedAtt:   float64(s.Requests) * 0.2,

		Timestamp: time.Now().Unix(),
	}
}
