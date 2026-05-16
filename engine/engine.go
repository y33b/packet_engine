package engine

import (
	"nexus/detector"
	"nexus/ml"
	"nexus/model"
	"time"
)

type Engine struct {
	Store     map[string]*model.IPStats
	Detector  *detector.Detector
	Alerts    chan model.Alert
	ML        chan ml.MLEvent
	LastAlert map[string]time.Time
}

func NewEngine() *Engine {
	return &Engine{
		Store:     make(map[string]*model.IPStats),
		Detector:  &detector.Detector{},
		Alerts:    make(chan model.Alert, 100),
		ML:        make(chan ml.MLEvent, 100),
		LastAlert: make(map[string]time.Time),
	}
}

func (e *Engine) Process(event model.Event) {

	now := time.Now()

	stats := e.Store[event.SrcIP]

	if stats == nil {
		stats = &model.IPStats{
			IP:        event.SrcIP,
			Ports:     make(map[int]bool),
			FirstSeen: now,
			LastReset: now,
		}
		e.Store[event.SrcIP] = stats
	}

	if now.Sub(stats.LastReset) >= time.Second {
		stats.RequestsPerSec = stats.Requests
		stats.Requests = 0
		stats.Ports = make(map[int]bool)
		stats.LastReset = now
	}

	stats.Requests++
	stats.Ports[event.DstPort] = true
	stats.LastSeen = now

	packetRate := float64(stats.RequestsPerSec) * 10.0
	uniquePorts := float64(len(stats.Ports)) * 5.0
	failedAtt := float64(stats.RequestsPerSec) * 0.2

	mlEvent := ml.MLEvent{
		SrcIP:       event.SrcIP,
		PacketRate:  packetRate,
		UniquePorts: uniquePorts,
		FailedAtt:   failedAtt,
		Timestamp:   now.Unix(),
	}

	select {
	case e.ML <- mlEvent:
	default:
	}

	alert := e.Detector.Analyze(stats)

	if alert.Risk > 0.5 {

		last, ok := e.LastAlert[event.SrcIP]

		if ok && now.Sub(last) < 10*time.Second {
			return
		}

		e.LastAlert[event.SrcIP] = now

		e.Alerts <- alert
	}
}
